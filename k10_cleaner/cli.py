# k10-cleaner — CLI tool
# Copyright (c) 2026 Georgios Kapellakis
# Licensed under AGPL-3.0 — see LICENSE for details.
#
# Replaces k10-cancel-stuck-actions.sh. Provides check mode (policy dashboard),
# show-completed mode, and cancel mode (stuck action detection + cancellation).

from __future__ import annotations

import argparse
import hmac as _hmac
import re
import sys
import time

from . import VERSION
from .compliance import ComplianceEngine
from .db import K10Database
from .kubectl import Kubectl

# ======================================================================
# Constants — identical to bash
# ======================================================================

ACTION_TYPES = [
    "backupactions",
    "exportactions",
    "restoreactions",
    "runactions",
    "retireactions",
    "stageactions",
    "importactions",
    "reportactions",
    "upgradeactions",
    "validateactions",
    "batchrestoreactions",
    "migratefcdactions",
]

KIND_MAP = {
    "backupactions": "BackupAction",
    "exportactions": "ExportAction",
    "restoreactions": "RestoreAction",
    "runactions": "RunAction",
    "retireactions": "RetireAction",
    "stageactions": "StageAction",
    "importactions": "ImportAction",
    "reportactions": "ReportAction",
    "upgradeactions": "UpgradeAction",
    "validateactions": "ValidateAction",
    "batchrestoreactions": "BatchRestoreAction",
    "migratefcdactions": "MigrateFCDAction",
}

ACTION_VERB_MAP = {
    "backup": "backupactions",
    "export": "exportactions",
    "restore": "restoreactions",
    "run": "runactions",
    "retire": "retireactions",
    "stage": "stageactions",
    "import": "importactions",
    "report": "reportactions",
    "upgrade": "upgradeactions",
    "validate": "validateactions",
    "batchrestore": "batchrestoreactions",
    "migratefcd": "migratefcdactions",
}

VERB_DISPLAY = {
    "backup": "Snapshot",
    "export": "Export",
    "restore": "Restore",
    "retire": "Retire",
    "report": "Report",
}

NAMESPACE = "kasten-io"

_TARGET_STATES = {"Pending", "Running", "AttemptFailed"}


def _safe_error_message(status: dict) -> str:
    """Safely extract error message from status dict. Handles string, null, or dict."""
    err = status.get("error")
    if err is None:
        return ""
    if isinstance(err, dict):
        return err.get("message", "")
    return str(err)


# ======================================================================
# Utility functions
# ======================================================================

def parse_duration(dur: str) -> int:
    """Parse duration string (e.g. 24h, 2d) into seconds. Minimum 1h."""
    m = re.match(r"^(\d+)([hdHD])$", dur)
    if not m:
        print(f"Error: invalid duration '{dur}'", file=sys.stderr)
        sys.exit(1)
    num = int(m.group(1))
    unit = m.group(2).lower()
    if unit == "h":
        seconds = num * 3600
    elif unit == "d":
        seconds = num * 86400
    else:
        print(f"Error: unsupported duration unit '{unit}' (use h or d)", file=sys.stderr)
        sys.exit(1)
    if seconds < 3600:
        print(f"Error: minimum --max-age is 1h (got '{dur}')", file=sys.stderr)
        sys.exit(1)
    return seconds


def is_valid_k8s_name(name: str) -> bool:
    """Validate K8s resource name (RFC 1123 DNS label, max 253 chars)."""
    return bool(name) and len(name) <= 253 and bool(re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", name))


def compute_age(timestamp: str, now_epoch: float) -> int | None:
    """Compute age in seconds, clamping to 0 on clock skew. Returns None on parse failure."""
    import email.utils
    from datetime import datetime, timezone

    # Try ISO 8601 format first (K8s timestamps)
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            dt = datetime.strptime(timestamp, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            epoch = dt.timestamp()
            age = int(now_epoch - epoch)
            return max(age, 0)
        except ValueError:
            continue
    return None


def format_age_hours(age_secs: int | None) -> str:
    if age_secs is None:
        return "?"
    return f"{age_secs // 3600}"


def build_namespace_list(pol_ns: str, default_ns: str = NAMESPACE) -> list[str]:
    """Parse potentially comma-separated namespace list."""
    namespaces = [default_ns]
    if pol_ns == "(all)":
        return namespaces
    for ns in pol_ns.split(","):
        ns = ns.strip()
        if ns and ns != default_ns:
            namespaces.append(ns)
    return namespaces


def format_max_age_display(seconds: int) -> str:
    hours = seconds // 3600
    return f"{hours}h"


def _format_display_time(timestamp: str) -> str:
    """Format K8s timestamp for display."""
    from datetime import datetime, timezone
    try:
        dt = datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
        dt = dt.replace(tzinfo=timezone.utc)
        local_dt = dt.astimezone()
        return local_dt.strftime("%a %b %d %Y %I:%M %p")
    except ValueError:
        return timestamp


def _get_policy_namespaces(policy: dict) -> str:
    """Extract target namespace(s) from a K10 policy."""
    # Try matchExpressions first
    try:
        expressions = policy.get("spec", {}).get("selector", {}).get("matchExpressions", [])
        for expr in expressions:
            if expr.get("key") == "k10.kasten.io/appNamespace":
                values = expr.get("values", [])
                if values:
                    return ", ".join(values)
    except (TypeError, KeyError):
        pass

    # Try matchLabels
    try:
        ml = policy.get("spec", {}).get("selector", {}).get("matchLabels", {})
        ns = ml.get("k10.kasten.io/appNamespace", "")
        if ns:
            return ns
    except (TypeError, KeyError):
        pass

    return "(all)"


def _get_policy_actions_display(policy: dict) -> str:
    """Extract action types from policy spec for display."""
    try:
        actions = policy.get("spec", {}).get("actions", [])
        display = []
        for a in actions:
            verb = a.get("action", "")
            if verb == "backup":
                display.append("Snapshot")
            elif verb == "export":
                display.append("Export")
            elif verb == "restore":
                display.append("Restore")
            elif verb == "retire":
                display.append("Retire")
            elif verb == "report":
                display.append("Report")
            elif verb:
                display.append(verb[0].upper() + verb[1:])
        return " + ".join(display) if display else "\u2014"
    except (TypeError, KeyError):
        return "\u2014"


def _get_policy_action_verbs(policy: dict) -> list[str]:
    """Extract action verbs from policy spec."""
    try:
        return [a.get("action", "") for a in policy.get("spec", {}).get("actions", []) if a.get("action")]
    except (TypeError, KeyError):
        return []


# ======================================================================
# K10Cleaner
# ======================================================================

class K10Cleaner:
    def __init__(self, kubectl: Kubectl, db: K10Database, compliance: ComplianceEngine):
        self._kc = kubectl
        self._db = db
        self._compliance = compliance
        self._now_epoch = time.time()

    # ------------------------------------------------------------------
    # Check mode — policy status dashboard
    # ------------------------------------------------------------------
    def run_check_mode(self, max_age_seconds: int):
        print("=== K10 Policy Status Dashboard ===")
        print()

        policies_data = self._kc.get_json(
            ["get", "policies.config.kio.kasten.io", "-n", NAMESPACE]
        )
        if policies_data is None:
            print("Error: failed to list K10 policies", file=sys.stderr)
            sys.exit(1)

        items = policies_data.get("items", [])
        if not items:
            print(f"No K10 policies found in namespace {NAMESPACE}.")
            sys.exit(0)

        items.sort(key=lambda p: p.get("metadata", {}).get("name", ""))
        policy_count = len(items)
        count_complete = 0
        count_failed = 0
        count_running = 0
        count_stuck = 0
        count_skipped = 0
        count_norun = 0
        shown = 0

        for policy in items:
            pol_name = policy.get("metadata", {}).get("name", "")
            pol_ns = _get_policy_namespaces(policy)
            pol_actions = _get_policy_actions_display(policy)
            target_namespaces = build_namespace_list(pol_ns)

            # Check for active actions
            has_active = False
            for action_type in ACTION_TYPES:
                for check_ns in target_namespaces:
                    lines = self._kc.get_lines([
                        "get", action_type, "-n", check_ns,
                        "-l", f"k10.kasten.io/policyName={pol_name}",
                        "--no-headers",
                    ])
                    for line in lines:
                        parts = line.split()
                        if parts and parts[-1] in _TARGET_STATES:
                            has_active = True
                            break
                    if has_active:
                        break
                if has_active:
                    break

            # Find most recent action
            latest_time = ""
            latest_status = ""
            latest_error = ""

            for verb in _get_policy_action_verbs(policy):
                resource = ACTION_VERB_MAP.get(verb, "")
                if not resource:
                    continue
                for search_ns in target_namespaces:
                    data = self._kc.get_json([
                        "get", resource, "-n", search_ns,
                        "-l", f"k10.kasten.io/policyName={pol_name}",
                        "--sort-by=.metadata.creationTimestamp",
                    ])
                    if not data:
                        continue
                    action_items = data.get("items", [])
                    if not action_items:
                        continue
                    last = action_items[-1]
                    act_time = last.get("metadata", {}).get("creationTimestamp", "")
                    if not act_time:
                        continue
                    if not latest_time or act_time > latest_time:
                        latest_time = act_time
                        latest_status = last.get("status", {}).get("state", "Unknown")
                        latest_error = _safe_error_message(last.get("status", {}))

            if not latest_status:
                latest_status = "\u2014"

            if has_active:
                latest_status = "Running"
                latest_error = ""

            # Count by status
            if latest_status == "Complete":
                count_complete += 1
                continue
            elif latest_status == "Failed":
                count_failed += 1
            elif latest_status == "Skipped":
                count_skipped += 1
            elif latest_status == "Running":
                count_running += 1
            elif latest_status == "\u2014":
                count_norun += 1
                continue

            # Check if stuck
            is_stuck = False
            if latest_time and latest_status in ("Running", "Pending", "AttemptFailed"):
                age_secs = compute_age(latest_time, self._now_epoch)
                if age_secs is not None and age_secs >= max_age_seconds:
                    is_stuck = True
                    count_stuck += 1

            display_time = _format_display_time(latest_time) if latest_time else "\u2014"
            status_display = f"STUCK ({latest_status})" if is_stuck else latest_status

            # Print header on first result
            if shown == 0:
                print(
                    f"{'NAME':<28s} {'NAMESPACE':<20s} {'ACTION':<22s} {'LAST RUN':<28s} STATUS"
                )
                print("-" * 108)
            shown += 1

            print(
                f"{pol_name:<28s} {pol_ns:<20s} {pol_actions:<22s} {display_time:<28s} {status_display}"
            )
            if latest_error:
                print(f"  error: {latest_error}")

            # Show active actions for this policy
            for action_type in ACTION_TYPES:
                kind = KIND_MAP[action_type]
                for search_ns in target_namespaces:
                    lines = self._kc.get_lines([
                        "get", action_type, "-n", search_ns,
                        "-l", f"k10.kasten.io/policyName={pol_name}",
                        "--no-headers",
                        "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.state,NS:.metadata.namespace",
                    ])
                    for line in lines:
                        parts = line.split()
                        if len(parts) < 3:
                            continue
                        act_name, act_status_raw, act_ns = parts[0], parts[1], parts[2]
                        if act_status_raw not in _TARGET_STATES:
                            continue

                        # Get full action JSON
                        act_data = self._kc.get_json([
                            "get", action_type, act_name, "-n", act_ns,
                        ])
                        if not act_data:
                            continue

                        act_state = act_data.get("status", {}).get("state", "")
                        act_creation = act_data.get("metadata", {}).get("creationTimestamp", "")
                        act_start = act_data.get("status", {}).get("startTime", "")
                        act_progress = act_data.get("status", {}).get("progress", "")
                        act_err = _safe_error_message(act_data.get("status", {}))

                        # Compute age
                        if act_start and act_state == "Running":
                            age_ref = act_start
                        else:
                            age_ref = act_creation

                        act_age_hours = "?"
                        act_is_old = False
                        if age_ref:
                            act_age_secs = compute_age(age_ref, self._now_epoch)
                            if act_age_secs is not None:
                                act_age_hours = str(act_age_secs // 3600)
                                act_is_old = act_age_secs >= max_age_seconds

                        # Health label
                        signals = []
                        if act_state == "Pending" and act_is_old:
                            signals.append("old")
                        elif act_state == "AttemptFailed":
                            signals.append("retry-loop")
                        elif act_state == "Running":
                            if act_progress is not None and str(act_progress) == "0" and act_is_old:
                                signals.append("no-progress")
                            if act_err:
                                signals.append("has-error")

                        if act_is_old and signals:
                            health = "STUCK"
                        elif act_is_old:
                            health = "OLD"
                        else:
                            health = "OK"

                        progress_str = f" progress={act_progress}%" if act_progress not in (None, "") else " progress=\u2014"
                        signal_str = f" ({', '.join(signals)})" if signals else ""

                        print(
                            f"  [{health:<5s}] {kind:<20s} {act_name:<40s} age={act_age_hours + 'h':<5s} "
                            f"{act_state}{progress_str} policy={pol_name}{signal_str}"
                        )
                        if act_err:
                            print(f"          error: {act_err}")

        if shown == 0:
            print("All policies healthy \u2014 nothing to report.")

        print()
        print("=== Summary ===")
        print(f"Policies: {policy_count} ({count_complete} complete, not shown)")
        print(f"  Failed:    {count_failed}")
        print(f"  Skipped:   {count_skipped}")
        print(f"  Running:   {count_running}")
        print(f"  Stuck:     {count_stuck}")
        print(f"  Never run: {count_norun}")

        if count_stuck > 0:
            print()
            print("Tip: run with --dry-run to see what would be cancelled, or without flags to cancel stuck actions.")

    # ------------------------------------------------------------------
    # Show completed policies
    # ------------------------------------------------------------------
    def run_show_completed(self):
        print("=== Recently Completed K10 Policies ===")
        print()

        policies_data = self._kc.get_json(
            ["get", "policies.config.kio.kasten.io", "-n", NAMESPACE]
        )
        if policies_data is None:
            print("Error: failed to list K10 policies", file=sys.stderr)
            sys.exit(1)

        items = policies_data.get("items", [])
        if not items:
            print(f"No K10 policies found in namespace {NAMESPACE}.")
            sys.exit(0)

        items.sort(key=lambda p: p.get("metadata", {}).get("name", ""))
        count_completed = 0
        shown = 0

        for policy in items:
            pol_name = policy.get("metadata", {}).get("name", "")
            pol_ns = _get_policy_namespaces(policy)
            target_namespaces = build_namespace_list(pol_ns)

            latest_time = ""
            latest_status = ""
            latest_verb = ""

            for verb in _get_policy_action_verbs(policy):
                resource = ACTION_VERB_MAP.get(verb, "")
                if not resource:
                    continue
                for search_ns in target_namespaces:
                    data = self._kc.get_json([
                        "get", resource, "-n", search_ns,
                        "-l", f"k10.kasten.io/policyName={pol_name}",
                        "--sort-by=.metadata.creationTimestamp",
                    ])
                    if not data:
                        continue
                    action_items = data.get("items", [])
                    if not action_items:
                        continue
                    last = action_items[-1]
                    act_time = last.get("metadata", {}).get("creationTimestamp", "")
                    if not act_time:
                        continue
                    if not latest_time or act_time > latest_time:
                        latest_time = act_time
                        latest_status = last.get("status", {}).get("state", "Unknown")
                        latest_verb = verb

            if latest_status != "Complete":
                continue

            count_completed += 1
            display_time = _format_display_time(latest_time) if latest_time else "\u2014"
            action_display = VERB_DISPLAY.get(latest_verb, latest_verb[0].upper() + latest_verb[1:] if latest_verb else "\u2014")

            if shown == 0:
                print(f"{'NAME':<28s} {'NAMESPACE':<20s} {'ACTION':<22s} COMPLETED AT")
                print("-" * 92)
            shown += 1

            print(f"{pol_name:<28s} {pol_ns:<20s} {action_display:<22s} {display_time}")

        print()
        if count_completed == 0:
            print("No recently completed policies found.")
        else:
            word = "policy" if count_completed == 1 else "policies"
            print(f"{count_completed} completed {word}.")

    # ------------------------------------------------------------------
    # Cancel mode — stuck action detection + cancellation
    # ------------------------------------------------------------------
    def run_cancel_mode(self, max_age_seconds: int, dry_run: bool) -> int:
        if dry_run:
            print("[DRY RUN] No changes will be made.")
        print(f"Stuck detection: actions older than {format_max_age_display(max_age_seconds)}")
        print()

        total_found = 0
        total_stuck = 0
        total_cancelled = 0
        total_deleted = 0
        total_failed = 0
        total_skipped = 0
        count_pending = 0
        count_attempt_failed = 0
        count_no_progress = 0
        count_error_signal = 0

        for action_type in ACTION_TYPES:
            kind = KIND_MAP[action_type]

            lines = self._kc.get_lines([
                "get", action_type, "-n", NAMESPACE, "--no-headers",
                "-o", "custom-columns=NAME:.metadata.name,STATUS:.status.state",
            ])

            for line in lines:
                parts = line.split()
                if len(parts) < 2:
                    continue
                action_name, status = parts[0], parts[-1]
                if status not in _TARGET_STATES:
                    continue

                total_found += 1

                # Validate resource name
                if not is_valid_k8s_name(action_name):
                    print(f"Warning: invalid resource name '{action_name}', skipping")
                    continue

                # TOCTOU re-fetch
                action_data = self._kc.get_json([
                    "get", action_type, action_name, "-n", NAMESPACE,
                ])
                if not action_data:
                    print(f"Warning: could not fetch {kind} {action_name} (may have completed), skipping")
                    continue

                creation_ts = action_data.get("metadata", {}).get("creationTimestamp", "")
                start_time = action_data.get("status", {}).get("startTime", "")
                state = action_data.get("status", {}).get("state", "")
                progress = action_data.get("status", {}).get("progress", "")
                error_msg = _safe_error_message(action_data.get("status", {}))
                policy_name = action_data.get("metadata", {}).get("labels", {}).get("k10.kasten.io/policyName", "")

                # Skip if state changed
                if state not in _TARGET_STATES:
                    print(f"Skipping {kind} {action_name} \u2014 state changed to {state}")
                    total_skipped += 1
                    continue

                # Compute age
                if start_time and state == "Running":
                    age_ref = start_time
                else:
                    age_ref = creation_ts

                if not age_ref:
                    print(f"Warning: no timestamp for {kind} {action_name}, skipping")
                    continue

                age_seconds = compute_age(age_ref, self._now_epoch)
                if age_seconds is None:
                    print(f"Warning: could not parse timestamp '{age_ref}' for {kind} {action_name}, skipping")
                    continue

                age_hours = age_seconds // 3600

                # Skip young actions
                if age_seconds < max_age_seconds:
                    total_skipped += 1
                    continue

                # Determine stuck reasons
                reasons = []

                if state == "Pending":
                    reasons.append(f"Pending for {age_hours}h (never started)")
                    count_pending += 1
                elif state == "AttemptFailed":
                    reasons.append(f"AttemptFailed for {age_hours}h (stuck in retry loop)")
                    count_attempt_failed += 1
                elif state == "Running":
                    has_signal = False
                    if progress is not None and str(progress) == "0":
                        reasons.append(f"no progress (progress=0 after {age_hours}h)")
                        count_no_progress += 1
                        has_signal = True
                    if error_msg:
                        reasons.append("error present")
                        count_error_signal += 1
                        has_signal = True
                    if not has_signal:
                        total_skipped += 1
                        continue

                total_stuck += 1
                reason_str = ", ".join(reasons)
                policy_label = f" policy={policy_name}" if policy_name else ""
                print(f"STUCK: {kind} {action_name} [{state}]{policy_label} \u2014 age {age_hours}h \u2014 {reason_str}")
                if error_msg:
                    print(f"  error: {error_msg}")

                if dry_run:
                    print("  -> Would attempt cancel, then delete if cancel fails")
                    continue

                # Try CancelAction first
                cancel_yaml = self._build_cancel_yaml(action_name, NAMESPACE, kind)
                ok, output = self._kc.create_from_yaml(cancel_yaml, NAMESPACE)
                if ok:
                    print(f"  -> Cancelled via CancelAction")
                    total_cancelled += 1
                else:
                    print(f"  -> CancelAction failed, deleting directly...")
                    ok, output = self._kc.delete_resource(action_type, action_name, NAMESPACE)
                    if ok:
                        print(f"  -> Deleted")
                        total_deleted += 1
                    else:
                        print(f"  -> FAILED to delete")
                        total_failed += 1

        print()
        print("=== Summary ===")
        print(f"Found:     {total_found} actions in target states (Pending/Running/AttemptFailed)")
        print(f"Skipped:   {total_skipped} (too young or Running without stuck signals)")
        print(f"Stuck:     {total_stuck} actions identified as stuck")
        print(f"Cancelled: {total_cancelled}")
        print(f"Deleted:   {total_deleted}")
        print(f"Failed:    {total_failed}")
        print()
        print("--- Detection breakdown ---")
        print(f"Pending (never started): {count_pending}")
        print(f"AttemptFailed (retry):   {count_attempt_failed}")
        print(f"No progress (stalled):   {count_no_progress}")
        print(f"Error signal:            {count_error_signal}")

        return total_failed

    @staticmethod
    def _build_cancel_yaml(name: str, namespace: str, kind: str) -> str:
        return (
            f"apiVersion: actions.kio.kasten.io/v1alpha1\n"
            f"kind: CancelAction\n"
            f"metadata:\n"
            f"  generateName: cancel-{name}-\n"
            f"  namespace: {namespace}\n"
            f"spec:\n"
            f"  subject:\n"
            f"    apiVersion: actions.kio.kasten.io/v1alpha1\n"
            f"    kind: {kind}\n"
            f"    name: {name}\n"
            f"    namespace: {namespace}\n"
        )


# ======================================================================
# main()
# ======================================================================

def main():
    parser = argparse.ArgumentParser(
        prog="k10-cleaner",
        description="Cancel or delete stuck K10 actions across all namespaces.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  k10-cleaner --check                  Status dashboard\n"
            "  k10-cleaner --dry-run                 Show what would be done\n"
            "  k10-cleaner --max-age 2d              Cancel actions older than 2 days\n"
            "  k10-cleaner --show-recent-completed   Show completed policies\n"
            "  k10-cleaner --show-fingerprint        Get cluster ID for license request\n"
            "  k10-cleaner --license-key <key>       Save license key for this cluster\n"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be done without making changes",
    )
    parser.add_argument(
        "--max-age",
        type=str,
        default="24h",
        metavar="<duration>",
        help="Only target actions older than this (default: 24h). Supports: 1h, 24h, 2d, 72h, etc. (minimum: 1h)",
    )
    parser.add_argument(
        "--check", "--monitor",
        action="store_true",
        dest="check",
        help="Status dashboard \u2014 show all active actions and exit",
    )
    parser.add_argument(
        "--show-recent-completed",
        action="store_true",
        help="Show recently completed policies and exit",
    )
    parser.add_argument(
        "--license-key",
        type=str,
        metavar="<key>",
        help="Save a license key for this cluster (persisted in DB)",
    )
    parser.add_argument(
        "--show-fingerprint",
        action="store_true",
        help="Print the cluster fingerprint and exit (use this to request a license)",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"k10-cleaner {VERSION}",
    )

    args = parser.parse_args()

    # Init components
    kc = Kubectl()
    db = K10Database()
    compliance = ComplianceEngine(kc, db)

    # --show-fingerprint: detect fingerprint, print, exit
    if args.show_fingerprint:
        compliance.cluster_fingerprint()
        fp = compliance.info.fingerprint
        if fp == "unknown":
            print("Error: could not determine cluster fingerprint (is kubectl configured?)", file=sys.stderr)
            sys.exit(1)
        print(f"Cluster fingerprint: {fp}")
        print()
        print("To request a license key, send this fingerprint to:")
        print("  georgios.kapellakis@yandex.com")
        sys.exit(0)

    # --license-key: save to DB, validate against current cluster, exit
    if args.license_key is not None:
        compliance.cluster_fingerprint()
        fp = compliance.info.fingerprint
        if fp == "unknown":
            print("Error: could not determine cluster fingerprint (is kubectl configured?)", file=sys.stderr)
            sys.exit(1)
        db.set_config("license_key", args.license_key)
        expected = compliance.generate_key(fp)
        if _hmac.compare_digest(args.license_key, expected):
            print(f"License key saved and validated for cluster {fp}")
            print("The banner and delay will no longer appear on this cluster.")
        else:
            print(f"License key saved for cluster {fp}, but it is NOT valid.", file=sys.stderr)
            print("The key does not match this cluster's fingerprint.", file=sys.stderr)
            print(f"Cluster fingerprint: {fp}", file=sys.stderr)
            sys.exit(1)
        sys.exit(0)

    max_age_seconds = parse_duration(args.max_age)

    # License check
    compliance.license_check()

    # Preflight: namespace check
    if not kc.namespace_exists(NAMESPACE):
        print(f"Error: cannot reach cluster or namespace '{NAMESPACE}' not found.", file=sys.stderr)
        print("Check that kubectl is configured and you have access to the K10 namespace.", file=sys.stderr)
        sys.exit(1)

    cleaner = K10Cleaner(kc, db, compliance)

    if args.check:
        cleaner.run_check_mode(max_age_seconds)
        sys.exit(0)

    if args.show_recent_completed:
        cleaner.run_show_completed()
        sys.exit(0)

    # Cancel mode (default)
    failed = cleaner.run_cancel_mode(max_age_seconds, args.dry_run)
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
