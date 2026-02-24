#!/bin/bash
#
# k10-cancel-stuck-actions.sh
# Copyright (c) 2026 Georgios Kapellakis
# Licensed under AGPL-3.0 — see LICENSE for details.
#
# Cancels or deletes stuck K10 actions across all namespaces using smart
# stuck detection: age threshold + progress stall + error signal detection.
#
# K10's CancelAction only works on Running actions — Pending actions that never
# started are deleted directly as a fallback.
#
# Usage: ./k10-cancel-stuck-actions.sh [--dry-run] [--max-age <duration>] [--check] [--show-recent-completed]
#   --dry-run          Show what would be done without making changes
#   --max-age <dur>    Only target actions older than this (default: 24h)
#                      Supports: 1h, 24h, 2d, 72h, etc. (minimum: 1h)
#   --check            Status dashboard — show all active actions and exit

set -euo pipefail

DRY_RUN=false
CHECK_MODE=false
SHOW_COMPLETED=false
MAX_AGE_SECONDS=$((24 * 3600))  # default: 24h

usage() {
    echo "Usage: $0 [--dry-run] [--max-age <duration>] [--check] [--show-recent-completed]"
    echo "  --dry-run          Show what would be done without making changes"
    echo "  --max-age <dur>    Only target actions older than this (default: 24h)"
    echo "                     Supports: 1h, 24h, 2d, 72h, etc. (minimum: 1h)"
    echo "  --check            Status dashboard — show all active actions and exit"
    echo "  --show-recent-completed  Show recently completed policies and exit"
    exit 1
}

# Parse duration string (e.g. 24h, 2d) into seconds
parse_duration() {
    local dur="$1"
    local num unit
    num="${dur%[hdHD]}"
    unit="${dur##*[0-9]}"
    unit="${unit,,}"  # lowercase

    if ! [[ "$num" =~ ^[0-9]+$ ]]; then
        echo "Error: invalid duration '${dur}' (expected format: <number><h|d>, e.g. 24h, 2d)" >&2
        return 1
    fi

    local seconds
    case "$unit" in
        h) seconds=$((num * 3600)) ;;
        d) seconds=$((num * 86400)) ;;
        *)
            echo "Error: unsupported duration unit '${unit}' (use h or d)" >&2
            return 1
            ;;
    esac

    # Bug #4: enforce minimum of 1 hour to prevent accidental mass cancellation
    if [[ $seconds -lt 3600 ]]; then
        echo "Error: minimum --max-age is 1h (got '${dur}')" >&2
        return 1
    fi

    echo "$seconds"
}

# Validate K8s resource name (RFC 1123 DNS subdomain)
# Bug #8: sanitize before interpolating into YAML
is_valid_k8s_name() {
    [[ "$1" =~ ^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$ ]]
}

# Filter lines where the LAST column matches target states
# Bug #6: anchor grep to status column instead of matching anywhere
filter_by_status() {
    awk '$NF ~ /^(Pending|Running|AttemptFailed)$/'
}

# Parse POL_NS (potentially comma-separated) into a proper namespace array
# Bug #3: handle multi-namespace policies
# Populates the global TARGET_NAMESPACES array
build_namespace_list() {
    local pol_ns="$1"
    TARGET_NAMESPACES=("$NAMESPACE")
    if [[ "$pol_ns" == "(all)" ]]; then
        return
    fi
    local ns
    while IFS= read -r ns; do
        ns="${ns## }"  # trim leading space
        ns="${ns%% }"  # trim trailing space
        if [[ -n "$ns" && "$ns" != "$NAMESPACE" ]]; then
            TARGET_NAMESPACES+=("$ns")
        fi
    done <<< "${pol_ns//,/$'\n'}"
}

# Parse CLI arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --max-age)
            [[ -z "${2:-}" ]] && { echo "Error: --max-age requires a value" >&2; usage; }
            MAX_AGE_SECONDS=$(parse_duration "$2") || exit 1
            shift 2
            ;;
        --check|--monitor)
            CHECK_MODE=true
            shift
            ;;
        --show-recent-completed)
            SHOW_COMPLETED=true
            shift
            ;;
        -h|--help)
            usage
            ;;
        *)
            echo "Error: unknown argument '$1'" >&2
            usage
            ;;
    esac
done

# Compute display string for max age (show fractional hours if needed)
if [[ $((MAX_AGE_SECONDS % 3600)) -eq 0 ]]; then
    MAX_AGE_DISPLAY="$(( MAX_AGE_SECONDS / 3600 ))h"
else
    MAX_AGE_DISPLAY="$(awk "BEGIN { printf \"%.1fh\", ${MAX_AGE_SECONDS}/3600 }")"
fi

NAMESPACE="kasten-io"

# Source shared compliance library — required for operation.
K10LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ ! -f "${K10LIB_DIR}/k10-cleaner-lib.sh" ]]; then
    echo "Error: k10-cleaner-lib.sh not found in ${K10LIB_DIR}." >&2
    echo "This file is required. Re-download the tool from the official repository." >&2
    echo "Repository: https://github.com/gekap/k10-cleaner" >&2
    exit 1
fi

source "${K10LIB_DIR}/k10-cleaner-lib.sh"

k10_license_check

# Bug #7: pre-flight connectivity check — fail fast instead of silently returning empty
if ! kubectl get namespace "$NAMESPACE" > /dev/null 2>&1; then
    echo "Error: cannot reach cluster or namespace '${NAMESPACE}' not found." >&2
    echo "Check that kubectl is configured and you have access to the K10 namespace." >&2
    exit 1
fi

ACTION_TYPES=(
    backupactions
    exportactions
    restoreactions
    runactions
    retireactions
    stageactions
    importactions
    reportactions
    upgradeactions
    validateactions
    batchrestoreactions
    migratefcdactions
)

# Map plural resource name to CRD Kind for CancelAction subject
declare -A KIND_MAP=(
    [backupactions]="BackupAction"
    [exportactions]="ExportAction"
    [restoreactions]="RestoreAction"
    [runactions]="RunAction"
    [retireactions]="RetireAction"
    [stageactions]="StageAction"
    [importactions]="ImportAction"
    [reportactions]="ReportAction"
    [upgradeactions]="UpgradeAction"
    [validateactions]="ValidateAction"
    [batchrestoreactions]="BatchRestoreAction"
    [migratefcdactions]="MigrateFCDAction"
)

# Map policy action verbs to K10 plural resource names
declare -A ACTION_VERB_MAP=(
    [backup]="backupactions"
    [export]="exportactions"
    [restore]="restoreactions"
    [run]="runactions"
    [retire]="retireactions"
    [stage]="stageactions"
    [import]="importactions"
    [report]="reportactions"
    [upgrade]="upgradeactions"
    [validate]="validateactions"
    [batchrestore]="batchrestoreactions"
    [migratefcd]="migratefcdactions"
)

# Compute age in seconds, clamping to 0 on clock skew
# Bug #11: handle future timestamps from clock skew
compute_age() {
    local timestamp="$1"
    local epoch now_epoch
    epoch=$(date -d "$timestamp" +%s 2>/dev/null) || return 1
    now_epoch=$(date +%s)
    local age=$((now_epoch - epoch))
    if [[ $age -lt 0 ]]; then
        echo "0"
    else
        echo "$age"
    fi
}

# --- Check mode: policy status dashboard ---
if [[ "$CHECK_MODE" == "true" ]]; then
    echo "=== K10 Policy Status Dashboard ==="
    echo ""

    POLICIES_JSON=$(kubectl get policies.config.kio.kasten.io -n "$NAMESPACE" -o json 2>/dev/null) || {
        echo "Error: failed to list K10 policies" >&2
        exit 1
    }
    if [[ "$(echo "$POLICIES_JSON" | jq '.items | length')" == "0" ]]; then
        echo "No K10 policies found in namespace ${NAMESPACE}."
        exit 0
    fi

    POLICY_COUNT=$(echo "$POLICIES_JSON" | jq '.items | length')
    COUNT_COMPLETE=0
    COUNT_FAILED=0
    COUNT_RUNNING=0
    COUNT_STUCK=0
    COUNT_SKIPPED=0
    COUNT_NORUN=0
    SHOWN=0

    while read -r POLICY; do
        POL_NAME=$(echo "$POLICY" | jq -r '.metadata.name')

        # Extract target namespace(s)
        POL_NS=$(echo "$POLICY" | jq -r '
            [
                (.spec.selector.matchExpressions // [] | map(select(.key == "k10.kasten.io/appNamespace")) | .[0].values // [])[]
            ] | join(", ")
        ')
        if [[ -z "$POL_NS" ]]; then
            POL_NS=$(echo "$POLICY" | jq -r '
                .spec.selector.matchLabels["k10.kasten.io/appNamespace"] // empty
            ')
        fi
        [[ -z "$POL_NS" ]] && POL_NS="(all)"

        # Extract action types from policy spec
        POL_ACTIONS=$(echo "$POLICY" | jq -r '
            [.spec.actions[].action // empty] | map(
                if . == "backup" then "Snapshot"
                elif . == "export" then "Export"
                elif . == "restore" then "Restore"
                elif . == "retire" then "Retire"
                elif . == "report" then "Report"
                else (.[0:1] | ascii_upcase) + .[1:]
                end
            ) | join(" + ")
        ')
        [[ -z "$POL_ACTIONS" ]] && POL_ACTIONS="—"

        # Bug #3: build proper namespace array from potentially multi-value POL_NS
        build_namespace_list "$POL_NS"

        # Check if this policy has ANY active (non-terminal) actions
        HAS_ACTIVE=false
        for ACTION_TYPE in "${ACTION_TYPES[@]}"; do
            for CHECK_NS in "${TARGET_NAMESPACES[@]}"; do
                if kubectl get "$ACTION_TYPE" -n "$CHECK_NS" \
                    -l "k10.kasten.io/policyName=${POL_NAME}" \
                    --no-headers 2>/dev/null \
                    | filter_by_status | grep -q .; then
                    HAS_ACTIVE=true
                    break 2
                fi
            done
        done

        # Find the most recent action for this policy across all action types
        # Search all target namespaces
        LATEST_TIME=""
        LATEST_STATUS=""
        LATEST_ERROR=""

        while IFS= read -r ACT_VERB; do
            [[ -z "$ACT_VERB" ]] && continue
            RESOURCE="${ACTION_VERB_MAP[$ACT_VERB]:-}"
            [[ -z "$RESOURCE" ]] && continue

            for SEARCH_NS in "${TARGET_NAMESPACES[@]}"; do
                LATEST_ACTION=$(kubectl get "$RESOURCE" -n "$SEARCH_NS" \
                    -l "k10.kasten.io/policyName=${POL_NAME}" \
                    --sort-by=.metadata.creationTimestamp \
                    -o json 2>/dev/null | jq '.items[-1] // empty') || true

                [[ -z "$LATEST_ACTION" || "$LATEST_ACTION" == "null" ]] && continue

                ACT_TIME=$(echo "$LATEST_ACTION" | jq -r '.metadata.creationTimestamp // empty')
                [[ -z "$ACT_TIME" ]] && continue

                act_epoch=""
                act_epoch=$(date -d "$ACT_TIME" +%s 2>/dev/null) || continue
                if [[ -z "$LATEST_TIME" ]] || [[ $act_epoch -gt $(date -d "$LATEST_TIME" +%s 2>/dev/null || echo 0) ]]; then
                    LATEST_TIME="$ACT_TIME"
                    LATEST_STATUS=$(echo "$LATEST_ACTION" | jq -r '.status.state // "Unknown"')
                    LATEST_ERROR=$(echo "$LATEST_ACTION" | jq -r '.status.error.message // empty')
                fi
            done
        done < <(echo "$POLICY" | jq -r '.spec.actions[].action // empty')

        [[ -z "$LATEST_STATUS" ]] && LATEST_STATUS="—"

        # Override status to Running if there are active actions
        if [[ "$HAS_ACTIVE" == "true" ]]; then
            LATEST_STATUS="Running"
            LATEST_ERROR=""
        fi

        # Count by status (always count, even if not displayed)
        case "$LATEST_STATUS" in
            Complete)   COUNT_COMPLETE=$((COUNT_COMPLETE + 1)); continue ;;
            Failed)     COUNT_FAILED=$((COUNT_FAILED + 1)) ;;
            Skipped)    COUNT_SKIPPED=$((COUNT_SKIPPED + 1)) ;;
            Running)    COUNT_RUNNING=$((COUNT_RUNNING + 1)) ;;
            Pending|AttemptFailed) ;;
            "—")        COUNT_NORUN=$((COUNT_NORUN + 1)); continue ;;
        esac

        # Check if stuck (for Running/Pending/AttemptFailed)
        IS_STUCK=false
        if [[ -n "$LATEST_TIME" && "$LATEST_STATUS" =~ ^(Running|Pending|AttemptFailed)$ ]]; then
            AGE_SECS=$(compute_age "$LATEST_TIME") || true
            if [[ -n "${AGE_SECS:-}" ]] && [[ $AGE_SECS -ge $MAX_AGE_SECONDS ]]; then
                IS_STUCK=true
                COUNT_STUCK=$((COUNT_STUCK + 1))
            fi
        fi

        # Format last run time
        DISPLAY_TIME=$(date -d "$LATEST_TIME" "+%a %b %d %Y %I:%M %p" 2>/dev/null || echo "$LATEST_TIME")

        # Status label
        STATUS_DISPLAY="$LATEST_STATUS"
        if [[ "$IS_STUCK" == "true" ]]; then
            STATUS_DISPLAY="STUCK (${LATEST_STATUS})"
        fi

        # Print policy header
        if [[ $SHOWN -eq 0 ]]; then
            printf "%-28s %-20s %-22s %-28s %s\n" \
                "NAME" "NAMESPACE" "ACTION" "LAST RUN" "STATUS"
            printf "%s\n" "--------------------------------------------------------------------------------------------------------------------"
        fi
        SHOWN=$((SHOWN + 1))

        printf "%-28s %-20s %-22s %-28s %s\n" \
            "$POL_NAME" "$POL_NS" "$POL_ACTIONS" "$DISPLAY_TIME" "$STATUS_DISPLAY"

        if [[ -n "$LATEST_ERROR" ]]; then
            echo "  error: ${LATEST_ERROR}"
        fi

        # Show active actions for this policy across all target namespaces
        for ACTION_TYPE in "${ACTION_TYPES[@]}"; do
            KIND="${KIND_MAP[$ACTION_TYPE]}"

            ACTIVE_ACTIONS=""
            for SEARCH_NS in "${TARGET_NAMESPACES[@]}"; do
                NS_ACTIONS=$(kubectl get "$ACTION_TYPE" -n "$SEARCH_NS" \
                    -l "k10.kasten.io/policyName=${POL_NAME}" \
                    --no-headers \
                    -o custom-columns=NAME:.metadata.name,STATUS:.status.state,NS:.metadata.namespace 2>/dev/null \
                    | filter_by_status || true)
                if [[ -n "$NS_ACTIONS" ]]; then
                    ACTIVE_ACTIONS+="${NS_ACTIONS}"$'\n'
                fi
            done
            ACTIVE_ACTIONS="${ACTIVE_ACTIONS%$'\n'}"  # trim trailing newline

            [[ -z "$ACTIVE_ACTIONS" ]] && continue

            while read -r ACT_NAME _ACT_STATUS ACT_NS; do
                [[ -z "$ACT_NAME" ]] && continue

                ACT_JSON=$(kubectl get "$ACTION_TYPE" "$ACT_NAME" -n "$ACT_NS" --request-timeout=30s -o json 2>/dev/null) || continue
                [[ -z "$ACT_JSON" ]] && continue

                ACT_STATE=$(echo "$ACT_JSON" | jq -r '.status.state // empty')
                ACT_CREATION=$(echo "$ACT_JSON" | jq -r '.metadata.creationTimestamp // empty')
                ACT_START=$(echo "$ACT_JSON" | jq -r '.status.startTime // empty')
                ACT_PROGRESS=$(echo "$ACT_JSON" | jq -r '.status.progress // empty')
                ACT_ERR=$(echo "$ACT_JSON" | jq -r '.status.error.message // empty')

                # Compute age
                if [[ -n "$ACT_START" && "$ACT_STATE" == "Running" ]]; then
                    ACT_AGE_REF="$ACT_START"
                else
                    ACT_AGE_REF="$ACT_CREATION"
                fi

                ACT_AGE_HOURS="?"
                ACT_IS_OLD=false
                if [[ -n "$ACT_AGE_REF" ]]; then
                    ACT_AGE_SECS=$(compute_age "$ACT_AGE_REF") || true
                    if [[ -n "${ACT_AGE_SECS:-}" ]]; then
                        if [[ $ACT_AGE_SECS -lt 3600 ]]; then
                            ACT_AGE_HOURS="$(awk "BEGIN { printf \"%.1f\", ${ACT_AGE_SECS}/3600 }")"
                        else
                            ACT_AGE_HOURS=$(( ACT_AGE_SECS / 3600 ))
                        fi
                        [[ $ACT_AGE_SECS -ge $MAX_AGE_SECONDS ]] && ACT_IS_OLD=true
                    fi
                fi

                # Health label
                ACT_SIGNALS=()
                case "$ACT_STATE" in
                    Pending)        [[ "$ACT_IS_OLD" == "true" ]] && ACT_SIGNALS+=("old") ;;
                    AttemptFailed)  ACT_SIGNALS+=("retry-loop") ;;
                    Running)
                        # Bug #5: check progress on all action types, not just PROGRESS_TYPES
                        if [[ -n "$ACT_PROGRESS" && "$ACT_PROGRESS" == "0" ]] && [[ "$ACT_IS_OLD" == "true" ]]; then
                            ACT_SIGNALS+=("no-progress")
                        fi
                        [[ -n "$ACT_ERR" ]] && ACT_SIGNALS+=("has-error")
                        ;;
                esac

                if [[ "$ACT_IS_OLD" == "true" ]] && [[ ${#ACT_SIGNALS[@]} -gt 0 ]]; then
                    ACT_HEALTH="STUCK"
                elif [[ "$ACT_IS_OLD" == "true" ]]; then
                    ACT_HEALTH="OLD"
                else
                    ACT_HEALTH="OK"
                fi

                # Progress suffix
                if [[ -n "$ACT_PROGRESS" ]]; then
                    ACT_PROGRESS_STR=" progress=${ACT_PROGRESS}%"
                else
                    ACT_PROGRESS_STR=" progress=—"
                fi

                # Signal suffix
                ACT_SIGNAL_STR=""
                if [[ ${#ACT_SIGNALS[@]} -gt 0 ]]; then
                    ACT_SIGNAL_STR=" ($(printf '%s, ' "${ACT_SIGNALS[@]}" | sed 's/, $//'))"
                fi

                printf "  [%-5s] %-20s %-40s age=%-5s %s%s%s\n" \
                    "$ACT_HEALTH" "$KIND" "$ACT_NAME" "${ACT_AGE_HOURS}h" "${ACT_STATE}${ACT_PROGRESS_STR}" " policy=${POL_NAME}" "$ACT_SIGNAL_STR"

                if [[ -n "$ACT_ERR" ]]; then
                    echo "          error: ${ACT_ERR}"
                fi
            done <<< "$ACTIVE_ACTIONS"
        done
    done < <(echo "$POLICIES_JSON" | jq -c '.items | sort_by(.metadata.name)[]')

    if [[ $SHOWN -eq 0 ]]; then
        echo "All policies healthy — nothing to report."
    fi

    echo ""
    echo "=== Summary ==="
    echo "Policies: ${POLICY_COUNT} (${COUNT_COMPLETE} complete, not shown)"
    echo "  Failed:    ${COUNT_FAILED}"
    echo "  Skipped:   ${COUNT_SKIPPED}"
    echo "  Running:   ${COUNT_RUNNING}"
    echo "  Stuck:     ${COUNT_STUCK}"
    echo "  Never run: ${COUNT_NORUN}"

    if [[ $COUNT_STUCK -gt 0 ]]; then
        echo ""
        echo "Tip: run with --dry-run to see what would be cancelled, or without flags to cancel stuck actions."
    fi
    exit 0
fi

# --- Show recently completed policies ---
if [[ "$SHOW_COMPLETED" == "true" ]]; then
    echo "=== Recently Completed K10 Policies ==="
    echo ""

    POLICIES_JSON=$(kubectl get policies.config.kio.kasten.io -n "$NAMESPACE" -o json 2>/dev/null) || {
        echo "Error: failed to list K10 policies" >&2
        exit 1
    }
    if [[ "$(echo "$POLICIES_JSON" | jq '.items | length')" == "0" ]]; then
        echo "No K10 policies found in namespace ${NAMESPACE}."
        exit 0
    fi

    COUNT_COMPLETED=0
    SHOWN=0

    while read -r POLICY; do
        POL_NAME=$(echo "$POLICY" | jq -r '.metadata.name')

        # Extract target namespace(s)
        POL_NS=$(echo "$POLICY" | jq -r '
            [
                (.spec.selector.matchExpressions // [] | map(select(.key == "k10.kasten.io/appNamespace")) | .[0].values // [])[]
            ] | join(", ")
        ')
        if [[ -z "$POL_NS" ]]; then
            POL_NS=$(echo "$POLICY" | jq -r '
                .spec.selector.matchLabels["k10.kasten.io/appNamespace"] // empty
            ')
        fi
        [[ -z "$POL_NS" ]] && POL_NS="(all)"

        build_namespace_list "$POL_NS"

        # Find the most recent action for this policy across all action types
        LATEST_TIME=""
        LATEST_STATUS=""
        LATEST_VERB=""

        while IFS= read -r ACT_VERB; do
            [[ -z "$ACT_VERB" ]] && continue
            RESOURCE="${ACTION_VERB_MAP[$ACT_VERB]:-}"
            [[ -z "$RESOURCE" ]] && continue

            for SEARCH_NS in "${TARGET_NAMESPACES[@]}"; do
                LATEST_ACTION=$(kubectl get "$RESOURCE" -n "$SEARCH_NS" \
                    -l "k10.kasten.io/policyName=${POL_NAME}" \
                    --sort-by=.metadata.creationTimestamp \
                    -o json 2>/dev/null | jq '.items[-1] // empty') || true

                [[ -z "$LATEST_ACTION" || "$LATEST_ACTION" == "null" ]] && continue

                ACT_TIME=$(echo "$LATEST_ACTION" | jq -r '.metadata.creationTimestamp // empty')
                [[ -z "$ACT_TIME" ]] && continue

                act_epoch=""
                act_epoch=$(date -d "$ACT_TIME" +%s 2>/dev/null) || continue
                if [[ -z "$LATEST_TIME" ]] || [[ $act_epoch -gt $(date -d "$LATEST_TIME" +%s 2>/dev/null || echo 0) ]]; then
                    LATEST_TIME="$ACT_TIME"
                    LATEST_STATUS=$(echo "$LATEST_ACTION" | jq -r '.status.state // "Unknown"')
                    LATEST_VERB="$ACT_VERB"
                fi
            done
        done < <(echo "$POLICY" | jq -r '.spec.actions[].action // empty')

        # Only show completed policies
        [[ "$LATEST_STATUS" != "Complete" ]] && continue

        COUNT_COMPLETED=$((COUNT_COMPLETED + 1))

        # Format completed time
        DISPLAY_TIME=$(date -d "$LATEST_TIME" "+%a %b %d %Y %I:%M %p" 2>/dev/null || echo "$LATEST_TIME")

        # Format action verb for display
        case "$LATEST_VERB" in
            backup)  ACTION_DISPLAY="Snapshot" ;;
            export)  ACTION_DISPLAY="Export" ;;
            restore) ACTION_DISPLAY="Restore" ;;
            retire)  ACTION_DISPLAY="Retire" ;;
            report)  ACTION_DISPLAY="Report" ;;
            *)       ACTION_DISPLAY="$(echo "${LATEST_VERB:0:1}" | tr '[:lower:]' '[:upper:]')${LATEST_VERB:1}" ;;
        esac

        # Print header on first result
        if [[ $SHOWN -eq 0 ]]; then
            printf "%-28s %-20s %-22s %s\n" \
                "NAME" "NAMESPACE" "ACTION" "COMPLETED AT"
            printf "%s\n" "--------------------------------------------------------------------------------------------"
        fi
        SHOWN=$((SHOWN + 1))

        printf "%-28s %-20s %-22s %s\n" \
            "$POL_NAME" "$POL_NS" "$ACTION_DISPLAY" "$DISPLAY_TIME"
    done < <(echo "$POLICIES_JSON" | jq -c '.items | sort_by(.metadata.name)[]')

    echo ""
    if [[ $COUNT_COMPLETED -eq 0 ]]; then
        echo "No recently completed policies found."
    else
        echo "${COUNT_COMPLETED} completed $(if [[ $COUNT_COMPLETED -eq 1 ]]; then echo "policy"; else echo "policies"; fi)."
    fi
    exit 0
fi

# --- Cancel mode ---
if [[ "$DRY_RUN" == "true" ]]; then
    echo "[DRY RUN] No changes will be made."
fi
echo "Stuck detection: actions older than ${MAX_AGE_DISPLAY}"
echo ""

TOTAL_FOUND=0
TOTAL_STUCK=0
TOTAL_CANCELLED=0
TOTAL_DELETED=0
TOTAL_FAILED=0
TOTAL_SKIPPED=0

# Detection reason counters
COUNT_PENDING=0
COUNT_ATTEMPT_FAILED=0
COUNT_NO_PROGRESS=0
COUNT_ERROR_SIGNAL=0

for ACTION_TYPE in "${ACTION_TYPES[@]}"; do
    KIND="${KIND_MAP[$ACTION_TYPE]}"

    # Bug #6: use awk to match status column, not grep across entire line
    CANDIDATES=$(kubectl get "$ACTION_TYPE" -n "$NAMESPACE" --no-headers \
        -o custom-columns=NAME:.metadata.name,STATUS:.status.state 2>&1 \
        | filter_by_status || true)

    [[ -z "$CANDIDATES" ]] && continue

    while read -r ACTION_NAME _STATUS; do
        [[ -z "$ACTION_NAME" ]] && continue
        TOTAL_FOUND=$((TOTAL_FOUND + 1))

        # Bug #8: validate resource name before using in YAML
        if ! is_valid_k8s_name "$ACTION_NAME"; then
            echo "Warning: invalid resource name '${ACTION_NAME}', skipping"
            continue
        fi

        # Bug #9: re-fetch action state to handle TOCTOU race
        ACTION_JSON=$(kubectl get "$ACTION_TYPE" "$ACTION_NAME" -n "$NAMESPACE" --request-timeout=30s -o json 2>&1) || {
            echo "Warning: could not fetch ${KIND} ${ACTION_NAME} (may have completed), skipping"
            continue
        }
        if [[ -z "$ACTION_JSON" ]]; then
            echo "Warning: empty response for ${KIND} ${ACTION_NAME}, skipping"
            continue
        fi

        # Extract fields with jq
        CREATION_TS=$(echo "$ACTION_JSON" | jq -r '.metadata.creationTimestamp // empty')
        START_TIME=$(echo "$ACTION_JSON" | jq -r '.status.startTime // empty')
        STATE=$(echo "$ACTION_JSON" | jq -r '.status.state // empty')
        PROGRESS=$(echo "$ACTION_JSON" | jq -r '.status.progress // empty')
        ERROR_MSG=$(echo "$ACTION_JSON" | jq -r '.status.error.message // empty')
        POLICY_NAME=$(echo "$ACTION_JSON" | jq -r '.metadata.labels["k10.kasten.io/policyName"] // empty')

        # Bug #9: skip if action is no longer in a target state (completed between list and fetch)
        case "$STATE" in
            Pending|Running|AttemptFailed) ;;
            *)
                echo "Skipping ${KIND} ${ACTION_NAME} — state changed to ${STATE}"
                TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
                continue
                ;;
        esac

        # Compute age: prefer startTime for Running, fall back to creationTimestamp
        if [[ -n "$START_TIME" && "$STATE" == "Running" ]]; then
            AGE_REF="$START_TIME"
        else
            AGE_REF="$CREATION_TS"
        fi

        if [[ -z "$AGE_REF" ]]; then
            echo "Warning: no timestamp for ${KIND} ${ACTION_NAME}, skipping"
            continue
        fi

        # Bug #11: use compute_age with clock skew protection
        AGE_SECONDS=$(compute_age "$AGE_REF") || {
            echo "Warning: could not parse timestamp '${AGE_REF}' for ${KIND} ${ACTION_NAME}, skipping"
            continue
        }
        if [[ $AGE_SECONDS -lt 3600 ]]; then
            AGE_HOURS="$(awk "BEGIN { printf \"%.1f\", ${AGE_SECONDS}/3600 }")"
        else
            AGE_HOURS=$((AGE_SECONDS / 3600))
        fi

        # Gate: skip actions younger than the threshold
        if [[ $AGE_SECONDS -lt $MAX_AGE_SECONDS ]]; then
            TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
            continue
        fi

        # Determine stuck reason(s)
        REASONS=()

        case "$STATE" in
            Pending)
                REASONS+=("Pending for ${AGE_HOURS}h (never started)")
                COUNT_PENDING=$((COUNT_PENDING + 1))
                ;;
            AttemptFailed)
                REASONS+=("AttemptFailed for ${AGE_HOURS}h (stuck in retry loop)")
                COUNT_ATTEMPT_FAILED=$((COUNT_ATTEMPT_FAILED + 1))
                ;;
            Running)
                # Running actions need an additional signal beyond age
                HAS_SIGNAL=false

                # Bug #5: check progress stall on all action types
                if [[ -n "$PROGRESS" && "$PROGRESS" == "0" ]]; then
                    REASONS+=("no progress (progress=0 after ${AGE_HOURS}h)")
                    COUNT_NO_PROGRESS=$((COUNT_NO_PROGRESS + 1))
                    HAS_SIGNAL=true
                fi

                # Check error signal
                if [[ -n "$ERROR_MSG" ]]; then
                    REASONS+=("error present")
                    COUNT_ERROR_SIGNAL=$((COUNT_ERROR_SIGNAL + 1))
                    HAS_SIGNAL=true
                fi

                if [[ "$HAS_SIGNAL" != "true" ]]; then
                    # Running, old, but no stuck signal — skip to protect healthy long ops
                    TOTAL_SKIPPED=$((TOTAL_SKIPPED + 1))
                    continue
                fi
                ;;
        esac

        TOTAL_STUCK=$((TOTAL_STUCK + 1))
        REASON_STR=$(printf '%s, ' "${REASONS[@]}" | sed 's/, $//')
        POLICY_LABEL=""
        if [[ -n "$POLICY_NAME" ]]; then
            POLICY_LABEL=" policy=${POLICY_NAME}"
        fi
        echo "STUCK: ${KIND} ${ACTION_NAME} [${STATE}]${POLICY_LABEL} — age ${AGE_HOURS}h — ${REASON_STR}"
        if [[ -n "$ERROR_MSG" ]]; then
            echo "  error: ${ERROR_MSG}"
        fi

        if [[ "$DRY_RUN" == "true" ]]; then
            echo "  -> Would attempt cancel, then delete if cancel fails"
            continue
        fi

        # Try CancelAction first (works for Running actions)
        cancel_yaml=""
        cancel_yaml=$(sed \
            -e "s|__ACTION_NAME__|${ACTION_NAME}|g" \
            -e "s|__NAMESPACE__|${NAMESPACE}|g" \
            -e "s|__KIND__|${KIND}|g" <<'EOF'
apiVersion: actions.kio.kasten.io/v1alpha1
kind: CancelAction
metadata:
  generateName: cancel-__ACTION_NAME__-
  namespace: __NAMESPACE__
spec:
  subject:
    apiVersion: actions.kio.kasten.io/v1alpha1
    kind: __KIND__
    name: __ACTION_NAME__
    namespace: __NAMESPACE__
EOF
        )
        if echo "$cancel_yaml" | kubectl create --request-timeout=30s -n "$NAMESPACE" -f - 2>&1; then
            echo "  -> Cancelled via CancelAction"
            TOTAL_CANCELLED=$((TOTAL_CANCELLED + 1))
        else
            # CancelAction failed (likely "not yet cancelable" for Pending actions)
            # Fall back to direct deletion
            echo "  -> CancelAction failed, deleting directly..."
            if kubectl delete "$ACTION_TYPE" "$ACTION_NAME" -n "$NAMESPACE" --request-timeout=30s 2>&1; then
                echo "  -> Deleted"
                TOTAL_DELETED=$((TOTAL_DELETED + 1))
            else
                echo "  -> FAILED to delete"
                TOTAL_FAILED=$((TOTAL_FAILED + 1))
            fi
        fi
    done <<< "$CANDIDATES"
done

echo ""
echo "=== Summary ==="
echo "Found:     ${TOTAL_FOUND} actions in target states (Pending/Running/AttemptFailed)"
echo "Skipped:   ${TOTAL_SKIPPED} (too young or Running without stuck signals)"
echo "Stuck:     ${TOTAL_STUCK} actions identified as stuck"
echo "Cancelled: ${TOTAL_CANCELLED}"
echo "Deleted:   ${TOTAL_DELETED}"
echo "Failed:    ${TOTAL_FAILED}"
echo ""
echo "--- Detection breakdown ---"
echo "Pending (never started): ${COUNT_PENDING}"
echo "AttemptFailed (retry):   ${COUNT_ATTEMPT_FAILED}"
echo "No progress (stalled):   ${COUNT_NO_PROGRESS}"
echo "Error signal:            ${COUNT_ERROR_SIGNAL}"

exit $(( TOTAL_FAILED > 0 ? 1 : 0 ))
