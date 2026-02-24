# k10-cleaner — license compliance engine
# Copyright (c) 2026 Georgios Kapellakis
# Licensed under AGPL-3.0 — see LICENSE for details.
#
# Replaces k10-cleaner-lib.sh. Provides cluster fingerprinting, enterprise
# detection, environment detection, license validation, and Telegram alerts.

from __future__ import annotations

import atexit
import base64
import hashlib
import os
import re
import signal
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

from . import VERSION
from .db import K10Database
from .kubectl import Kubectl

_LICENSE_PUBLIC_KEY_HEX = "2530cc7dd44d956df636564d70d100656e84cb9a6d970b29f63cb08e02a98753"


def _verify_license_signature(fingerprint: str, license_key: str) -> bool:
    """Verify a ``k10-<base64url>`` license key against a cluster fingerprint."""
    if not license_key.startswith("k10-"):
        return False
    encoded = license_key[4:]
    encoded += "=" * (-len(encoded) % 4)  # restore base64url padding
    try:
        sig_bytes = base64.urlsafe_b64decode(encoded)
    except Exception:
        return False
    if len(sig_bytes) != 64:
        return False

    pub_key_bytes = bytes.fromhex(_LICENSE_PUBLIC_KEY_HEX)
    message = fingerprint.encode()

    # Try the C-backed cryptography library first (faster)
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        pk = Ed25519PublicKey.from_public_bytes(pub_key_bytes)
        pk.verify(sig_bytes, message)
        return True
    except ImportError:
        pass  # cryptography not installed — use pure-Python fallback
    except Exception:
        return False  # invalid signature or malformed key

    # Pure-Python fallback (zero dependencies)
    from .ed25519_verify import verify

    return verify(pub_key_bytes, sig_bytes, message)


_TELEMETRY_ENDPOINT = "https://k10-monitor.togioma.gr/api/v1/telemetry"

# Pre-compiled environment classification patterns
_PAT_PROD = re.compile(r"(?:^|[^a-z])(prod|prd|production|live)(?:[^a-z]|$)", re.I)
_PAT_DR = re.compile(r"(?:^|[^a-z])(dr|disaster-recovery|failover|standby)(?:[^a-z]|$)", re.I)
_PAT_UAT = re.compile(r"(?:^|[^a-z])(uat|acceptance|pre-prod|preprod)(?:[^a-z]|$)", re.I)
_PAT_STAGING = re.compile(r"(?:^|[^a-z])(staging|stg|stage)(?:[^a-z]|$)", re.I)
_PAT_DEV = re.compile(
    r"(?:^|[^a-z])(dev|develop|development|sandbox|test|testing|lab|local|minikube|kind|k3s|docker-desktop)(?:[^a-z]|$)",
    re.I,
)


@dataclass
class ClusterInfo:
    fingerprint: str = "unknown"
    enterprise_score: int = 0
    node_count: int = 0
    namespace_count: int = 0
    provider: str = "unknown"
    k10_version: str = "unknown"
    cp_nodes: int = 0
    has_paid_license: bool = False
    is_enterprise: bool = False
    environment: str = "unknown"
    env_source: str = "none"
    license_required: bool = False
    licensed: bool = False
    run_count: int = 0
    public_ip: str = "unknown"
    server_url: str = "unknown"


class ComplianceEngine:
    def __init__(self, kubectl: Kubectl, db: K10Database):
        self._kc = kubectl
        self._db = db
        self.info = ClusterInfo()

    # ------------------------------------------------------------------
    # Fingerprint
    # ------------------------------------------------------------------
    def cluster_fingerprint(self):
        uid = self._kc.get_namespace_uid("kube-system")
        if not uid:
            self.info.fingerprint = "unknown"
            return
        self.info.fingerprint = hashlib.sha256(uid.encode()).hexdigest()[:16]
        self._db.record_fingerprint(self.info.fingerprint)

    # ------------------------------------------------------------------
    # Network info
    # ------------------------------------------------------------------
    def detect_network_info(self):
        """Detect public IP and K8s API server URL."""
        # Public IP — try multiple services, 3s timeout each
        for endpoint in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"):
            try:
                req = urllib.request.Request(endpoint, headers={"User-Agent": "k10-cleaner"})
                resp = urllib.request.urlopen(req, timeout=3)
                ip = resp.read().decode().strip()
                if ip:
                    self.info.public_ip = ip
                    break
            except Exception:
                continue

        # K8s API server URL
        self.info.server_url = self._kc.get_server_url() or "unknown"

    # ------------------------------------------------------------------
    # Enterprise detection (5-signal scoring)
    # ------------------------------------------------------------------
    def detect_enterprise(self):
        score = 0
        info = self.info

        # Signal 1: node count > 3
        try:
            info.node_count = self._kc.count_resources("nodes")
        except Exception:
            info.node_count = 0
        if info.node_count > 3:
            score += 1

        # Signal 2: managed Kubernetes (EKS/AKS/GKE/OpenShift)
        try:
            node_labels = self._kc.get_node_labels_json()
        except Exception:
            node_labels = ""
        try:
            server_version = self._kc.get_server_version()
        except Exception:
            server_version = ""

        if "eks.amazonaws.com" in node_labels.lower():
            info.provider = "EKS"
            score += 1
        elif "kubernetes.azure.com" in node_labels.lower():
            info.provider = "AKS"
            score += 1
        elif "cloud.google.com/gke" in node_labels.lower():
            info.provider = "GKE"
            score += 1
        elif "openshift" in server_version.lower():
            info.provider = "OpenShift"
            score += 1

        # Signal 3: namespace count > 10
        try:
            info.namespace_count = self._kc.count_resources("namespaces")
        except Exception:
            info.namespace_count = 0
        if info.namespace_count > 10:
            score += 1

        # Signal 4: HA control plane
        try:
            info.cp_nodes = self._kc.count_resources(
                "nodes", ["-l", "node-role.kubernetes.io/control-plane"]
            )
        except Exception:
            info.cp_nodes = 0
        if info.cp_nodes <= 0:
            try:
                info.cp_nodes = self._kc.count_resources(
                    "nodes", ["-l", "node-role.kubernetes.io/master"]
                )
            except Exception:
                info.cp_nodes = 0
        try:
            apiserver_pods = self._kc.count_resources(
                "pods", ["-n", "kube-system", "-l", "component=kube-apiserver"]
            )
        except Exception:
            apiserver_pods = 0
        if info.cp_nodes > 1 or apiserver_pods > 1:
            score += 1

        # Signal 5: paid K10 license (>5 nodes + license secret/configmap)
        if info.node_count > 5:
            has_license = False
            for check_args in (
                ["get", "configmap", "-n", "kasten-io", "-l", "app=k10,component=license", "--no-headers"],
                ["get", "secret", "-n", "kasten-io", "-l", "app=k10,component=license", "--no-headers"],
                ["get", "configmap", "k10-license", "-n", "kasten-io", "--no-headers"],
                ["get", "secret", "k10-license", "-n", "kasten-io", "--no-headers"],
            ):
                try:
                    lines = self._kc.get_lines(check_args)
                    if lines:
                        has_license = True
                        break
                except Exception:
                    pass
            if has_license:
                info.has_paid_license = True
                score += 1

        # K10 version
        rc, out, _ = self._kc.run(
            ["get", "deployment", "catalog-svc", "-n", "kasten-io",
             "-o", "jsonpath={.metadata.labels.version}"]
        )
        if rc == 0 and out.strip():
            info.k10_version = out.strip()
        else:
            rc, out, _ = self._kc.run(
                ["get", "deployment", "catalog-svc", "-n", "kasten-io",
                 "-o", "jsonpath={.spec.template.spec.containers[0].image}"]
            )
            if rc == 0 and out.strip():
                info.k10_version = out.strip().rsplit(":", 1)[-1]
            else:
                info.k10_version = "unknown"

        info.enterprise_score = score
        info.is_enterprise = score >= 3

    # ------------------------------------------------------------------
    # Environment detection (6-signal cascade)
    # ------------------------------------------------------------------
    @staticmethod
    def _classify_string(text: str) -> str | None:
        """Classify text against known environment patterns. Returns env name or None."""
        if not text:
            return None
        for pat, env in (
            (_PAT_PROD, "production"),
            (_PAT_DR, "dr"),
            (_PAT_UAT, "uat"),
            (_PAT_STAGING, "staging"),
            (_PAT_DEV, "dev"),
        ):
            if pat.search(text):
                return env
        return None

    def detect_environment(self):
        info = self.info

        # Manual override
        override = os.environ.get("K10CLEANER_ENVIRONMENT", "")
        if override:
            info.environment = override
            info.env_source = "K10CLEANER_ENVIRONMENT"
            self._env_license_decision()
            return

        # Signal 1: kubectl current-context
        context = self._kc.get_current_context()
        env = self._classify_string(context)
        if env:
            info.environment = env
            info.env_source = f"context:{context}"
            self._env_license_decision()
            return

        # Signal 2: cluster name
        cluster_name = self._kc.get_cluster_name()
        env = self._classify_string(cluster_name)
        if env:
            info.environment = env
            info.env_source = f"cluster-name:{cluster_name}"
            self._env_license_decision()
            return

        # Signal 3: namespace labels
        ns_labels = self._kc.get_ns_env_labels()
        env = self._classify_string(ns_labels)
        if env:
            info.environment = env
            info.env_source = "namespace-label"
            self._env_license_decision()
            return

        # Signal 4: node labels
        node_labels = self._kc.get_node_env_labels()
        env = self._classify_string(node_labels)
        if env:
            info.environment = env
            info.env_source = "node-label"
            self._env_license_decision()
            return

        # Signal 5: server URL
        server_url = self._kc.get_server_url()
        env = self._classify_string(server_url)
        if env:
            info.environment = env
            info.env_source = "server-url"
            self._env_license_decision()
            return

        # No match — fall back to enterprise score
        info.env_source = "enterprise-score"
        self._env_license_decision()

    def _env_license_decision(self):
        info = self.info
        if info.environment in ("production", "dr"):
            info.license_required = True
        elif info.environment in ("dev", "uat", "staging"):
            info.license_required = False
        else:
            info.license_required = info.enterprise_score >= 3

    # ------------------------------------------------------------------
    # License key validation (Ed25519 signature)
    # ------------------------------------------------------------------
    def validate_license(self) -> bool:
        # Env var takes priority, then DB
        user_key = os.environ.get("K10CLEANER_LICENSE_KEY") or self._db.get_config("license_key")
        if not user_key:
            return False
        fp = self.info.fingerprint
        if not fp or fp == "unknown":
            return False
        return _verify_license_signature(fp, user_key)

    # ------------------------------------------------------------------
    # Telegram notification
    # ------------------------------------------------------------------
    def _telegram_notify(self, event_type: str):
        if os.environ.get("K10CLEANER_NO_PHONE_HOME", "") == "true":
            return

        # Env var overrides DB; DB holds the persisted defaults
        token = os.environ.get("K10CLEANER_TG_TOKEN") or self._db.get_config("tg_token")
        chat_id = os.environ.get("K10CLEANER_TG_CHAT_ID") or self._db.get_config("tg_chat_id")

        if not token or not chat_id or token == "PLACEHOLDER_BOT_TOKEN":
            return

        if self._db.is_telegram_failed():
            return

        info = self.info
        icons = {"UNLICENSED_RUN": "\U0001f534", "TAMPER_DETECTED": "\U0001f6a8"}
        icon = icons.get(event_type, "\u26a0\ufe0f")
        subjects = {
            "UNLICENSED_RUN": f"Unlicensed {info.environment} use",
            "TAMPER_DETECTED": "TAMPER DETECTED",
        }
        subject = subjects.get(event_type, event_type)

        from .db import _utcnow

        text = (
            f"{icon} *K10-CLEANER License Alert*\n"
            f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\n"
            f"*Event:* {subject}\n"
            f"*Environment:* {info.environment} ({info.env_source})\n"
            f"*Cluster ID:* `{info.fingerprint}`\n"
            f"*Provider:* {info.provider}\n"
            f"*Nodes:* {info.node_count} ({info.cp_nodes} control-plane)\n"
            f"*Namespaces:* {info.namespace_count}\n"
            f"*K10 Version:* {info.k10_version}\n"
            f"*Enterprise Score:* {info.enterprise_score}/5\n"
            f"*Public IP:* `{info.public_ip}`\n"
            f"*API Server:* `{info.server_url}`\n"
            f"*Unlicensed Run #:* {info.run_count}\n"
            f"*Tool Version:* {VERSION}\n"
            f"*Timestamp:* {_utcnow()}"
        )

        data = urllib.parse.urlencode({
            "chat_id": chat_id,
            "parse_mode": "Markdown",
            "text": text,
        }).encode()

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        req = urllib.request.Request(url, data=data, method="POST")
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            # Permanent failure only on auth errors (bad token/chat_id)
            if e.code in (401, 403, 404):
                self._db.mark_telegram_failed()
        except Exception:
            pass  # Transient network errors — retry next run

    # ------------------------------------------------------------------
    # Compliance telemetry report
    # ------------------------------------------------------------------
    def _compliance_report(self):
        info = self.info
        if not info.license_required:
            return
        if info.licensed:
            return
        if os.environ.get("K10CLEANER_NO_PHONE_HOME", "") == "true":
            return

        license_key_provided = bool(os.environ.get("K10CLEANER_LICENSE_KEY", ""))
        license_key_valid = self.validate_license() if license_key_provided else False

        from .db import _utcnow
        import json

        payload = json.dumps({
            "event": "unlicensed_run",
            "fingerprint": info.fingerprint,
            "environment": info.environment,
            "env_source": info.env_source,
            "public_ip": info.public_ip,
            "server_url": info.server_url,
            "provider": info.provider,
            "node_count": info.node_count,
            "cp_nodes": info.cp_nodes,
            "namespace_count": info.namespace_count,
            "k10_version": info.k10_version,
            "enterprise_score": info.enterprise_score,
            "license_key_provided": license_key_provided,
            "license_key_valid": license_key_valid,
            "unlicensed_run_count": info.run_count,
            "tool_version": VERSION,
            "timestamp": _utcnow(),
        }).encode()

        req = urllib.request.Request(
            _TELEMETRY_ENDPOINT,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            urllib.request.urlopen(req, timeout=5)
        except Exception:
            pass  # telemetry has its own fail marker in bash; simplified here

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------
    def show_banner(self):
        info = self.info

        if not info.license_required:
            if os.environ.get("K10CLEANER_NO_BANNER", "") == "true":
                return
            return

        if self.validate_license():
            info.licensed = True
            return
        info.licensed = False

        # Banner title
        titles = {
            "production": "Production Environment",
            "dr": "DR Environment",
        }
        banner_title = titles.get(
            info.environment,
            f"Enterprise Environment (score {info.enterprise_score}/5)",
        )

        # Increment run count BEFORE delay — Ctrl+C cannot undo this
        info.run_count = self._db.increment_run_count(info.fingerprint)

        # Escalating delay
        delay_override = os.environ.get("_K10_UNLICENSED_DELAY")
        if delay_override is not None:
            try:
                delay = max(0, int(delay_override))
            except ValueError:
                delay = 10 + (info.run_count - 1) * 60
        else:
            delay = 10 + (info.run_count - 1) * 60

        self._db.append_audit(
            info.fingerprint, info.environment,
            "UNLICENSED_RUN",
            f"run_count={info.run_count} delay={delay}s",
        )
        self._telegram_notify("UNLICENSED_RUN")

        banner = (
            f"================================================================================\n"
            f"  K10-CLEANER  \u2014  {banner_title} (Unlicensed)\n"
            f"================================================================================\n"
            f"  Environment:  {info.environment} (detected via {info.env_source})\n"
            f"  Provider:     {info.provider}\n"
            f"  Nodes:        {info.node_count} ({info.cp_nodes} control-plane)\n"
            f"  Namespaces:   {info.namespace_count}\n"
            f"  K10 version:  {info.k10_version}\n"
            f"  Cluster ID:   {info.fingerprint}\n"
            f"  Public IP:    {info.public_ip}\n"
            f"  API Server:   {info.server_url}\n"
            f"  Score:        {info.enterprise_score}/5\n"
            f"  Run #:        {info.run_count} (delay increases by 60s per unlicensed run)\n"
            f"--------------------------------------------------------------------------------\n"
            f"  This tool is licensed under AGPL-3.0. Production and DR use without source\n"
            f"  disclosure requires a commercial license.\n"
            f"\n"
            f"  To obtain a license key for this cluster, contact:\n"
            f"    georgios.kapellakis@yandex.com\n"
            f"\n"
            f"  Include your Cluster ID in the request. Once received:\n"
            f"    export K10CLEANER_LICENSE_KEY=<your-key>\n"
            f"\n"
            f"  Details: COMMERCIAL_LICENSE.md\n"
            f"================================================================================"
        )
        print(banner, file=sys.stderr)

        if delay > 0:
            print(
                f"  Continuing in {delay}s \u2014 obtain a license to remove this delay...",
                file=sys.stderr,
            )
            old_handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, signal.SIG_IGN)
            time.sleep(delay)
            signal.signal(signal.SIGINT, old_handler)

    # ------------------------------------------------------------------
    # Unlicensed warning (registered as atexit)
    # ------------------------------------------------------------------
    def unlicensed_warning(self):
        if not self.info.license_required:
            return
        if self.info.licensed:
            return
        print(
            f"[K10-CLEANER] WARNING: Unlicensed {self.info.environment} use detected "
            f"(cluster {self.info.fingerprint}). License required \u2014 "
            f"see COMMERCIAL_LICENSE.md or contact georgios.kapellakis@yandex.com",
            file=sys.stderr,
        )

    # ------------------------------------------------------------------
    # Orchestrator
    # ------------------------------------------------------------------
    def license_check(self):
        self.cluster_fingerprint()
        self.detect_enterprise()
        self.detect_environment()
        self.detect_network_info()
        self.show_banner()
        self._compliance_report()
        if self.info.license_required and not self.info.licensed:
            atexit.register(self.unlicensed_warning)
