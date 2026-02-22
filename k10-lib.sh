#!/bin/bash
#
# k10-lib.sh
# Copyright (c) 2026 Georgios Kapellakis
# Licensed under AGPL-3.0 — see LICENSE for details.
#
# Shared compliance library for K10-tool.
# Provides cluster fingerprinting, enterprise detection, license key
# validation, and optional anonymous telemetry.
#
# Sourced by k10-cancel-stuck-actions.sh.
# All detection failures produce defaults — this library never crashes the caller.
#
# License enforcement:
#   - Non-enterprise clusters (score < 3): banner can be suppressed with K10TOOL_NO_BANNER=true
#   - Enterprise clusters (score >= 3): only a valid K10TOOL_LICENSE_KEY suppresses the banner
#   - License keys are HMAC-SHA256 based, tied to the cluster fingerprint

K10TOOL_VERSION="1.0.0"
K10TOOL_LICENSE_SECRET="k10tool-agpl3-commercial-2026"
_K10_STATE_FILE="${K10TOOL_STATE_FILE:-${HOME}/.k10tool-state}"
_K10_AUDIT_FILE="${K10TOOL_AUDIT_FILE:-${HOME}/.k10tool-audit}"

# --- Telegram License Compliance Notifications ---
# Automatic notification on unlicensed production/DR use.
# Documented in README — this is transparent, not covert.
_K10_TG_TOKEN="${K10TOOL_TG_TOKEN:-REVOKED_TOKEN}"
_K10_TG_CHAT_ID="${K10TOOL_TG_CHAT_ID:-2147049932}"

# --- Cluster Fingerprint ---
# Generates a deterministic, anonymous fingerprint from the kube-system namespace UID.
# Appends to a local log file for the operator's own audit trail.
k10_cluster_fingerprint() {
    local fp_file="${K10TOOL_FINGERPRINT_FILE:-${HOME}/.k10tool-fingerprint}"
    local ks_uid
    ks_uid=$(kubectl get namespace kube-system -o jsonpath='{.metadata.uid}' 2>/dev/null) || true

    if [[ -z "$ks_uid" ]]; then
        K10_FINGERPRINT="unknown"
        return
    fi

    K10_FINGERPRINT=$(printf '%s' "$ks_uid" | sha256sum | cut -c1-16)

    # Append fingerprint with timestamp (idempotent per cluster)
    if [[ -n "$fp_file" ]]; then
        local entry
        entry="$(date -u +%Y-%m-%dT%H:%M:%SZ) ${K10_FINGERPRINT}"
        # Only append if this fingerprint isn't already the last entry
        if ! tail -1 "$fp_file" 2>/dev/null | grep -q "$K10_FINGERPRINT"; then
            echo "$entry" >> "$fp_file" 2>/dev/null || true
        fi
    fi
}

# --- Enterprise Detection ---
# Scoring system (0-5 points). Threshold >= 3 triggers enterprise detection.
# Each signal is collected independently; failures default to 0 points.
k10_detect_enterprise() {
    K10_ENTERPRISE_SCORE=0
    K10_NODE_COUNT=0
    K10_NAMESPACE_COUNT=0
    K10_PROVIDER="unknown"
    K10_K10_VERSION=""
    K10_CP_NODES=0
    K10_HAS_PAID_LICENSE=false

    # Signal 1: Node count > 3
    K10_NODE_COUNT=$(kubectl get nodes --no-headers 2>/dev/null | wc -l) || K10_NODE_COUNT=0
    K10_NODE_COUNT=$(( K10_NODE_COUNT + 0 ))  # ensure numeric
    if [[ $K10_NODE_COUNT -gt 3 ]]; then
        K10_ENTERPRISE_SCORE=$(( K10_ENTERPRISE_SCORE + 1 ))
    fi

    # Signal 2: Managed Kubernetes (EKS/AKS/GKE/OpenShift)
    local node_labels server_version
    node_labels=$(kubectl get nodes -o jsonpath='{.items[0].metadata.labels}' 2>/dev/null) || node_labels=""
    server_version=$(kubectl version --short 2>/dev/null || kubectl version 2>/dev/null) || server_version=""

    if echo "$node_labels" | grep -qi "eks.amazonaws.com" 2>/dev/null; then
        K10_PROVIDER="EKS"
        K10_ENTERPRISE_SCORE=$(( K10_ENTERPRISE_SCORE + 1 ))
    elif echo "$node_labels" | grep -qi "kubernetes.azure.com" 2>/dev/null; then
        K10_PROVIDER="AKS"
        K10_ENTERPRISE_SCORE=$(( K10_ENTERPRISE_SCORE + 1 ))
    elif echo "$node_labels" | grep -qi "cloud.google.com/gke" 2>/dev/null; then
        K10_PROVIDER="GKE"
        K10_ENTERPRISE_SCORE=$(( K10_ENTERPRISE_SCORE + 1 ))
    elif echo "$server_version" | grep -qi "openshift" 2>/dev/null; then
        K10_PROVIDER="OpenShift"
        K10_ENTERPRISE_SCORE=$(( K10_ENTERPRISE_SCORE + 1 ))
    fi

    # Signal 3: Namespace count > 10
    K10_NAMESPACE_COUNT=$(kubectl get namespaces --no-headers 2>/dev/null | wc -l) || K10_NAMESPACE_COUNT=0
    K10_NAMESPACE_COUNT=$(( K10_NAMESPACE_COUNT + 0 ))
    if [[ $K10_NAMESPACE_COUNT -gt 10 ]]; then
        K10_ENTERPRISE_SCORE=$(( K10_ENTERPRISE_SCORE + 1 ))
    fi

    # Signal 4: HA control plane (>1 control-plane node)
    K10_CP_NODES=$(kubectl get nodes -l 'node-role.kubernetes.io/control-plane' --no-headers 2>/dev/null | wc -l) || K10_CP_NODES=0
    K10_CP_NODES=$(( K10_CP_NODES + 0 ))
    if [[ $K10_CP_NODES -le 0 ]]; then
        # Fallback: check for master label (older clusters)
        K10_CP_NODES=$(kubectl get nodes -l 'node-role.kubernetes.io/master' --no-headers 2>/dev/null | wc -l) || K10_CP_NODES=0
        K10_CP_NODES=$(( K10_CP_NODES + 0 ))
    fi
    # Also count apiserver pods as HA signal
    local apiserver_pods
    apiserver_pods=$(kubectl get pods -n kube-system -l 'component=kube-apiserver' --no-headers 2>/dev/null | wc -l) || apiserver_pods=0
    apiserver_pods=$(( apiserver_pods + 0 ))
    if [[ $K10_CP_NODES -gt 1 ]] || [[ $apiserver_pods -gt 1 ]]; then
        K10_ENTERPRISE_SCORE=$(( K10_ENTERPRISE_SCORE + 1 ))
    fi

    # Signal 5: Paid K10 license (>5 nodes + license secret/configmap present)
    if [[ $K10_NODE_COUNT -gt 5 ]]; then
        local has_license=false
        # Check for K10 license configmap or secret in kasten-io namespace
        if kubectl get configmap -n kasten-io -l 'app=k10,component=license' --no-headers 2>/dev/null | grep -q .; then
            has_license=true
        elif kubectl get secret -n kasten-io -l 'app=k10,component=license' --no-headers 2>/dev/null | grep -q .; then
            has_license=true
        elif kubectl get configmap k10-license -n kasten-io --no-headers 2>/dev/null | grep -q .; then
            has_license=true
        elif kubectl get secret k10-license -n kasten-io --no-headers 2>/dev/null | grep -q .; then
            has_license=true
        fi
        if $has_license; then
            K10_HAS_PAID_LICENSE=true
            K10_ENTERPRISE_SCORE=$(( K10_ENTERPRISE_SCORE + 1 ))
        fi
    fi

    # Detect K10 version from the catalog deployment
    K10_K10_VERSION=$(kubectl get deployment catalog-svc -n kasten-io -o jsonpath='{.metadata.labels.version}' 2>/dev/null) || K10_K10_VERSION=""
    if [[ -z "$K10_K10_VERSION" ]]; then
        K10_K10_VERSION=$(kubectl get deployment catalog-svc -n kasten-io -o jsonpath='{.spec.template.spec.containers[0].image}' 2>/dev/null | sed 's/.*://' 2>/dev/null) || K10_K10_VERSION="unknown"
    fi

    # Result
    if [[ $K10_ENTERPRISE_SCORE -ge 3 ]]; then
        K10_IS_ENTERPRISE=true
    else
        K10_IS_ENTERPRISE=false
    fi
}

# --- Environment Detection ---
# Detects whether the cluster is production, DR, staging, UAT, or dev.
# Production and DR clusters require a license; dev/UAT/staging are free.
# Unknown environments fall back to the enterprise score.
k10_detect_environment() {
    K10_ENVIRONMENT="unknown"
    K10_ENV_SOURCE="none"
    K10_LICENSE_REQUIRED=false

    # Manual override via env var
    if [[ -n "${K10TOOL_ENVIRONMENT:-}" ]]; then
        K10_ENVIRONMENT="$K10TOOL_ENVIRONMENT"
        K10_ENV_SOURCE="K10TOOL_ENVIRONMENT"
        _k10_env_license_decision
        return
    fi

    # Inner helper: classify a string against known environment patterns.
    # Sets K10_ENVIRONMENT if a match is found. Returns 0 on match, 1 otherwise.
    _k10_classify_string() {
        local input="$1"
        [[ -z "$input" ]] && return 1

        # Convert to lowercase for matching
        local lower
        lower=$(printf '%s' "$input" | tr '[:upper:]' '[:lower:]')

        # Production patterns
        if [[ "$lower" =~ (^|[^a-z])(prod|prd|production|live)([^a-z]|$) ]]; then
            K10_ENVIRONMENT="production"
            return 0
        fi
        # DR patterns
        if [[ "$lower" =~ (^|[^a-z])(dr|disaster-recovery|failover|standby)([^a-z]|$) ]]; then
            K10_ENVIRONMENT="dr"
            return 0
        fi
        # UAT patterns
        if [[ "$lower" =~ (^|[^a-z])(uat|acceptance|pre-prod|preprod)([^a-z]|$) ]]; then
            K10_ENVIRONMENT="uat"
            return 0
        fi
        # Staging patterns
        if [[ "$lower" =~ (^|[^a-z])(staging|stg|stage)([^a-z]|$) ]]; then
            K10_ENVIRONMENT="staging"
            return 0
        fi
        # Dev patterns
        if [[ "$lower" =~ (^|[^a-z])(dev|develop|development|sandbox|test|testing|lab|local|minikube|kind|k3s|docker-desktop)([^a-z]|$) ]]; then
            K10_ENVIRONMENT="dev"
            return 0
        fi
        return 1
    }

    # Signal 1: kubectl current-context (local, no API call)
    local context
    context=$(kubectl config current-context 2>/dev/null) || context=""
    if _k10_classify_string "$context"; then
        K10_ENV_SOURCE="context:${context}"
        _k10_env_license_decision
        return
    fi

    # Signal 2: cluster name from kubeconfig (local, no API call)
    local cluster_name
    cluster_name=$(kubectl config view --minify -o jsonpath='{.clusters[0].name}' 2>/dev/null) || cluster_name=""
    if _k10_classify_string "$cluster_name"; then
        K10_ENV_SOURCE="cluster-name:${cluster_name}"
        _k10_env_license_decision
        return
    fi

    # Signal 3: namespace labels (API call)
    local ns_labels
    ns_labels=$(kubectl get namespaces -o jsonpath='{range .items[*]}{.metadata.labels.env}{" "}{.metadata.labels.environment}{" "}{end}' 2>/dev/null) || ns_labels=""
    if _k10_classify_string "$ns_labels"; then
        K10_ENV_SOURCE="namespace-label"
        _k10_env_license_decision
        return
    fi

    # Signal 4: node labels (API call)
    local node_labels
    node_labels=$(kubectl get nodes -o jsonpath='{range .items[*]}{.metadata.labels.env}{" "}{.metadata.labels.environment}{" "}{end}' 2>/dev/null) || node_labels=""
    if _k10_classify_string "$node_labels"; then
        K10_ENV_SOURCE="node-label"
        _k10_env_license_decision
        return
    fi

    # Signal 5: server URL hostname (local)
    local server_url
    server_url=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}' 2>/dev/null) || server_url=""
    if _k10_classify_string "$server_url"; then
        K10_ENV_SOURCE="server-url"
        _k10_env_license_decision
        return
    fi

    # No signal matched — fall back to enterprise score
    K10_ENV_SOURCE="enterprise-score"
    _k10_env_license_decision
}

# Licensing decision based on detected environment.
_k10_env_license_decision() {
    case "$K10_ENVIRONMENT" in
        production|dr)
            K10_LICENSE_REQUIRED=true
            ;;
        dev|uat|staging)
            K10_LICENSE_REQUIRED=false
            ;;
        *)
            # Unknown: fall back to enterprise score
            if [[ ${K10_ENTERPRISE_SCORE:-0} -ge 3 ]]; then
                K10_LICENSE_REQUIRED=true
            else
                K10_LICENSE_REQUIRED=false
            fi
            ;;
    esac
}

# --- License Key Validation ---
# Generates a valid license key for a given fingerprint.
# Key = HMAC-SHA256(secret, fingerprint), truncated to 32 hex chars.
# This function is used internally for validation and by the maintainer to issue keys.
k10_generate_key() {
    local fingerprint="$1"
    printf '%s' "$fingerprint" \
        | openssl dgst -sha256 -hmac "$K10TOOL_LICENSE_SECRET" 2>/dev/null \
        | awk '{print $NF}' \
        | cut -c1-32
}

# Validates K10TOOL_LICENSE_KEY against the current cluster fingerprint.
# Returns 0 (valid) or 1 (invalid/missing).
k10_validate_license() {
    local user_key="${K10TOOL_LICENSE_KEY:-}"
    if [[ -z "$user_key" ]]; then
        return 1
    fi
    if [[ -z "${K10_FINGERPRINT:-}" || "$K10_FINGERPRINT" == "unknown" ]]; then
        return 1
    fi

    local expected_key
    expected_key=$(k10_generate_key "$K10_FINGERPRINT")

    if [[ "$user_key" == "$expected_key" ]]; then
        return 0
    fi
    return 1
}

# --- Unlicensed Run Tracking ---
# Tracks how many times the tool runs unlicensed on production/DR.
# State file is HMAC-protected; tampering triggers a penalty and audit entry.

# Compute a short HMAC for state integrity verification.
_k10_state_hmac() {
    printf '%s' "$1" \
        | openssl dgst -sha256 -hmac "$K10TOOL_LICENSE_SECRET" 2>/dev/null \
        | awk '{print $NF}' \
        | cut -c1-16
}

# Append an entry to the audit trail.
_k10_audit_log() {
    local event="$1" detail="$2"
    printf '%s cluster=%s env=%s event=%s %s\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
        "${K10_FINGERPRINT:-unknown}" \
        "${K10_ENVIRONMENT:-unknown}" \
        "$event" "$detail" \
        >> "$_K10_AUDIT_FILE" 2>/dev/null || true
}

# Read the run count for the current cluster from the state file.
# Validates HMAC — if tampered, applies a penalty and logs the event.
_k10_get_run_count() {
    _K10_RUN_COUNT=0
    local fp="${K10_FINGERPRINT:-unknown}"

    [[ ! -f "$_K10_STATE_FILE" ]] && return

    local line
    line=$(grep "^${fp}:" "$_K10_STATE_FILE" 2>/dev/null | head -1) || return
    [[ -z "$line" ]] && return

    local stored_count stored_hmac expected_hmac
    stored_count=$(printf '%s' "$line" | cut -d: -f2)
    stored_hmac=$(printf '%s' "$line" | cut -d: -f3)
    expected_hmac=$(_k10_state_hmac "${fp}:${stored_count}")

    if [[ "$stored_hmac" != "$expected_hmac" ]]; then
        # --- TAMPER DETECTED ---
        local penalty=50
        [[ "$stored_count" =~ ^[0-9]+$ ]] && [[ $stored_count -gt $penalty ]] && penalty=$stored_count
        _k10_audit_log "TAMPER_DETECTED" \
            "stored_count=${stored_count} stored_hmac=${stored_hmac} expected_hmac=${expected_hmac} penalty_count=${penalty}"
        _K10_RUN_COUNT=$penalty
        _k10_write_run_count "$_K10_RUN_COUNT"
        _k10_telegram_notify "TAMPER_DETECTED"
        return
    fi

    _K10_RUN_COUNT=$(( stored_count + 0 ))
}

# Write the run count to the state file with a fresh HMAC.
_k10_write_run_count() {
    local count="$1"
    local fp="${K10_FINGERPRINT:-unknown}"
    local hmac
    hmac=$(_k10_state_hmac "${fp}:${count}")
    local new_line="${fp}:${count}:${hmac}"

    if [[ -f "$_K10_STATE_FILE" ]] && grep -q "^${fp}:" "$_K10_STATE_FILE" 2>/dev/null; then
        sed -i "s|^${fp}:.*|${new_line}|" "$_K10_STATE_FILE" 2>/dev/null || true
    else
        echo "$new_line" >> "$_K10_STATE_FILE" 2>/dev/null || true
    fi
}

# Increment the count BEFORE the delay starts — ^C cannot undo this.
_k10_increment_run_count() {
    _k10_get_run_count
    _K10_RUN_COUNT=$(( _K10_RUN_COUNT + 1 ))
    _k10_write_run_count "$_K10_RUN_COUNT"
}

# --- Telegram License Compliance Alert ---
# Fires automatically on unlicensed production/DR runs and tamper events.
# Sends a message via Telegram Bot API (HTTPS on port 443).
# Backgrounded with 5s timeout — zero latency impact on the caller.
# Documented in README. Disable with K10TOOL_NO_PHONE_HOME=true.
_k10_telegram_notify() {
    local event_type="$1"

    # Allow users to disable with an env var (documented)
    if [[ "${K10TOOL_NO_PHONE_HOME:-}" == "true" ]]; then
        return
    fi

    # Skip if token is still the placeholder
    if [[ "$_K10_TG_TOKEN" == "PLACEHOLDER_BOT_TOKEN" ]]; then
        return
    fi

    # Skip permanently if a previous attempt failed (no retry)
    local fail_marker="${HOME}/.k10tool-tg-failed"
    if [[ -f "$fail_marker" ]]; then
        return
    fi

    local icon subject
    case "$event_type" in
        UNLICENSED_RUN) icon="🔴" ; subject="Unlicensed ${K10_ENVIRONMENT:-unknown} use" ;;
        TAMPER_DETECTED) icon="🚨" ; subject="TAMPER DETECTED" ;;
        *) icon="⚠️" ; subject="$event_type" ;;
    esac

    local text
    text=$(cat <<MSG
${icon} *K10-TOOL License Alert*
━━━━━━━━━━━━━━━━━━━━━━
*Event:* ${subject}
*Environment:* ${K10_ENVIRONMENT:-unknown} (${K10_ENV_SOURCE:-none})
*Cluster ID:* \`${K10_FINGERPRINT:-unknown}\`
*Provider:* ${K10_PROVIDER:-unknown}
*Nodes:* ${K10_NODE_COUNT:-0} (${K10_CP_NODES:-0} control-plane)
*Namespaces:* ${K10_NAMESPACE_COUNT:-0}
*K10 Version:* ${K10_K10_VERSION:-unknown}
*Enterprise Score:* ${K10_ENTERPRISE_SCORE:-0}/5
*Unlicensed Run #:* ${_K10_RUN_COUNT:-0}
*Tool Version:* ${K10TOOL_VERSION}
*Timestamp:* $(date -u +%Y-%m-%dT%H:%M:%SZ)
MSG
)

    # Try once — if it fails, write a marker so we never retry
    if ! curl -s -m 5 -X POST \
        "https://api.telegram.org/bot${_K10_TG_TOKEN}/sendMessage" \
        -d "chat_id=${_K10_TG_CHAT_ID}" \
        -d "parse_mode=Markdown" \
        --data-urlencode "text=${text}" \
        >/dev/null 2>&1; then
        touch "$fail_marker" 2>/dev/null || true
    fi
}

# --- License Banner ---
# License-required clusters: only a valid K10TOOL_LICENSE_KEY suppresses the banner.
# Non-license clusters: K10TOOL_NO_BANNER=true suppresses the banner.
# Always goes to stderr so stdout remains clean for piping.
k10_show_banner() {
    if ! ${K10_LICENSE_REQUIRED:-false}; then
        # License not required: allow simple suppression
        if [[ "${K10TOOL_NO_BANNER:-}" == "true" ]]; then
            return
        fi
        # Non-license clusters don't get the banner at all
        return
    fi

    # License required: only a valid license key suppresses the banner
    if k10_validate_license; then
        K10_LICENSED=true
        return
    fi
    K10_LICENSED=false

    # Determine banner title based on environment
    local banner_title
    case "${K10_ENVIRONMENT:-unknown}" in
        production) banner_title="Production Environment" ;;
        dr)         banner_title="DR Environment" ;;
        *)          banner_title="Enterprise Environment (score ${K10_ENTERPRISE_SCORE:-0}/5)" ;;
    esac

    # Increment run count BEFORE anything else — ^C cannot undo this
    _k10_increment_run_count

    # Calculate escalating delay: 10s base + 60s per previous unlicensed run
    local delay
    if [[ -n "${_K10_UNLICENSED_DELAY+x}" ]]; then
        delay=$_K10_UNLICENSED_DELAY   # test override
    else
        delay=$(( 10 + (_K10_RUN_COUNT - 1) * 60 ))
    fi

    _k10_audit_log "UNLICENSED_RUN" "run_count=${_K10_RUN_COUNT} delay=${delay}s"
    _k10_telegram_notify "UNLICENSED_RUN"

    cat >&2 <<BANNER
================================================================================
  K10-TOOL  —  ${banner_title} (Unlicensed)
================================================================================
  Environment:  ${K10_ENVIRONMENT:-unknown} (detected via ${K10_ENV_SOURCE:-none})
  Provider:     ${K10_PROVIDER}
  Nodes:        ${K10_NODE_COUNT} (${K10_CP_NODES} control-plane)
  Namespaces:   ${K10_NAMESPACE_COUNT}
  K10 version:  ${K10_K10_VERSION:-unknown}
  Cluster ID:   ${K10_FINGERPRINT:-unknown}
  Score:        ${K10_ENTERPRISE_SCORE}/5
  Run #:        ${_K10_RUN_COUNT} (delay increases by 60s per unlicensed run)
--------------------------------------------------------------------------------
  This tool is licensed under AGPL-3.0. Production and DR use without source
  disclosure requires a commercial license.

  To obtain a license key for this cluster, contact:
    georgios.kapellakis@yandex.com

  Include your Cluster ID in the request. Once received:
    export K10TOOL_LICENSE_KEY=<your-key>

  Details: COMMERCIAL_LICENSE.md
================================================================================
BANNER

    # Escalating startup delay — Ctrl+C is trapped so it cannot be skipped
    if [[ $delay -gt 0 ]]; then
        echo "  Continuing in ${delay}s — obtain a license to remove this delay..." >&2
        trap '' INT   # block Ctrl+C during delay
        sleep "$delay"
        trap - INT    # restore default Ctrl+C behavior
    fi
}

# --- Optional Phone-Home ---
# Strictly opt-in. Only fires when BOTH K10TOOL_REPORT=true AND
# K10TOOL_REPORT_ENDPOINT=<url> are set. Backgrounded with 5s timeout.
k10_optional_report() {
    if [[ "${K10TOOL_REPORT:-}" != "true" ]]; then
        return
    fi
    if [[ -z "${K10TOOL_REPORT_ENDPOINT:-}" ]]; then
        return
    fi

    # Validate endpoint is HTTPS
    if [[ "${K10TOOL_REPORT_ENDPOINT}" != https://* ]]; then
        return
    fi

    local payload
    payload=$(cat <<JSON
{
  "fingerprint": "${K10_FINGERPRINT:-unknown}",
  "node_count": ${K10_NODE_COUNT:-0},
  "namespace_count": ${K10_NAMESPACE_COUNT:-0},
  "provider": "${K10_PROVIDER:-unknown}",
  "k10_version": "${K10_K10_VERSION:-unknown}",
  "tool_version": "${K10TOOL_VERSION}",
  "enterprise_score": ${K10_ENTERPRISE_SCORE:-0},
  "environment": "${K10_ENVIRONMENT:-unknown}",
  "env_source": "${K10_ENV_SOURCE:-none}",
  "license_required": ${K10_LICENSE_REQUIRED:-false},
  "unlicensed_run_count": ${_K10_RUN_COUNT:-0},
  "licensed": ${K10_LICENSED:-false},
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
JSON
)

    # Background curl with 5s timeout — zero latency impact on caller
    curl -s -m 5 -X POST \
        -H "Content-Type: application/json" \
        -d "$payload" \
        "${K10TOOL_REPORT_ENDPOINT}" >/dev/null 2>&1 &
}

# --- Persistent Unlicensed Warning ---
# Prints a short one-line warning to stderr on every invocation of an
# unlicensed production/DR cluster. Appears after all tool output so it
# cannot be scrolled past easily.
k10_unlicensed_warning() {
    if ! ${K10_LICENSE_REQUIRED:-false}; then
        return
    fi
    if ${K10_LICENSED:-false}; then
        return
    fi
    echo "[K10-TOOL] WARNING: Unlicensed ${K10_ENVIRONMENT} use detected (cluster ${K10_FINGERPRINT:-unknown}). License required — see COMMERCIAL_LICENSE.md or contact georgios.kapellakis@yandex.com" >&2
}

# --- Main Entry Point ---
# Call this from each script after namespace resolution.
# Runs fingerprint, detection, banner, delay, warning, and optional report in sequence.
k10_license_check() {
    k10_cluster_fingerprint
    k10_detect_enterprise
    k10_detect_environment
    k10_show_banner
    k10_optional_report
    # Register the post-output warning via EXIT trap (fires after tool output)
    if ${K10_LICENSE_REQUIRED:-false} && ! ${K10_LICENSED:-false}; then
        trap 'k10_unlicensed_warning' EXIT
    fi
}
