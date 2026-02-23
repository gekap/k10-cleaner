# K10-tool

A smart stuck-action detection and cancellation tool for [Veeam Kasten K10](https://www.kasten.io/) backup environments.

K10 actions (backups, exports, restores) can get stuck in `Pending`, `Running`, or `AttemptFailed` states indefinitely. This tool identifies genuinely stuck actions using multi-signal detection and safely cancels them — without killing legitimate long-running operations.

## Features

### Smart Stuck Detection

Unlike blindly cancelling all non-complete actions, K10-tool uses three layers of detection:

| Signal | Condition | Applies to |
|--------|-----------|------------|
| **Age threshold** | Action older than `--max-age` (default 24h) | All actions (required gate) |
| **No progress** | `progress` field is `0` after threshold | All action types |
| **Error present** | `status.error.message` is non-empty | All action types |
| **Pending forever** | State is `Pending` (never started) | All actions |
| **AttemptFailed** | Stuck in retry loop | All actions |

`Running` actions older than the threshold are only cancelled if they **also** show no progress or have an error — protecting healthy long-running operations.

### Policy Status Dashboard (`--check`)

A read-only overview of all K10 policies and their current state, similar to the K10 UI dashboard:

```
$ ./k10-cancel-stuck-actions.sh --check

=== K10 Policy Status Dashboard ===

NAME                         NAMESPACE            ACTION                 LAST RUN                     STATUS
--------------------------------------------------------------------------------------------------------------------
notes-app-backup             notes-app            Snapshot + Export      Sat Feb 21 2026 12:38 PM     Running
  [OK   ] RunAction            policy-run-xxxxx                         age=0h    Running progress=—  policy=notes-app-backup
  [OK   ] BackupAction         scheduled-xxxxx                          age=0h    Running progress=—  policy=notes-app-backup
  [OK   ] ExportAction         policy-run-xxxxx                         age=0h    Running progress=5% policy=notes-app-backup
crypto-analyzer-backup       crypto-analyzer      Snapshot + Export      Sat Feb 21 2026 10:13 AM     Skipped

=== Summary ===
Policies: 9 (7 complete, not shown)
  Failed:    0
  Skipped:   1
  Running:   1
  Stuck:     0
  Never run: 0
```

- Shows policy names, target namespaces, action types, last run time, and status
- Completed policies are hidden (count shown in summary) — use `--show-recent-completed` to view them
- Active actions are expanded underneath each running policy with health labels (`OK`, `OLD`, `STUCK`)
- Searches both `kasten-io` and application namespaces for actions

### Recently Completed Policies (`--show-recent-completed`)

A standalone view of policies whose most recent action completed successfully:

```
$ ./k10-cancel-stuck-actions.sh --show-recent-completed

=== Recently Completed K10 Policies ===

NAME                         NAMESPACE            ACTION                 COMPLETED AT
--------------------------------------------------------------------------------------------
notes-app-backup             notes-app            Snapshot               Sat Feb 21 2026 12:45 PM
crypto-analyzer-backup       crypto-analyzer      Export                 Sat Feb 21 2026 10:20 AM

2 completed policies.
```

- Shows policy name, target namespace, last action type, and completion time
- Complements `--check`, which hides completed policies behind a summary count

### Safe Cancellation

```
$ ./k10-cancel-stuck-actions.sh --dry-run --max-age 48h

[DRY RUN] No changes will be made.
Stuck detection: actions older than 48h

STUCK: BackupAction scheduled-abc123 [Running] policy=myapp-backup — age 72h — no progress (progress=0 after 72h)
  -> Would attempt cancel, then delete if cancel fails

=== Summary ===
Found:     3 actions in target states (Pending/Running/AttemptFailed)
Skipped:   2 (too young or Running without stuck signals)
Stuck:     1 actions identified as stuck
```

- Attempts K10 `CancelAction` first (graceful cancellation)
- Falls back to direct deletion for `Pending` actions that can't be cancelled
- Re-checks action state before cancelling (handles race conditions)
- Validates resource names before YAML interpolation

## Usage

```
./k10-cancel-stuck-actions.sh [--dry-run] [--max-age <duration>] [--check] [--show-recent-completed]
```

| Flag | Description |
|------|-------------|
| `--check` / `--monitor` | Status dashboard — show all policies and active actions, then exit |
| `--show-recent-completed` | Show recently completed policies with completion time, then exit |
| `--dry-run` | Show what would be cancelled without making changes |
| `--max-age <dur>` | Only target actions older than this (default: `24h`, minimum: `1h`). Supports `h` (hours) and `d` (days): `12h`, `24h`, `2d`, `72h` |
| `-h` / `--help` | Show usage |

### Examples

```bash
# Check current policy status (read-only)
./k10-cancel-stuck-actions.sh --check

# View recently completed policies
./k10-cancel-stuck-actions.sh --show-recent-completed

# Preview what would be cancelled (default: actions older than 24h)
./k10-cancel-stuck-actions.sh --dry-run

# Preview with custom threshold
./k10-cancel-stuck-actions.sh --dry-run --max-age 48h

# Cancel stuck actions older than 2 days
./k10-cancel-stuck-actions.sh --max-age 2d
```

## Requirements

- `kubectl` configured with access to the K10 namespace (`kasten-io`)
- `jq` for JSON parsing
- `bash` 4.0+ (associative arrays)
- Veeam Kasten K10 installed on the target cluster

## How It Works

1. Scans all 12 K10 action types across `kasten-io` and application namespaces
2. For each action in `Pending`, `Running`, or `AttemptFailed` state:
   - Computes age from `status.startTime` (Running) or `metadata.creationTimestamp` (fallback)
   - Skips actions younger than `--max-age`
   - For `Running` actions, requires an additional stuck signal (no progress or error present)
   - `Pending` and `AttemptFailed` actions older than the threshold are always considered stuck
3. Cancels via K10 `CancelAction` CRD (graceful), falls back to `kubectl delete` if CancelAction fails
4. Cancelling a `RunAction` cascades to cancel all child actions (BackupAction, ExportAction, etc.)

## License Compliance System

The tool includes a **two-tier licensing model** powered by `k10-lib.sh`. It is **free on dev, UAT, and staging** clusters but **requires a license on production and DR** environments. This system is **non-blocking** — it never prevents the tool from running, but production/DR clusters will see a persistent license banner on every run until a valid key is provided.

### How It Works

On startup, the script:

1. **Generates a cluster fingerprint** — SHA256 hash of the `kube-system` namespace UID, truncated to 16 characters. Anonymous and deterministic (same cluster always produces the same ID). Logged to `~/.k10tool-fingerprint`.

2. **Detects environment type** by checking cluster naming signals (first match wins):

| Priority | Signal | Source | API Call? |
|----------|--------|--------|-----------|
| 1 | `kubectl config current-context` | Context name | No |
| 2 | Cluster name from kubeconfig | `kubectl config view --minify` | No |
| 3 | Namespace labels (`env=` / `environment=`) | Namespace metadata | Yes |
| 4 | Node labels (`env=` / `environment=`) | Node metadata | Yes |
| 5 | Server URL hostname | Kubeconfig | No |

   Each signal is matched against word-boundary patterns for known environments:

   - **production**: `prod`, `prd`, `production`, `live`
   - **dr**: `dr`, `disaster-recovery`, `failover`, `standby`
   - **uat**: `uat`, `acceptance`, `pre-prod`, `preprod`
   - **staging**: `staging`, `stg`, `stage`
   - **dev**: `dev`, `develop`, `development`, `sandbox`, `test`, `testing`, `lab`, `local`, `minikube`, `kind`, `k3s`, `docker-desktop`

   You can override detection by setting `K10TOOL_ENVIRONMENT` (e.g., `export K10TOOL_ENVIRONMENT=dev`).

3. **Determines license requirement** based on detected environment:

   - **production** or **dr** → license required
   - **dev**, **uat**, or **staging** → free, no license needed
   - **unknown** (no signal matched) → falls back to enterprise scoring (score >= 3 = license required)

4. **Enterprise scoring** (0-5 points, used as fallback for unknown environments):

| Signal | Points | Detection Method |
|--------|--------|-----------------|
| Node count > 3 | +1 | `kubectl get nodes` |
| Managed K8s (EKS/AKS/GKE/OpenShift) | +1 | Node labels + server version |
| Namespace count > 10 | +1 | `kubectl get namespaces` |
| HA control plane (>1 control-plane node) | +1 | Node labels + apiserver pod count |
| Paid K10 license (>5 nodes + license present) | +1 | K10 configmap/secret |

5. **License key validation** — on license-required clusters, the banner **cannot be suppressed** without a valid license key tied to the cluster fingerprint. `K10TOOL_NO_BANNER=true` is ignored on license-required clusters.

6. **Optional telemetry** — only when explicitly opted in via environment variables.

### Obtaining a License Key

Production and DR users will see a banner like this on every run:

```
================================================================================
  K10-TOOL  —  Production Environment (Unlicensed)
================================================================================
  Environment:  production (detected via context:prod-eks-cluster)
  Cluster ID:   a1b2c3d4e5f67890
  ...
  To obtain a license key for this cluster, contact:
    georgios.kapellakis@yandex.com

  Include your Cluster ID in the request. Once received:
    export K10TOOL_LICENSE_KEY=<your-key>
================================================================================
```

Each license key is unique to a cluster fingerprint and cannot be reused across clusters.

### Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `K10TOOL_LICENSE_KEY` | unset | License key for this cluster (suppresses banner on production/DR clusters) |
| `K10TOOL_ENVIRONMENT` | unset | Override auto-detected environment (`production`, `dr`, `uat`, `staging`, `dev`) |
| `K10TOOL_NO_BANNER` | unset | Set to `true` to suppress the banner (only works on non-license-required clusters) |
| `K10TOOL_NO_PHONE_HOME` | unset | Set to `true` to disable automatic license compliance telemetry and notifications |
| `K10TOOL_FINGERPRINT_FILE` | `~/.k10tool-fingerprint` | Custom path for the fingerprint log file |

### License Compliance Telemetry

Unlicensed production and DR runs automatically send license compliance data to the project maintainer. This includes:

1. **Telemetry report** — JSON POST to `https://k10-monitor.togioma.gr/api/v1/telemetry`
2. **Telegram notification** — instant alert to the maintainer

**Data transmitted:**

| Field | Description | Example |
|-------|-------------|---------|
| `fingerprint` | Anonymous cluster hash (SHA256 of kube-system UID) | `9f997317edb46fb6` |
| `environment` | Detected environment type | `production` |
| `env_source` | How the environment was detected | `context:prod-eks-eu` |
| `server_url` | Kubernetes API server URL (from local kubeconfig) | `https://k8s.example.com:6443` |
| `provider` | Cloud provider | `EKS` |
| `node_count` | Number of cluster nodes | `8` |
| `cp_nodes` | Number of control-plane nodes | `3` |
| `namespace_count` | Number of namespaces | `25` |
| `k10_version` | Installed K10 version | `7.0.5` |
| `enterprise_score` | Enterprise detection score (0-5) | `4` |
| `license_key_provided` | Whether a license key was set | `true` / `false` |
| `license_key_valid` | Whether the provided key is valid | `true` / `false` |
| `unlicensed_run_count` | Number of unlicensed runs on this cluster | `3` |
| `tool_version` | K10-tool version | `1.0.0` |
| `timestamp` | UTC timestamp | `2026-02-23T15:30:00Z` |

The receiving server also captures the **source IP address** from the HTTP request.

**When it fires:**
- Every unlicensed run on a production or DR cluster
- When tamper detection is triggered (Telegram only)

**When it does NOT fire:**
- Dev, UAT, or staging environments (license not required)
- Licensed production/DR clusters (valid `K10TOOL_LICENSE_KEY`)
- When `K10TOOL_NO_PHONE_HOME=true` is set
- After the first failed attempt (network unreachable) — never retries

Both channels use HTTPS (port 443) with a 5-second timeout. If the first attempt fails (e.g., firewall blocks outbound HTTPS), a marker file is written and no further attempts are made. This is fully documented here and visible in the source code (`k10-lib.sh`).

### Escalating Delay

Unlicensed production/DR runs incur a startup delay that increases with each run:

| Run # | Delay | Formula |
|-------|-------|---------|
| 1 | 10s | `10 + (1-1) × 60` |
| 2 | 70s | `10 + (2-1) × 60` |
| 3 | 130s | `10 + (3-1) × 60` |
| N | ... | `10 + (N-1) × 60` |

- Ctrl+C is blocked during the delay
- The run counter is HMAC-protected — editing the state file (`~/.k10tool-state`) triggers tamper detection, sets the counter to 50 (penalty), and sends an alert
- All events are logged to `~/.k10tool-audit`

### Graceful Degradation

- All kubectl calls are guarded — detection failures produce defaults, never crash the tool
- `k10-lib.sh` is required — the tool will not run if it is missing or modified
- The banner never appears when `--help` is used (exits before compliance check)
- Environment detection adds minimal overhead (first two signals are local, no API calls)
- Telemetry uses try-once semantics — if the network blocks it, it never retries

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see [LICENSE](LICENSE) for details.

This means you are free to use, modify, and distribute this tool, but **any modifications or derivative works must also be released under AGPL-3.0**, including when used to provide a network service.

This tool is provided **as-is, without warranty of any kind**. Use at your own risk. Always test with `--dry-run` first.

### Commercial License

If your organization requires a **proprietary/commercial license** (without AGPL copyleft obligations), enterprise support, custom integrations, or SLA-backed maintenance, see [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md) or contact: **georgios.kapellakis@yandex.com**
