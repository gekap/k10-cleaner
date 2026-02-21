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
- Completed policies are hidden (count shown in summary)
- Active actions are expanded underneath each running policy with health labels (`OK`, `OLD`, `STUCK`)
- Searches both `kasten-io` and application namespaces for actions

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
./k10-cancel-stuck-actions.sh [--dry-run] [--max-age <duration>] [--check]
```

| Flag | Description |
|------|-------------|
| `--check` / `--monitor` | Status dashboard — show all policies and active actions, then exit |
| `--dry-run` | Show what would be cancelled without making changes |
| `--max-age <dur>` | Only target actions older than this (default: `24h`, minimum: `1h`). Supports `h` (hours) and `d` (days): `12h`, `24h`, `2d`, `72h` |
| `-h` / `--help` | Show usage |

### Examples

```bash
# Check current policy status (read-only)
./k10-cancel-stuck-actions.sh --check

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

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)** — see [LICENSE](LICENSE) for details.

This means you are free to use, modify, and distribute this tool, but **any modifications or derivative works must also be released under AGPL-3.0**, including when used to provide a network service.

This tool is provided **as-is, without warranty of any kind**. Use at your own risk. Always test with `--dry-run` first.

### Commercial License

If your organization requires a **proprietary/commercial license** (without AGPL copyleft obligations), enterprise support, custom integrations, or SLA-backed maintenance, contact: **georgios.kapellakis@yandex.com**
