# k10-cleaner — SQLite persistence layer
# Copyright (c) 2026 Georgios Kapellakis
# Licensed under AGPL-3.0 — see LICENSE for details.

from __future__ import annotations

import hashlib
import hmac as _hmac
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

_LICENSE_SECRET = "k10cleaner-agpl3-commercial-2026"

_SCHEMA_VERSION = 1

_SCHEMA_SQL = """\
CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS fingerprints (
    fingerprint TEXT PRIMARY KEY,
    first_seen  TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS run_state (
    fingerprint TEXT PRIMARY KEY,
    run_count   INTEGER NOT NULL DEFAULT 0,
    hmac        TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT,
    cluster     TEXT,
    environment TEXT,
    event       TEXT,
    detail      TEXT
);
CREATE TABLE IF NOT EXISTS telegram_fail (
    id        INTEGER PRIMARY KEY CHECK (id = 1),
    failed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS config (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""

_DEFAULT_CONFIG = {
    "tg_token": "8230606287:AAGoRGV9aS3Ix1kwKX8GPrWl3KJbzzpaV4A",
    "tg_chat_id": "2147049932",
}


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def compute_hmac(secret: str, data: str) -> str:
    """HMAC-SHA256, truncated to 16 hex chars (matches bash openssl output)."""
    return _hmac.new(
        secret.encode(), data.encode(), hashlib.sha256
    ).hexdigest()[:16]


class K10Database:
    def __init__(self, db_path: str | None = None):
        if db_path is None:
            db_path = os.environ.get(
                "K10CLEANER_DB_PATH",
                os.path.join(Path.home(), ".k10cleaner.db"),
            )
        self._path = db_path

        # Secure file creation
        old_umask = os.umask(0o077)
        try:
            self._conn = sqlite3.connect(self._path)
        finally:
            os.umask(old_umask)

        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._init_schema()
        self._seed_config()
        self._migrate_legacy()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------
    def _init_schema(self):
        cur = self._conn.cursor()
        cur.executescript(_SCHEMA_SQL)
        row = cur.execute(
            "SELECT version FROM schema_version LIMIT 1"
        ).fetchone()
        if row is None:
            cur.execute(
                "INSERT INTO schema_version (version) VALUES (?)",
                (_SCHEMA_VERSION,),
            )
        else:
            db_version = row[0]
            if db_version < _SCHEMA_VERSION:
                self._upgrade_schema(cur, db_version)
                cur.execute(
                    "UPDATE schema_version SET version = ?",
                    (_SCHEMA_VERSION,),
                )
        self._conn.commit()

    def _upgrade_schema(self, cur, from_version: int):
        """Run incremental schema migrations. Add new blocks as schema evolves."""
        # Example for future use:
        # if from_version < 2:
        #     cur.execute("ALTER TABLE ...")
        pass

    def _seed_config(self):
        """Insert default config values if they don't already exist."""
        for key, value in _DEFAULT_CONFIG.items():
            self._conn.execute(
                "INSERT OR IGNORE INTO config (key, value) VALUES (?, ?)",
                (key, value),
            )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Config key-value store
    # ------------------------------------------------------------------
    def get_config(self, key: str, default: str = "") -> str:
        row = self._conn.execute(
            "SELECT value FROM config WHERE key = ?", (key,)
        ).fetchone()
        return row[0] if row else default

    def set_config(self, key: str, value: str):
        self._conn.execute(
            "INSERT INTO config (key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )
        self._conn.commit()

    # ------------------------------------------------------------------
    # Legacy migration
    # ------------------------------------------------------------------
    def _migrate_legacy(self):
        home = str(Path.home())
        self._migrate_state_file(os.path.join(home, ".k10cleaner-state"))
        self._migrate_audit_file(os.path.join(home, ".k10cleaner-audit"))
        self._migrate_fingerprint_file(
            os.path.join(home, ".k10cleaner-fingerprint")
        )
        self._migrate_tg_failed(os.path.join(home, ".k10cleaner-tg-failed"))

    def _rename_migrated(self, path: str):
        migrated = path + ".migrated"
        if os.path.isfile(path) and not os.path.exists(migrated):
            try:
                os.rename(path, migrated)
            except OSError:
                pass

    def _migrate_state_file(self, path: str):
        if not os.path.isfile(path):
            return
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(":")
                    if len(parts) < 3:
                        continue
                    fp, count_s, stored_hmac = parts[0], parts[1], parts[2]
                    try:
                        count = int(count_s)
                    except ValueError:
                        continue
                    # Validate legacy HMAC before trusting the count
                    expected_hmac = compute_hmac(_LICENSE_SECRET, f"{fp}:{count}")
                    if not _hmac.compare_digest(stored_hmac, expected_hmac):
                        # Tampered legacy file — apply penalty
                        count = max(50, min(count, 100))
                    new_hmac = compute_hmac(_LICENSE_SECRET, f"{fp}:{count}")
                    self._conn.execute(
                        "INSERT OR IGNORE INTO run_state (fingerprint, run_count, hmac) VALUES (?, ?, ?)",
                        (fp, count, new_hmac),
                    )
            self._conn.commit()
        except OSError:
            pass
        self._rename_migrated(path)

    def _migrate_audit_file(self, path: str):
        if not os.path.isfile(path):
            return
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    # Format: TIMESTAMP cluster=X env=Y event=Z detail...
                    parts = line.split(None, 4)
                    if len(parts) < 4:
                        continue
                    ts = parts[0]
                    cluster = parts[1].split("=", 1)[1] if "=" in parts[1] else ""
                    env = parts[2].split("=", 1)[1] if "=" in parts[2] else ""
                    event = parts[3].split("=", 1)[1] if "=" in parts[3] else ""
                    detail = parts[4] if len(parts) > 4 else ""
                    self._conn.execute(
                        "INSERT INTO audit_log (timestamp, cluster, environment, event, detail) VALUES (?, ?, ?, ?, ?)",
                        (ts, cluster, env, event, detail),
                    )
            self._conn.commit()
        except OSError:
            pass
        self._rename_migrated(path)

    def _migrate_fingerprint_file(self, path: str):
        if not os.path.isfile(path):
            return
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    parts = line.split(None, 1)
                    if len(parts) < 2:
                        continue
                    ts, fp = parts[0], parts[1]
                    self._conn.execute(
                        "INSERT OR IGNORE INTO fingerprints (fingerprint, first_seen) VALUES (?, ?)",
                        (fp, ts),
                    )
            self._conn.commit()
        except OSError:
            pass
        self._rename_migrated(path)

    def _migrate_tg_failed(self, path: str):
        if not os.path.isfile(path):
            return
        try:
            self._conn.execute(
                "INSERT OR IGNORE INTO telegram_fail (id, failed_at) VALUES (1, ?)",
                (_utcnow(),),
            )
            self._conn.commit()
        except sqlite3.IntegrityError:
            pass
        self._rename_migrated(path)

    # ------------------------------------------------------------------
    # Fingerprints
    # ------------------------------------------------------------------
    def record_fingerprint(self, fingerprint: str):
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT OR IGNORE INTO fingerprints (fingerprint, first_seen) VALUES (?, ?)",
                (fingerprint, _utcnow()),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Run count (HMAC-protected)
    # ------------------------------------------------------------------
    def get_run_count(self, fingerprint: str) -> int:
        row = self._conn.execute(
            "SELECT run_count, hmac FROM run_state WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchone()
        if row is None:
            return 0

        stored_count, stored_hmac = row
        expected_hmac = compute_hmac(
            _LICENSE_SECRET, f"{fingerprint}:{stored_count}"
        )

        if not _hmac.compare_digest(stored_hmac, expected_hmac):
            # Tamper detected — penalty capped at 100
            penalty = max(50, min(stored_count, 100))
            self.append_audit(
                fingerprint,
                "unknown",
                "TAMPER_DETECTED",
                f"stored_count={stored_count} stored_hmac={stored_hmac} expected_hmac={expected_hmac} penalty_count={penalty}",
            )
            self.write_run_count(fingerprint, penalty)
            return penalty

        return stored_count

    def write_run_count(self, fingerprint: str, count: int):
        new_hmac = compute_hmac(_LICENSE_SECRET, f"{fingerprint}:{count}")
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            self._conn.execute(
                "INSERT INTO run_state (fingerprint, run_count, hmac) VALUES (?, ?, ?) "
                "ON CONFLICT(fingerprint) DO UPDATE SET run_count=excluded.run_count, hmac=excluded.hmac",
                (fingerprint, count, new_hmac),
            )
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def increment_run_count(self, fingerprint: str) -> int:
        """Atomic increment. Returns the new count."""
        self._conn.execute("BEGIN IMMEDIATE")
        try:
            row = self._conn.execute(
                "SELECT run_count, hmac FROM run_state WHERE fingerprint = ?",
                (fingerprint,),
            ).fetchone()

            if row is None:
                new_count = 1
            else:
                stored_count, stored_hmac = row
                expected = compute_hmac(
                    _LICENSE_SECRET, f"{fingerprint}:{stored_count}"
                )
                if not _hmac.compare_digest(stored_hmac, expected):
                    new_count = max(50, min(stored_count, 100)) + 1
                else:
                    new_count = stored_count + 1

            new_hmac = compute_hmac(
                _LICENSE_SECRET, f"{fingerprint}:{new_count}"
            )
            self._conn.execute(
                "INSERT INTO run_state (fingerprint, run_count, hmac) VALUES (?, ?, ?) "
                "ON CONFLICT(fingerprint) DO UPDATE SET run_count=excluded.run_count, hmac=excluded.hmac",
                (fingerprint, new_count, new_hmac),
            )
            self._conn.commit()
            return new_count
        except Exception:
            self._conn.rollback()
            raise

    # ------------------------------------------------------------------
    # Audit log
    # ------------------------------------------------------------------
    def append_audit(self, cluster: str, environment: str, event: str, detail: str):
        try:
            self._conn.execute("BEGIN IMMEDIATE")
            self._conn.execute(
                "INSERT INTO audit_log (timestamp, cluster, environment, event, detail) VALUES (?, ?, ?, ?, ?)",
                (_utcnow(), cluster, environment, event, detail),
            )
            self._conn.commit()
        except Exception:
            try:
                self._conn.rollback()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Telegram fail marker
    # ------------------------------------------------------------------
    def is_telegram_failed(self) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM telegram_fail WHERE id = 1"
        ).fetchone()
        return row is not None

    def mark_telegram_failed(self):
        try:
            self._conn.execute(
                "INSERT OR IGNORE INTO telegram_fail (id, failed_at) VALUES (1, ?)",
                (_utcnow(),),
            )
            self._conn.commit()
        except Exception:
            pass

    def close(self):
        self._conn.close()
