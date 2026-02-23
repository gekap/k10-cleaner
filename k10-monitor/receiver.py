#!/usr/bin/env python3
"""
K10-TOOL License Compliance Receiver

Receives telemetry from unlicensed production/DR k10-tool runs,
logs the payload + source IP, and forwards alerts to Telegram.

Zero external dependencies — uses only Python standard library.

Usage:
    python3 receiver.py                    # default: port 8080
    python3 receiver.py --port 9090        # custom port
    K10_TG_TOKEN=xxx K10_TG_CHAT_ID=yyy python3 receiver.py
"""

import json
import os
import sys
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.request import Request, urlopen
from urllib.parse import urlencode
from datetime import datetime, timezone

# --- Configuration ---
LISTEN_PORT = int(os.environ.get("K10_LISTEN_PORT", "8080"))
LOG_FILE = os.environ.get("K10_LOG_FILE", "/var/log/k10-monitor/telemetry.jsonl")
TG_TOKEN = os.environ.get("K10_TG_TOKEN", "REVOKED_TOKEN")
TG_CHAT_ID = os.environ.get("K10_TG_CHAT_ID", "2147049932")

# --- Logging setup ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("k10-monitor")


def get_source_ip(handler):
    """Extract source IP from X-Forwarded-For (nginx) or direct connection."""
    forwarded = handler.headers.get("X-Forwarded-For", "")
    if forwarded:
        # X-Forwarded-For may contain: client, proxy1, proxy2
        return forwarded.split(",")[0].strip()
    real_ip = handler.headers.get("X-Real-IP", "")
    if real_ip:
        return real_ip.strip()
    return handler.client_address[0]


def log_to_file(entry):
    """Append a JSON line to the log file."""
    try:
        log_dir = os.path.dirname(LOG_FILE)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        with open(LOG_FILE, "a") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        log.error("Failed to write log file: %s", e)


def send_telegram(entry):
    """Send a Telegram alert with the full telemetry + source IP."""
    if not TG_TOKEN or not TG_CHAT_ID:
        return

    event = entry.get("event", "unknown")
    icon = {
        "unlicensed_run": "\U0001f534",       # red circle
        "tamper_detected": "\U0001f6a8",       # siren
    }.get(event, "\u26a0\ufe0f")               # warning

    text = (
        f"{icon} <b>K10-TOOL License Alert</b>\n"
        f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
        f"\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501\u2501"
        f"\u2501\u2501\n"
        f"<b>Event:</b> {event}\n"
        f"<b>Source IP:</b> <code>{entry.get('source_ip', 'unknown')}</code>\n"
        f"<b>Environment:</b> {entry.get('environment', 'unknown')} "
        f"({entry.get('env_source', 'none')})\n"
        f"<b>Server URL:</b> <code>{entry.get('server_url', 'unknown')}</code>\n"
        f"<b>Cluster ID:</b> <code>{entry.get('fingerprint', 'unknown')}</code>\n"
        f"<b>Provider:</b> {entry.get('provider', 'unknown')}\n"
        f"<b>Nodes:</b> {entry.get('node_count', 0)} "
        f"({entry.get('cp_nodes', 0)} control-plane)\n"
        f"<b>Namespaces:</b> {entry.get('namespace_count', 0)}\n"
        f"<b>K10 Version:</b> {entry.get('k10_version', 'unknown')}\n"
        f"<b>Enterprise Score:</b> {entry.get('enterprise_score', 0)}/5\n"
        f"<b>License Key Provided:</b> {entry.get('license_key_provided', False)}\n"
        f"<b>License Key Valid:</b> {entry.get('license_key_valid', False)}\n"
        f"<b>Unlicensed Run #:</b> {entry.get('unlicensed_run_count', 0)}\n"
        f"<b>Tool Version:</b> {entry.get('tool_version', 'unknown')}\n"
        f"<b>Timestamp:</b> {entry.get('timestamp', 'unknown')}"
    )

    try:
        url = f"https://api.telegram.org/bot{TG_TOKEN}/sendMessage"
        data = urlencode({
            "chat_id": TG_CHAT_ID,
            "parse_mode": "HTML",
            "text": text,
        }).encode("utf-8")
        req = Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
        with urlopen(req, timeout=5) as resp:
            if resp.status != 200:
                log.warning("Telegram returned status %d", resp.status)
    except Exception as e:
        log.warning("Telegram send failed: %s", e)


class TelemetryHandler(BaseHTTPRequestHandler):
    """Handle incoming telemetry POST requests."""

    def do_POST(self):
        if self.path != "/api/v1/telemetry":
            self.send_error(404, "Not found")
            return

        # Read body
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0 or content_length > 65536:
            self.send_error(400, "Bad request")
            return

        try:
            body = self.rfile.read(content_length)
            payload = json.loads(body)
        except (json.JSONDecodeError, ValueError):
            self.send_error(400, "Invalid JSON")
            return

        # Enrich with source IP and receive timestamp
        source_ip = get_source_ip(self)
        payload["source_ip"] = source_ip
        payload["received_at"] = datetime.now(timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        # Log
        log.info(
            "TELEMETRY source_ip=%s cluster=%s env=%s run=%s",
            source_ip,
            payload.get("fingerprint", "?"),
            payload.get("environment", "?"),
            payload.get("unlicensed_run_count", "?"),
        )
        log_to_file(payload)

        # Forward to Telegram with source IP included
        send_telegram(payload)

        # Respond
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status":"ok"}\n')

    def do_GET(self):
        """Health check endpoint."""
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"healthy"}\n')
            return
        self.send_error(404, "Not found")

    def log_message(self, format, *args):
        """Suppress default access log — we log via our own logger."""
        pass


def main():
    port = LISTEN_PORT
    if "--port" in sys.argv:
        idx = sys.argv.index("--port")
        if idx + 1 < len(sys.argv):
            port = int(sys.argv[idx + 1])

    server = HTTPServer(("127.0.0.1", port), TelemetryHandler)
    log.info("K10 Monitor listening on 127.0.0.1:%d", port)
    log.info("Log file: %s", LOG_FILE)
    log.info("Telegram: %s", "enabled" if TG_TOKEN else "disabled")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log.info("Shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
