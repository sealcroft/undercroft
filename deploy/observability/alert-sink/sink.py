#!/usr/bin/env python3
"""Minimal Alertmanager webhook receiver for the Undercroft demo stack.

Listens on :9094 and logs a readable one-line summary of every alert
Alertmanager delivers, so the full path — Prometheus rule fires → Alertmanager
routes → receiver gets it — is visible without any external integration.
Swap this for Slack/email/PagerDuty in alertmanager.yml for real use.
"""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


def log(msg):
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):  # health check
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"alert-sink ok\n")

    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        raw = self.rfile.read(n)
        try:
            payload = json.loads(raw)
        except Exception as e:
            log(f"[alert-sink] bad payload: {e}")
            self.send_response(400)
            self.end_headers()
            return
        alerts = payload.get("alerts", [])
        log(f"[alert-sink] === delivery: {len(alerts)} alert(s), "
            f"status={payload.get('status')} ===")
        for a in alerts:
            labels = a.get("labels", {})
            ann = a.get("annotations", {})
            sev = labels.get("severity", "?")
            name = labels.get("alertname", "?")
            surface = labels.get("surface")
            vault = labels.get("vault")
            where = "".join(
                f" {k}={v}" for k, v in (("surface", surface), ("vault", vault)) if v
            )
            log(f"[alert-sink] {a.get('status', '?').upper():8} "
                f"[{sev}] {name}{where} :: {ann.get('summary', '')}")
            if ann.get("runbook_url"):
                log(f"[alert-sink]          runbook: {ann['runbook_url']}")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok\n")

    def log_message(self, *a):  # silence default access logging
        pass


if __name__ == "__main__":
    log("[alert-sink] listening on :9094")
    HTTPServer(("0.0.0.0", 9094), Handler).serve_forever()
