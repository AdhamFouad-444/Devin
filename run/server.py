#!/usr/bin/env python3
"""Falcon Shield demo server — static files + drive-the-demo API on :8080.

Serves the repo over HTTP (dashboard at /apps/mission-control/, pitch at
/docs/pitch.html, event bus at /events/*.jsonl) and adds:

  POST /api/attack   {"scenario": "sqli"}  — fire an attack scenario (rotates if omitted)
  POST /api/decision — proxied to the voice service on :8020 (remote approve/deny)
  POST /api/reset    — wipe events/*.jsonl for a clean board

Stdlib only. All attack traffic targets our own sandbox portal — simulation only.
"""
import glob
import json
import os
import subprocess
import sys
import threading
import urllib.request
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8080
VOICE = "http://localhost:8020"
SCENARIOS = ["sqli", "dos", "scan", "brute", "cve"]
_next = {"i": 0}


def run_attack(scenario):
    try:
        subprocess.run([sys.executable, "tools/attacker/attack.py", "--scenario", scenario],
                       cwd=ROOT, timeout=120)
    except Exception as e:
        print(f"[api] attack {scenario} failed: {e}", flush=True)


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=ROOT, **kw)

    def log_message(self, fmt, *args):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    EVENT_FILES = ["attacks", "incidents", "agents", "approval_requests",
                   "approval_decisions", "call"]

    def do_GET(self):
        # single-request event bundle — keeps remote/tunnel polling cheap
        if self.path.split("?")[0] == "/api/events":
            out = {}
            for name in self.EVENT_FILES:
                lines = []
                try:
                    with open(os.path.join(ROOT, "events", name + ".jsonl")) as f:
                        for l in f:
                            l = l.strip()
                            if l:
                                try:
                                    lines.append(json.loads(l))
                                except Exception:
                                    pass
                except OSError:
                    pass
                out[name] = lines
            return self._json(200, out)
        return super().do_GET()

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "POST, GET")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:
            body = json.loads(raw)
        except Exception:
            body = {}

        if self.path == "/api/attack":
            scenario = body.get("scenario")
            if not scenario:
                scenario = SCENARIOS[_next["i"] % len(SCENARIOS)]
                _next["i"] += 1
            if scenario not in SCENARIOS:
                return self._json(400, {"ok": False, "error": "unknown scenario"})
            threading.Thread(target=run_attack, args=(scenario,), daemon=True).start()
            print(f"[api] attack fired: {scenario}", flush=True)
            return self._json(200, {"ok": True, "scenario": scenario})

        if self.path == "/api/decision":
            try:
                req = urllib.request.Request(
                    VOICE + "/decision", data=raw,
                    headers={"Content-Type": "application/json"}, method="POST")
                with urllib.request.urlopen(req, timeout=10) as r:
                    return self._json(r.status, json.loads(r.read()))
            except Exception as e:
                return self._json(502, {"ok": False, "error": str(e)})

        if self.path == "/api/reset":
            removed = 0
            for f in glob.glob(os.path.join(ROOT, "events", "*.jsonl")):
                try:
                    os.remove(f); removed += 1
                except OSError:
                    pass
            print(f"[api] reset — removed {removed} event files", flush=True)
            return self._json(200, {"ok": True, "removed": removed})

        return self._json(404, {"ok": False, "error": "no such endpoint"})


if __name__ == "__main__":
    print(f"[falcon] serving {ROOT} on :{PORT}", flush=True)
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
