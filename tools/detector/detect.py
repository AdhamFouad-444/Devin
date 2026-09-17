#!/usr/bin/env python3
"""Falcon Shield detector — sentinel that tails the JSONL event bus and
classifies incidents. See contracts/README.md.

Tails events/requests.jsonl (portal request log) and events/attacks.jsonl
(attacker scenario log), applies heuristics keyed by source IP, and appends
each detection to events/incidents.jsonl twice: status "open", then "triaged"
after lightweight enrichment (geo label). Dedupes (kind, source_ip) within 60s.
Runs forever and prints every incident to stdout — this terminal is part of
the demo. Python 3.11+, stdlib only.
"""

import json
import os
import sys
import time
import urllib.parse
from collections import defaultdict, deque

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
EVENTS_DIR = os.environ.get("FALCON_EVENTS_DIR", os.path.join(REPO_ROOT, "events"))

POLL_INTERVAL = 0.5
DEDUPE_WINDOW = 60.0

BRUTE_FORCE_LIMIT = 5  # failed POST /login (401) per ip within the window
BRUTE_FORCE_WINDOW = 60.0
SCAN_404_LIMIT = 8  # distinct 404 paths per ip within the window
SCAN_404_WINDOW = 60.0
DOS_LIMIT = 25  # requests per ip within the window
DOS_WINDOW = 10.0

SQLI_MARKERS = ("' or", "--", "'1'='1", "union", "sleep(")

# attacks.jsonl scenario -> (kind, severity)
ATTACK_SCENARIO_KINDS = {
    "sqli": ("sqli", "high"),
    "brute": ("brute_force", "med"),
    "brute_force": ("brute_force", "med"),
    "scan": ("scan", "med"),
    "dos": ("dos", "high"),
    "cve": ("cve_probe", "med"),
    "cve_probe": ("cve_probe", "med"),
}


def _prune(dq, ts, window):
    while dq and dq[0] < ts - window:
        dq.popleft()


class Detector:
    def __init__(self, events_dir=EVENTS_DIR):
        self.events_dir = events_dir
        self.requests_path = os.path.join(events_dir, "requests.jsonl")
        self.attacks_path = os.path.join(events_dir, "attacks.jsonl")
        self.incidents_path = os.path.join(events_dir, "incidents.jsonl")
        self.offsets = {}  # path -> byte offset already consumed
        self.buffers = {}  # path -> trailing partial line
        self.req_ts = defaultdict(deque)  # ip -> deque of request timestamps
        self.login_fail_ts = defaultdict(deque)  # ip -> deque of 401 /login timestamps
        self.not_found_paths = defaultdict(dict)  # ip -> {path: last ts}
        self.geo = {}  # ip -> geo label
        self.seen = {}  # (kind, ip) -> ts last emitted
        self._seed_dedupe()

    # ---- event bus I/O ----------------------------------------------------

    def _seed_dedupe(self):
        """Don't re-fire incidents emitted before a restart."""
        for rec in _read_jsonl(self.incidents_path):
            key = (rec.get("kind"), rec.get("source_ip"))
            ts = rec.get("ts")
            if all(key) and isinstance(ts, (int, float)):
                if ts > self.seen.get(key, 0):
                    self.seen[key] = ts

    def _append(self, record):
        os.makedirs(self.events_dir, exist_ok=True)
        with open(self.incidents_path, "a") as f:
            f.write(json.dumps(record) + "\n")

    def _read_new(self, path):
        """Yield decoded records appended since the last call. Tolerates a
        missing file, truncation/rotation, and a trailing partial line."""
        try:
            size = os.path.getsize(path)
        except OSError:
            return
        offset = self.offsets.get(path, 0)
        if offset is None or size < offset:  # truncated or rotated
            offset = 0
        try:
            with open(path, encoding="utf-8", errors="replace") as f:
                f.seek(offset)
                chunk = f.read()
                self.offsets[path] = f.tell()
        except OSError:
            return
        buf = self.buffers.pop(path, "") + chunk
        lines = buf.split("\n")
        self.buffers[path] = lines.pop()  # trailing fragment until its "\n" lands
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue  # skip corrupt lines

    def poll_once(self):
        for path, handler in (
            (self.requests_path, self.handle_request),
            (self.attacks_path, self.handle_attack),
        ):
            for rec in self._read_new(path):
                if isinstance(rec, dict):
                    handler(rec)

    # ---- classification ---------------------------------------------------

    def handle_request(self, rec):
        ip = rec.get("ip")
        if not ip:
            return
        ts = _ts(rec)
        path = rec.get("path") or ""
        query = rec.get("query") or ""
        status = rec.get("status")
        method = (rec.get("method") or "").upper()
        self._note_geo(ip, rec.get("geo"))

        decoded_q = urllib.parse.unquote_plus(query).lower()
        decoded_full = urllib.parse.unquote_plus(f"{path}?{query}").lower()

        # DoS: request rate per ip
        dq = self.req_ts[ip]
        dq.append(ts)
        _prune(dq, ts, DOS_WINDOW)
        if len(dq) >= DOS_LIMIT:
            self.emit(
                "dos", "high", ip, ts,
                f"DoS: {len(dq)} requests from {ip} within {int(DOS_WINDOW)}s",
            )

        # SQLi: marker inside the query of a login request
        if path == "/login" and any(m in decoded_q for m in SQLI_MARKERS):
            snippet = urllib.parse.unquote_plus(query)[:100]
            self.emit("sqli", "high", ip, ts, f"SQLi payload in {path} from {ip}: {snippet}")

        # brute force: repeated failed logins
        if method == "POST" and path == "/login" and status == 401:
            fails = self.login_fail_ts[ip]
            fails.append(ts)
            _prune(fails, ts, BRUTE_FORCE_WINDOW)
            if len(fails) >= BRUTE_FORCE_LIMIT:
                self.emit(
                    "brute_force", "med", ip, ts,
                    f"Brute force: {len(fails)} failed POST /login (401) from {ip} within 60s",
                )

        # scan: many distinct 404s, or a hit on the debug endpoint
        if status == 404:
            paths = self.not_found_paths[ip]
            paths[path] = ts
            for p, t in list(paths.items()):
                if t < ts - SCAN_404_WINDOW:
                    del paths[p]
            if len(paths) >= SCAN_404_LIMIT:
                self.emit(
                    "scan", "med", ip, ts,
                    f"Scan: {len(paths)} distinct 404 paths from {ip} within 60s (e.g. {path})",
                )
        if path == "/debug/config":
            self.emit("scan", "med", ip, ts, f"Debug endpoint probe {path} from {ip}")

        # cve_probe: path traversal on /files, or /etc/passwd anywhere
        if (path == "/files" and ".." in decoded_q) or "/etc/passwd" in decoded_full:
            self.emit(
                "cve_probe", "med", ip, ts,
                f"Path-traversal probe {path}?{query} from {ip}",
            )

    def handle_attack(self, rec):
        ts = _ts(rec)
        scenario = (rec.get("scenario") or "").lower()
        source = rec.get("source") or {}
        ip = source.get("ip") or "unknown"
        self._note_geo(ip, source.get("geo"))
        kind, severity = ATTACK_SCENARIO_KINDS.get(scenario, ("anomaly", "med"))
        target = rec.get("target_path") or "?"
        result = rec.get("result") or ""
        self.emit(
            kind, severity, ip, ts,
            f"Attack scenario '{scenario}' from {ip} targeting {target} ({result})",
        )

    # ---- emission ----------------------------------------------------------

    def emit(self, kind, severity, ip, ts, evidence):
        """Dedupe then append open + triaged incident lines; returns the
        incident dict, or None when suppressed."""
        key = (kind, ip)
        if ts - self.seen.get(key, ts - DEDUPE_WINDOW - 1) < DEDUPE_WINDOW:
            return None
        self.seen[key] = ts
        incident = {
            "ts": round(ts, 3),
            "id": f"INC-{int(ts)}-{kind}",
            "kind": kind,
            "severity": severity,
            "status": "open",
            "evidence": evidence,
            "source_ip": ip,
            "session_url": None,
            "pr_url": None,
        }
        self._append(incident)
        geo = self.geo.get(ip)
        print(
            f"[{incident['id']}] {severity.upper():4} {kind:<12} {ip}"
            f"{f' ({geo})' if geo else ''} — {evidence}",
            flush=True,
        )
        triaged = dict(incident)
        triaged["status"] = "triaged"
        triaged["ts"] = round(time.time(), 3)
        self._append(triaged)
        return incident

    def _note_geo(self, ip, geo):
        if isinstance(geo, (list, tuple)) and len(geo) >= 3:
            self.geo[ip] = geo[2]


def _ts(rec):
    try:
        return float(rec.get("ts"))
    except (TypeError, ValueError):
        return time.time()


def _read_jsonl(path):
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
    except OSError:
        return


def main():
    os.makedirs(EVENTS_DIR, exist_ok=True)
    det = Detector(EVENTS_DIR)
    print(
        f"[detector] falcon-shield sentinel up — tailing {EVENTS_DIR} "
        f"every {POLL_INTERVAL}s",
        flush=True,
    )
    try:
        while True:
            det.poll_once()
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print("\n[detector] stopped", flush=True)


if __name__ == "__main__":
    sys.exit(main())
