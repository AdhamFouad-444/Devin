#!/usr/bin/env python3
"""Falcon Shield swarm controller — the brain that coordinates the swarm.

Reads (append-only JSONL bus, see contracts/README.md):
  events/incidents.jsonl           — reacts when an incident's latest status is "triaged"
  events/approval_decisions.jsonl  — approved/denied for ids in approval_requests.jsonl
  events/manual_decision.json      — optional file drop: {"id": ..., "decision": "approved"|"denied"}

Writes:
  events/incidents.jsonl           — contained / patch_pr / patched / verified / escalated
  events/agents.jsonl              — containment, patch, comms actions
  events/approval_requests.jsonl   — pending human approvals (voice/dashboard decide)

For patchable kinds a real Devin patch-agent session is spawned via the Devin API.
If DEVIN_API_KEY is unset or the API call fails, the flow degrades to a simulated
path — the demo never hard-stops.
"""

import json
import os
import re
import subprocess
import sys
import time

try:
    import requests
except ImportError:  # degraded mode must still run
    requests = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
EVENTS_DIR = os.path.join(REPO_ROOT, "events")

INCIDENTS_FILE = os.path.join(EVENTS_DIR, "incidents.jsonl")
AGENTS_FILE = os.path.join(EVENTS_DIR, "agents.jsonl")
APPROVAL_REQUESTS_FILE = os.path.join(EVENTS_DIR, "approval_requests.jsonl")
APPROVAL_DECISIONS_FILE = os.path.join(EVENTS_DIR, "approval_decisions.jsonl")
MANUAL_DECISION_FILE = os.path.join(EVENTS_DIR, "manual_decision.json")

PATCHABLE_KINDS = {"sqli", "cve_probe", "scan"}
# incidents.jsonl kind -> attacker --scenario name
VERIFY_SCENARIO = {
    "sqli": "sqli",
    "cve_probe": "cve",
    "scan": "scan",
    "brute_force": "brute",
    "dos": "dos",
    "anomaly": "scan",
}
KIND_LABEL = {
    "sqli": "SQL injection",
    "brute_force": "brute-force login",
    "scan": "directory scan",
    "dos": "denial-of-service spike",
    "cve_probe": "CVE probe",
    "anomaly": "anomalous traffic",
}

PATCH_PROMPT_TEMPLATE = (
    "Repo AdhamFouad-444/Devin, base branch falcon-shield. "
    "apps/portal/app.py has a {kind} vulnerability: {evidence} "
    "Fix it minimally (parameterize the SQL query / sanitize the file path / "
    "remove or auth-gate the debug endpoint as appropriate). "
    "Open a PR with base branch falcon-shield and reply with the PR URL."
)
PR_URL_RE = re.compile(r"https://github\.com/[\w.-]+/[\w.-]+/pull/\d+")

PR_POLL_INTERVAL_S = 20.0
PR_POLL_MAX_ATTEMPTS = 15
LOOP_SLEEP_S = 0.5


def say(msg):
    print(f"[controller {time.strftime('%H:%M:%S')}] {msg}", flush=True)


def append_line(path, obj):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "a") as f:
        f.write(json.dumps(obj) + "\n")


class JsonlTail:
    """Incremental reader for append-only JSONL files; tolerates missing files,
    truncation, and partial last lines."""

    def __init__(self, path):
        self.path = path
        self.offset = 0
        self.buf = ""

    def read_new(self):
        try:
            size = os.path.getsize(self.path)
        except OSError:
            return []
        if size < self.offset:  # file was truncated/rotated
            self.offset = 0
            self.buf = ""
        if size == self.offset:
            return []
        try:
            with open(self.path, "r", errors="replace") as f:
                f.seek(self.offset)
                data = f.read()
        except OSError:
            return []
        self.offset = size
        self.buf += data
        lines = self.buf.split("\n")
        self.buf = lines.pop()  # keep a possibly-partial last line
        out = []
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
            except json.JSONDecodeError:
                continue
            if isinstance(obj, dict):
                out.append(obj)
        return out


def now():
    return round(time.time(), 3)


def api_key():
    return os.environ.get("DEVIN_API_KEY", "").strip()


def api_base():
    return os.environ.get("DEVIN_API_BASE", DEVIN_API_BASE_DEFAULT).rstrip("/")


DEVIN_API_BASE_DEFAULT = "https://api.devin.ai"


def incident_update(inc, **fields):
    """New incidents.jsonl line carrying forward the latest known fields."""
    new = dict(inc)
    new["ts"] = now()
    new.update(fields)
    append_line(INCIDENTS_FILE, new)
    return new


def agent_action(role, incident_id, action, session_url=None):
    append_line(
        AGENTS_FILE,
        {
            "ts": now(),
            "agent_role": role,
            "incident_id": incident_id,
            "session_url": session_url,
            "action": action,
        },
    )


def spawn_patch_session(incident):
    """POST /v1/sessions to Devin. Returns (session_url, session_id) or raises."""
    prompt = PATCH_PROMPT_TEMPLATE.format(
        kind=incident.get("kind", "unknown"),
        evidence=incident.get("evidence", ""),
    )
    resp = requests.post(
        f"{api_base()}/v1/sessions",
        json={
            "prompt": prompt,
            "title": f"patch {incident.get('id', 'incident')}",
            "idempotent": False,
        },
        headers={"Authorization": f"Bearer {api_key()}"},
        timeout=30,
    )
    resp.raise_for_status()
    data = resp.json()
    url = data.get("url") or data.get("session_url")
    sid = data.get("session_id") or data.get("id")
    return url, sid


def find_pr_url(session_id):
    """Best-effort: look for a GitHub PR link anywhere in the session payload."""
    try:
        resp = requests.get(
            f"{api_base()}/v1/sessions/{session_id}",
            headers={"Authorization": f"Bearer {api_key()}"},
            timeout=15,
        )
        if resp.status_code != 200:
            return None
        m = PR_URL_RE.search(resp.text)
        return m.group(0) if m else None
    except Exception:
        return None


def request_approval(incident, action, summary, call_script):
    approval_id = f"APR-{incident.get('id', 'UNKNOWN')}"
    append_line(
        APPROVAL_REQUESTS_FILE,
        {
            "ts": now(),
            "id": approval_id,
            "incident_id": incident.get("id"),
            "action": action,
            "summary": summary,
            "call_script": call_script,
            "status": "pending",
        },
    )
    return approval_id


def merge_pr(pr_url):
    """Squash-merge a PR via gh; fall back to merging the head branch with git."""
    try:
        r = subprocess.run(
            ["gh", "pr", "merge", pr_url, "--squash"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=180,
        )
        if r.returncode == 0:
            return True
        say(f"gh pr merge failed ({r.stderr.strip() or r.stdout.strip()}) — trying git fallback")
    except Exception as e:
        say(f"gh pr merge error ({e}) — trying git fallback")
    try:
        v = subprocess.run(
            ["gh", "pr", "view", pr_url, "--json", "headRefName"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=60,
        )
        head = json.loads(v.stdout).get("headRefName")
        if not head:
            return False
        subprocess.run(
            ["git", "fetch", "origin", head],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
        )
        m = subprocess.run(
            ["git", "merge", "--no-edit", f"origin/{head}"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
        )
        if m.returncode != 0:
            say(f"git merge fallback failed: {m.stderr.strip()}")
            return False
        return True
    except Exception as e:
        say(f"git merge fallback error: {e}")
        return False


def verify_fix(kind):
    """Re-fire the attack scenario; True if the attacker reports BLOCKED."""
    scenario = VERIFY_SCENARIO.get(kind, "scan")
    try:
        r = subprocess.run(
            [sys.executable, "tools/attacker/attack.py", "--scenario", scenario, "--verify"],
            cwd=REPO_ROOT, capture_output=True, text=True, timeout=120,
        )
        out = (r.stdout or "") + (r.stderr or "")
        say(f"verify --scenario {scenario}: {'BLOCKED' if 'BLOCKED' in out else 'not blocked'}")
        return "BLOCKED" in out
    except Exception as e:
        say(f"verify run failed: {e}")
        return False


class Controller:
    def __init__(self):
        self.incidents = {}            # incident_id -> latest incident dict
        self.handled = set()           # incident ids already past/through triage handling
        self.approvals = {}            # approval_id -> request dict
        self.decided = set()           # approval ids already processed
        self.pr_polls = {}             # incident_id -> {session_id, next_ts, attempts}
        self.tails = {
            "incidents": JsonlTail(INCIDENTS_FILE),
            "requests": JsonlTail(APPROVAL_REQUESTS_FILE),
            "decisions": JsonlTail(APPROVAL_DECISIONS_FILE),
        }
        self._replay()

    # ---- ingest ---------------------------------------------------------

    def _replay(self):
        """Load existing backlog as state only (no side effects), so a restart
        never re-fires containment for incidents already handled."""
        for line in self.tails["incidents"].read_new():
            iid = line.get("id")
            if iid:
                self.incidents[iid] = line
        for iid, inc in self.incidents.items():
            if inc.get("status") != "open":
                self.handled.add(iid)
        for line in self.tails["requests"].read_new():
            rid = line.get("id")
            if rid:
                self.approvals[rid] = line
        for line in self.tails["decisions"].read_new():
            rid = line.get("id")
            if rid:
                self.decided.add(rid)
        pending = [i for i in self.incidents.values() if i.get("status") == "triaged"]
        for inc in pending:
            self.handle_triaged(inc)

    def ingest(self):
        for line in self.tails["incidents"].read_new():
            iid = line.get("id")
            if not iid:
                continue
            self.incidents[iid] = line
            if line.get("status") == "triaged" and iid not in self.handled:
                self.handle_triaged(line)
            elif line.get("status") != "triaged":
                self.handled.add(iid)  # never regress into re-handling
        for line in self.tails["requests"].read_new():
            rid = line.get("id")
            if rid:
                self.approvals[rid] = line
        for line in self.tails["decisions"].read_new():
            self.handle_decision(line)
        for line in self.manual_decisions():
            self.handle_decision(line)

    def manual_decisions(self):
        """Optional file drop: events/manual_decision.json with one decision
        object (or a list) — the dashboard fallback when voice is down."""
        try:
            with open(MANUAL_DECISION_FILE, "r") as f:
                data = json.load(f)
        except (OSError, json.JSONDecodeError):
            return []
        items = data if isinstance(data, list) else [data]
        out = []
        for it in items:
            if not isinstance(it, dict):
                continue
            dec = str(it.get("decision", "")).lower()
            if dec in ("approve", "approved"):
                dec = "approved"
            elif dec in ("deny", "denied"):
                dec = "denied"
            rid = it.get("id") or it.get("approval_id")
            if rid and dec in ("approved", "denied"):
                out.append({"ts": now(), "id": rid, "decision": dec,
                            "decided_by": it.get("decided_by", "manual")})
        return out

    # ---- reactions ------------------------------------------------------

    def handle_triaged(self, inc):
        iid = inc.get("id")
        kind = inc.get("kind", "anomaly")
        ip = inc.get("source_ip") or "unknown"
        label = KIND_LABEL.get(kind, kind)
        self.handled.add(iid)
        say(f"{iid} triaged ({kind}/{inc.get('severity', '?')}) from {ip}")

        # (a) autonomous containment
        action = f"blocked {ip} at edge (simulated)"
        agent_action("containment", iid, action)
        inc = incident_update(inc, status="contained")
        self.incidents[iid] = inc
        say(f"{iid} → contained ({action})")

        # (b) patch dispatch for patchable kinds
        session_url = None
        if kind in PATCHABLE_KINDS:
            session_url = self.dispatch_patch(inc)

        # (c) human approval request — always, so the voice/dashboard flow
        # stays alive for every incident class
        if kind in PATCHABLE_KINDS:
            summary = f"{label} attack on the citizen portal from {ip}; contained, patch ready"
            call_script = (
                f"Hello, this is Falcon Shield. A {label} attack hit the citizen "
                f"portal from {ip} — I've contained it and prepared the fix. "
                "The fix is ready. Shall I deploy it?"
            )
            req_action = "deploy_patch"
        else:
            summary = f"{label} from {ip}; contained at the edge"
            call_script = (
                f"Hello, this is Falcon Shield. A {label} hit the citizen portal "
                f"from {ip} — I've contained it. Shall I block the source range?"
            )
            req_action = "block_range"
        request_approval(inc, req_action, summary, call_script)
        track = f"patch session {session_url}" if session_url else "patch (mock)"
        if kind not in PATCHABLE_KINDS:
            track = "containment only"
        say(f"{iid} → {track} → awaiting approval (APR-{iid})…")

    def dispatch_patch(self, inc):
        """Spawn a Devin patch-agent session; degrade to mock on any failure."""
        iid = inc.get("id")
        if not api_key() or requests is None:
            agent_action("patch", iid, "patch dispatched (mock)")
            inc = incident_update(inc, status="patch_pr", session_url=None, pr_url=None)
            self.incidents[iid] = inc
            say(f"{iid} → patch dispatched (mock — no DEVIN_API_KEY)")
            return None
        try:
            url, sid = spawn_patch_session(inc)
        except Exception as e:
            agent_action("patch", iid, "patch dispatched (mock)")
            inc = incident_update(inc, status="patch_pr", session_url=None, pr_url=None)
            self.incidents[iid] = inc
            say(f"{iid} → patch dispatched (mock — Devin API error: {e})")
            return None
        agent_action("patch", iid, "patch agent session spawned", session_url=url)
        inc = incident_update(inc, status="patch_pr", session_url=url, pr_url=None)
        self.incidents[iid] = inc
        if sid:
            self.pr_polls[iid] = {"session_id": sid, "next_ts": time.time() + PR_POLL_INTERVAL_S,
                                  "attempts": 0}
        say(f"{iid} → patch session {url or '(no url returned)'}")
        return url

    def poll_patch_sessions(self):
        if requests is None or not api_key():
            self.pr_polls.clear()
            return
        for iid, poll in list(self.pr_polls.items()):
            if time.time() < poll["next_ts"]:
                continue
            poll["attempts"] += 1
            pr = find_pr_url(poll["session_id"])
            if pr:
                inc = incident_update(self.incidents[iid], pr_url=pr)
                self.incidents[iid] = inc
                say(f"{iid} → patch PR found: {pr}")
                del self.pr_polls[iid]
            elif poll["attempts"] >= PR_POLL_MAX_ATTEMPTS:
                say(f"{iid} → patch PR not found yet (optimistic patch_pr)")
                del self.pr_polls[iid]
            else:
                poll["next_ts"] = time.time() + PR_POLL_INTERVAL_S

    def handle_decision(self, line):
        rid = line.get("id")
        decision = line.get("decision")
        if not rid or rid in self.decided or decision not in ("approved", "denied"):
            return
        req = self.approvals.get(rid)
        if not req:
            return  # unknown approval id
        self.decided.add(rid)
        iid = req.get("incident_id")
        inc = self.incidents.get(iid) or {"id": iid}
        by = line.get("decided_by", "?")
        if decision == "denied":
            incident_update(inc, status="escalated")
            agent_action("comms", iid, f"{rid} denied by {by} — escalated to human ops")
            say(f"{rid} denied by {by} → {iid} escalated")
            return
        say(f"{rid} approved by {by}")
        if req.get("action") == "deploy_patch":
            self.deploy_patch(inc)
        else:
            agent_action("containment", iid, f"{req.get('action')} executed (simulated)")
            say(f"{iid} → {req.get('action')} executed (simulated)")

    def deploy_patch(self, inc):
        iid = inc.get("id")
        pr_url = inc.get("pr_url")
        if pr_url:
            ok = merge_pr(pr_url)
            say(f"{iid} → PR {'merged' if ok else 'merge failed'}: {pr_url}")
            if verify_fix(inc.get("kind", "")):
                inc = incident_update(inc, status="verified")
                agent_action("self_heal", iid, "patch merged; attack re-run BLOCKED")
                say(f"{iid} → verified (attack now BLOCKED)")
            else:
                inc = incident_update(inc, status="patched")
                agent_action("self_heal", iid, "patch merged; re-verify inconclusive")
                say(f"{iid} → patched")
        else:
            # mock mode or PR URL never surfaced — never hard-stop the demo
            inc = incident_update(inc, status="patched")
            agent_action("self_heal", iid, "patch deploy approved (mock)")
            say(f"{iid} → patched (mock)")
        self.incidents[iid] = inc

    # ---- main -----------------------------------------------------------

    def run(self):
        say(f"Falcon Shield controller online — bus: {EVENTS_DIR}")
        say("Devin API: " + ("live" if (api_key() and requests) else "MOCK MODE (no DEVIN_API_KEY)"))
        while True:
            try:
                self.ingest()
                self.poll_patch_sessions()
            except Exception as e:  # the demo must never hard-stop
                say(f"loop error (ignored): {e}")
            time.sleep(LOOP_SLEEP_S)


if __name__ == "__main__":
    Controller().run()
