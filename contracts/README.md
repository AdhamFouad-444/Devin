# Falcon Shield — Component Contracts (READ FIRST)

A swarm-defense demo: a vulnerable mock UAE citizen portal is attacked; agents detect,
contain, and patch — humans approve high-impact actions by voice call or dashboard click.

## Golden rule for parallel builders

Each component lives in its own directory and communicates ONLY through the
append-only JSONL event bus in `events/` plus the fixed ports below. Do not modify
other components' directories. Do not change these schemas — other components depend on them.

## Event bus — `events/*.jsonl` (one JSON object per line, append-only)

Status updates are new lines with the same `id`; readers take the LATEST status per id.

| File | Written by | Line schema |
|---|---|---|
| `events/requests.jsonl` | portal | `{"ts": float, "ip": str, "geo": [lat, lng, label] | null, "method": str, "path": str, "query": str, "status": int}` |
| `events/attacks.jsonl` | attacker | `{"ts": float, "scenario": str, "source": {"ip": str, "geo": [lat,lng,label]}, "target_path": str, "result": str}` |
| `events/incidents.jsonl` | detector (open/triaged), controller (contained/patched) | `{"ts": float, "id": str, "kind": "sqli"|"brute_force"|"scan"|"dos"|"cve_probe"|"anomaly", "severity": "low"|"med"|"high", "status": "open"|"triaged"|"contained"|"patch_pr"|"patched"|"verified"|"escalated", "evidence": str, "source_ip": str, "session_url": str|null, "pr_url": str|null}` |
| `events/agents.jsonl` | controller | `{"ts": float, "agent_role": "sentinel"|"triage"|"containment"|"patch"|"self_heal"|"comms", "incident_id": str, "session_url": str|null, "action": str}` |
| `events/approval_requests.jsonl` | controller | `{"ts": float, "id": str, "incident_id": str, "action": "deploy_patch"|"isolate_service"|"block_range", "summary": str, "call_script": str, "status": "pending"}` |
| `events/approval_decisions.jsonl` | dashboard OR voice | `{"ts": float, "id": str, "decision": "approved"|"denied", "decided_by": "dashboard"|"voice"}` |
| `events/call.jsonl` | voice | `{"ts": float, "approval_id": str, "state": "ringing"|"in_call"|"decided", "transcript": str}` |

## Components & fixed ports

| Component | Dir | Run | Contract |
|---|---|---|---|
| Portal (mock gov service) | `apps/portal` | `uvicorn app:app --port 8001` | FastAPI; logs every request to `requests.jsonl`; honors `X-Sim-Source` header as the fake source IP (attacker sets it). Contains INTENTIONAL vulns — do not "fix" portal code outside your task. |
| Attack generator | `tools/attacker` | `python attack.py --scenario <name> [--rate N]` | Sends requests to `PORTAL_URL` (default http://localhost:8001) using `X-Sim-Source` spoofed IPs w/ fake geo; appends to `attacks.jsonl`. Scenarios: `sqli`, `brute`, `scan`, `dos`, `cve`. `--verify` mode re-fires one probe and prints `BLOCKED`/`SUCCESS`. |
| Detector | `tools/detector` | `python detect.py` | Tails `requests.jsonl`/`attacks.jsonl`; classifies → appends `incidents.jsonl` (status `open`, then `triaged`). Dedupe by (kind, source_ip) within 60s. |
| Swarm controller | `tools/controller` | `python control.py` | Tails `incidents.jsonl`; for triaged incidents: append containment + `agents.jsonl`, set `contained`; for patchable kinds spawn a Devin patch-agent session (API below) → set `patch_pr` w/ `pr_url` + write `approval_requests.jsonl`; on `approved` decision: merge PR, re-run attacker `--verify`, set `patched`/`verified`. On `denied`: `escalated`. |
| Voice escalation | `tools/voice` | `python server.py` | Tails `approval_requests.jsonl`; appends `call.jsonl` (`ringing` with `call_script`). If `TWILIO_*` envs set → real call; else just `call.jsonl` (dashboard speaks it). Writes decisions to `approval_decisions.jsonl` (`decided_by: "voice"`). |
| Mission Control | `apps/mission-control` | served statically from repo root: `python -m http.server 8080` → `http://localhost:8080/apps/mission-control/` | Pure HTML/JS (Leaflet via CDN for the 2D map). Polls `../../events/*.jsonl` every ~1s. Must render: threat map (attack arcs + incident pins), incident feed, agent feed, metrics counters (attacks, blocked, MTTD/MTTR, human touches), approval queue with Approve/Deny → writes `approval_decisions.jsonl` via a tiny POST endpoint is NOT possible on static hosting — instead POST to `http://localhost:8020/decision` (the voice server exposes it). If voice server is down, show the approval anyway (demo fallback = controller also accepts `manual` file drop). |

## Devin API (used by controller)

- `POST https://api.devin.ai/v1/sessions`, header `Authorization: Bearer $DEVIN_API_KEY`,
  body `{"prompt": "...", "title": "patch: <incident>", "idempotent": false}` → `{session_id, url}`.
- If `DEVIN_API_KEY` is unset or the call fails: still append `agents.jsonl` with `session_url: null`
  and `action: "patch dispatched (mock)"` — the demo must never hard-fail.

## Coding conventions

- Python 3.11+, `fastapi`, `uvicorn`, `requests` — keep deps in each component's `requirements.txt`.
- No frameworks/build steps for the dashboard — one `index.html` + vanilla JS + CDN links.
- All appenders open files in append mode per write; all readers tolerate partial lines and missing files.
- Everything is a simulation: never attack anything except `PORTAL_URL`; never claim real CVEs.
