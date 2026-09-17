"""Falcon Shield — voice escalation service (:8020).

Tails events/approval_requests.jsonl; for each pending request it "calls" the
human on duty: appends a `ringing` entry to events/call.jsonl and, when the
TWILIO_* envs are set, places a real outbound call that speaks call_script and
gathers a spoken yes/no. The dashboard's simulated-call UI covers the demo when
no Twilio credentials are present. Contract: contracts/README.md.
"""
import json
import os
import threading
import time
import urllib.parse
from contextlib import asynccontextmanager
from xml.sax.saxutils import escape as xml_escape

import requests
import uvicorn
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(BASE_DIR, "..", ".."))
EVENTS_DIR = os.path.join(REPO_ROOT, "events")
os.makedirs(EVENTS_DIR, exist_ok=True)

REQ_FILE = os.path.join(EVENTS_DIR, "approval_requests.jsonl")
DEC_FILE = os.path.join(EVENTS_DIR, "approval_decisions.jsonl")
CALL_FILE = os.path.join(EVENTS_DIR, "call.jsonl")

POLL_INTERVAL = 0.5
_seen: set[str] = set()  # approval ids already rung this process


def _append(path: str, entry: dict):
    try:
        with open(path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    except OSError:
        pass


def _read_jsonl(path: str):
    rows = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass  # tolerate partial/torn lines
    except OSError:
        pass
    return rows


def _latest_requests() -> dict:
    latest = {}
    for row in _read_jsonl(REQ_FILE):
        if isinstance(row, dict) and row.get("id"):
            latest[row["id"]] = row
    return latest


def _decided_ids() -> set:
    return {r["id"] for r in _read_jsonl(DEC_FILE) if isinstance(r, dict) and r.get("id")}


def _call_states() -> dict:
    states = {}
    for row in _read_jsonl(CALL_FILE):
        if isinstance(row, dict) and row.get("approval_id"):
            states[row["approval_id"]] = row.get("state")
    return states


def _ring(req: dict):
    aid = req["id"]
    _append(CALL_FILE, {
        "ts": round(time.time(), 3),
        "approval_id": aid,
        "state": "ringing",
        "transcript": req.get("call_script") or req.get("summary") or "",
    })
    if _twilio_envs():
        threading.Thread(target=_place_call, args=(req,), daemon=True).start()


def _poll_loop():
    while True:
        try:
            decided = _decided_ids()
            states = _call_states()
            for aid, req in _latest_requests().items():
                if aid in _seen:
                    continue
                _seen.add(aid)
                if req.get("status") == "pending" and aid not in decided and states.get(aid) != "ringing":
                    _ring(req)
        except Exception as e:  # tail must never die
            print(f"[voice] poll error: {e}", flush=True)
        time.sleep(POLL_INTERVAL)


# --- Twilio (optional, isolated: only runs when all envs are set) -------------

def _twilio_envs():
    envs = [os.environ.get(k) for k in ("TWILIO_SID", "TWILIO_TOKEN", "TWILIO_FROM", "CALLEE")]
    return envs if all(envs) else None


def _voice_twiml(approval_id: str, script: str) -> str:
    action = f"/twilio/gather?approval_id={urllib.parse.quote(approval_id)}"
    return (
        f'<Response><Gather input="speech" speechTimeout="auto" '
        f'action="{action}" method="POST">'
        f"<Say>{xml_escape(script)}</Say></Gather>"
        f"<Say>No response received. This request remains pending.</Say></Response>"
    )


def _place_call(req: dict):
    sid, token, from_, callee = _twilio_envs()
    aid = req["id"]
    script = req.get("call_script") or req.get("summary") or ""
    base = os.environ.get("PUBLIC_BASE_URL", "").rstrip("/")
    data = {"To": callee, "From": from_}
    if base:
        data["Url"] = f"{base}/twilio/voice?approval_id={urllib.parse.quote(aid)}"
    else:
        # No public URL for the Gather callback — still speaks the script;
        # the dashboard's simulated-call UI collects the decision instead.
        data["Twiml"] = (
            f"<Response><Say>{xml_escape(script)}</Say>"
            f'<Gather input="speech" speechTimeout="auto"></Gather>'
            f"<Say>No response received. This request remains pending.</Say></Response>"
        )
    try:
        resp = requests.post(
            f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Calls.json",
            auth=(sid, token), data=data, timeout=15,
        )
        print(f"[voice] twilio call {aid}: {resp.status_code}", flush=True)
    except Exception as e:
        print(f"[voice] twilio call failed for {aid}: {e}", flush=True)


def _record_decision(aid: str, decision: str, decided_by: str):
    _append(DEC_FILE, {
        "ts": round(time.time(), 3),
        "id": aid,
        "decision": decision,
        "decided_by": decided_by,
    })
    if _call_states().get(aid) in ("ringing", "in_call"):
        _append(CALL_FILE, {
            "ts": round(time.time(), 3),
            "approval_id": aid,
            "state": "decided",
            "transcript": f"{decision} by {decided_by}",
        })


# --- HTTP API ---------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    threading.Thread(target=_poll_loop, daemon=True).start()
    yield


app = FastAPI(title="Falcon Shield — Voice Escalation", lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)


class Decision(BaseModel):
    id: str
    decision: str
    decided_by: str = "dashboard"


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/pending")
def pending():
    decided = _decided_ids()
    out = [
        req for aid, req in _latest_requests().items()
        if req.get("status") == "pending" and aid not in decided
    ]
    return sorted(out, key=lambda r: r.get("ts", 0))


@app.post("/decision")
def decide(body: Decision):
    if body.decision not in ("approved", "denied"):
        return Response(
            json.dumps({"ok": False, "error": "decision must be approved|denied"}),
            status_code=400, media_type="application/json",
        )
    _record_decision(body.id, body.decision, body.decided_by)
    return {"ok": True, "id": body.id, "decision": body.decision}


@app.api_route("/twilio/voice", methods=["GET", "POST"])
def twilio_voice(approval_id: str = ""):
    req = _latest_requests().get(approval_id, {})
    script = req.get("call_script") or "Approval requested. Say yes to approve or no to deny."
    _append(CALL_FILE, {
        "ts": round(time.time(), 3),
        "approval_id": approval_id,
        "state": "in_call",
        "transcript": script,
    })
    return Response(_voice_twiml(approval_id, script), media_type="application/xml")


@app.post("/twilio/gather")
async def twilio_gather(request: Request, approval_id: str = ""):
    form = urllib.parse.parse_qs((await request.body()).decode("utf-8", "replace"))
    speech = " ".join(form.get("SpeechResult", []) + form.get("Digits", [])).lower()
    decision = "approved" if "yes" in speech or "approve" in speech or "1" in speech else "denied"
    _record_decision(approval_id, decision, "voice")
    reply = "Approved." if decision == "approved" else "Denied."
    return Response(
        f"<Response><Say>{reply} Thank you.</Say></Response>",
        media_type="application/xml",
    )


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8020)
