# Voice escalation (the call)

Contract in `contracts/README.md`. Build `server.py`:

- HTTP server on **:8020** (FastAPI).
- Tail `events/approval_requests.jsonl`; for each `pending` request append
  `events/call.jsonl` `{state:"ringing", call_script}` and — if `TWILIO_SID`,
  `TWILIO_TOKEN`, `TWILIO_FROM`, `CALLEE` envs are set — place a real call
  (TwiML say call_script, gather "yes/no"); otherwise leave it to the
  dashboard's simulated-call UI.
- `POST /decision {id, decision: "approved"|"denied", decided_by}` → appends
  `events/approval_decisions.jsonl`. Called by the dashboard buttons AND by
  the voice path. CORS: allow `*`.
