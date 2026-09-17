# Falcon Shield — Demo Runbook

## Pre-demo (5 min)

```bash
pip install -r apps/portal/requirements.txt -r tools/voice/requirements.txt 2>/dev/null
./run/demo.sh all
# or individually:
#   cd apps/portal && uvicorn app:app --port 8001
#   python tools/voice/server.py                 # :8020 approvals/decisions
#   python tools/detector/detect.py              # tails requests+attacks -> incidents
#   python tools/controller/control.py           # swarm brain (DEVIN_API_KEY optional)
#   python -m http.server 8080                   # repo root
```

Open `http://localhost:8080/apps/mission-control/` fullscreen. Keep the
attacker terminal visible — audiences like watching the attacks fire.

If real patch agents are wanted live: `export DEVIN_API_KEY=...` before
starting the controller. Without it the controller runs in mock mode
(approvals still work, patch stage is simulated — the loop never breaks).

## Attack sequence (builds tension)

| # | Command | What the swarm does |
|---|---|---|
| 1 | `python tools/attacker/attack.py --scenario scan` | Sentinel flags scan → triage → contained |
| 2 | `python tools/attacker/attack.py --scenario brute` | brute_force incident → contained |
| 3 | `python tools/attacker/attack.py --scenario sqli` | SQLi (high) → contained → **patch agent spawned** → PR → approval requested |
| 4 | Answer the call (or dashboard Approve) | PR merges → `--verify` re-fires → **BLOCKED** |
| 5 | `python tools/attacker/attack.py --scenario dos` | High-severity burst → contained while talking |

## Fallbacks

| Failure | Fallback |
|---|---|
| Live Devin API unavailable | Controller mock mode — narrate "in production this spawns real engineers" |
| Voice server down | Dashboard approval buttons still write decisions |
| Network/venue blocks calls | Pre-recorded demo video (record a full run beforehand) |
| Detector misses an attack | Re-fire scenario; dedupe window is 60s |

## Closing line

"600,000 attacks a day. A swarm that detects, contains, and fixes the code
itself — and asks permission by phone. Zero new hires. 100% auditable."
