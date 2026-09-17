# Falcon Shield

A swarm of AI agents defends a mock UAE government service — detects, triages,
contains, and **patches** attacks autonomously, escalating high-impact actions
to a human by **voice call**.

> "600,000 attacks a day hit the UAE. There aren't enough humans. So we built a swarm."

See `SCOPE_OF_WORK.md` for the event pitch and `contracts/README.md` for the
build contract every component follows.

## Architecture

```
 attacker ──► portal ──► detector ──► controller ──► Devin patch agents ──► PR
                          │              │                │
                          ▼              ▼                ▼
                    events/*.jsonl  ◄──  dashboard  ◄──  voice (approval calls)
```

## Run the demo

```bash
./run/demo.sh all          # portal :8001, voice :8020, dashboard on :8080
python tools/attacker/attack.py --scenario sqli   # fire an attack
# dashboard: http://localhost:8080/apps/mission-control/
```

Built by a swarm of Devin sessions in ~2 hours — the swarm builds the swarm.
