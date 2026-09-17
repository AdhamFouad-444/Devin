# AGENTS.md — Falcon Shield

Read `contracts/README.md` FIRST — it defines the JSONL event bus, ports, and
component boundaries. Components are built in parallel by separate agent
sessions; only modify files inside the directory assigned to you.

Base branch for this build: `falcon-shield`. Open PRs targeting `falcon-shield`.

Python 3.11+, fastapi/uvicorn/requests. Dashboard = single index.html + vanilla
JS + CDN (Leaflet). Everything runs locally; simulation only.
