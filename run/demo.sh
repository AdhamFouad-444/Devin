#!/usr/bin/env bash
# Falcon Shield demo orchestrator — run each line in its own terminal, or source and run `demo_all`.
set -e
cd "$(dirname "$0")/.."

demo_all() {
  (cd apps/portal && uvicorn app:app --port 8001) &
  python tools/voice/server.py &
  python tools/detector/detect.py &
  python tools/controller/control.py &
  python -m http.server 8080 &
  echo "portal :8001 | voice :8020 | dashboard http://localhost:8080/apps/mission-control/"
  echo "fire attack: python tools/attacker/attack.py --scenario sqli"
  wait
}

if [ "$1" = "all" ]; then demo_all; else echo "usage: ./run/demo.sh all"; fi
