#!/usr/bin/env bash
# Generate data if missing, start the API, start the dashboard.
set -euo pipefail
cd "$(dirname "$0")"

PY=.venv/bin/python
[ -x "$PY" ] || { echo "No .venv -- run: python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"; exit 1; }

if [ ! -f data/raw/auth_logs.csv ]; then
  echo "==> generating synthetic logs"
  $PY -m src.scripts.generate_data
fi

echo "==> api on http://127.0.0.1:8000"
$PY -m uvicorn src.backend.main:app --host 127.0.0.1 --port 8000 &
API_PID=$!
trap 'kill $API_PID 2>/dev/null || true' EXIT

if [ -d src/frontend/node_modules ]; then
  echo "==> dashboard on http://127.0.0.1:5173"
  (cd src/frontend && npm run dev)
else
  echo "==> frontend deps missing (cd src/frontend && npm install); API only"
  wait $API_PID
fi
