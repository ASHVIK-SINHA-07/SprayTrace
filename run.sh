#!/usr/bin/env bash
# Generate data if missing, start the API, start the dashboard.
set -euo pipefail
cd "$(dirname "$0")"

PY=.venv/bin/python
if [ ! -x "$PY" ]; then
  echo "No .venv found. Set one up with:"
  echo "  python3.13 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  echo "(3.13 specifically -- 3.14 has no prebuilt pandas wheels and builds from source)"
  exit 1
fi

# Free the ports if a previous run left something listening. A stale uvicorn
# also serves a stale analysis, which is worse than a crash: the demo shows
# yesterday's campaigns and nothing looks wrong.
for port in 8000 5173; do
  pid=$(lsof -ti ":$port" 2>/dev/null || true)
  [ -n "$pid" ] && { echo "==> freeing port $port"; kill "$pid" 2>/dev/null || true; sleep 1; }
done

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
