#!/usr/bin/env bash
set -e
echo "================================================================"
echo "⚡ CarnetSats v3.3 — Dakar Bitcoin Hack by BTrust"
echo "================================================================"
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
  source .venv/bin/activate
  pip install -q -r requirements.txt
else
  source .venv/bin/activate
fi
echo "[1/2] Running the 85 deterministic protocol/security tests..."
pytest -v test_carnetsats.py
echo "[2/2] Starting CarnetSats Live MVP at http://localhost:8000 ..."
uvicorn app:app --host 0.0.0.0 --port 8000
