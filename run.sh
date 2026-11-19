#!/usr/bin/env bash
set -e
echo "================================================================"
echo "⚡ CarnetSats v3.8 — Dakar Bitcoin Hack by BTrust"
echo "================================================================"
if [ ! -d ".venv" ]; then
  python3 -m venv .venv
fi
source .venv/bin/activate
# Always ensure dependencies (idempotent): a new requirement such as
# websocket-client (rev4) is installed on the next start, not only when
# the venv is first created.
pip install -q -r requirements.txt
# Secrets (v3.8): .env holds CARNETSATS_NWC_URL / CARNETSATS_MERCHANT_KEY
# / CARNETSATS_VPUB. It is gitignored and never printed. On first start,
# create it with a fresh merchant signing key (64 hex chars) so Nostr
# credit events are no longer signed with the fixed demo secret. An
# existing .env is left untouched (your NWC URL and keys survive).
if [ ! -f ".env" ]; then
  python3 -c "import secrets; print('CARNETSATS_MERCHANT_KEY=' + secrets.token_hex(32))" > .env
  echo "[keys] Created .env with a fresh merchant key. Back it up somewhere safe (password manager) — if it is lost, the boutique gets a new Nostr identity."
fi
set -a
# shellcheck disable=SC1091
. ./.env
set +a
echo "[1/2] Running the 235 deterministic protocol/security tests (live relay test skipped offline)..."
# The live relay round-trip test (test_15_nostr_relay_roundtrip.py) needs a
# public relay and is NOT deterministic offline, so it is skipped by default.
# Run it explicitly with SKIP_RELAY_TESTS=0 on a machine with direct internet.
export SKIP_RELAY_TESTS=1
pytest -v test_carnetsats.py test_15_nostr_relay_roundtrip.py
echo "[2/2] Starting CarnetSats Live MVP at http://localhost:8000 ..."
uvicorn app:app --host 0.0.0.0 --port 8000
