"""CarnetSats live-NWC test (v3.7 rev4) — SKIPPED BY DEFAULT.

What it does
------------
With a real testnet wallet configured via CARNETSATS_NWC_URL (in .env,
never in git), it proves the live path end to end against that wallet:

1. ``get_info`` answers from the real wallet (alias/network/methods).
2. ``make_invoice`` returns a REAL BOLT11 from the wallet (decodable,
   payment_hash present) — no demo key, no local minting.
3. ``lookup_invoice`` reports the invoice UNSETTLED (nobody paid it).
4. ``settle_incoming_invoice`` raises "not settled yet" — the app never
   marks an unpaid real invoice as paid.

It NEVER calls pay_invoice and NEVER spends. The invoice it creates is
for 1 sat and simply expires unpaid on the wallet.

Run it on the PC after adding a testnet NWC URL to .env::

    SKIP_RELAY_TESTS=0 CARNETSATS_NWC_URL="$(grep CARNETSATS_NWC_URL .env | cut -d= -f2-)" \\
        .venv/bin/python -m pytest test_23_nwc_live.py -v -s

(or just run it with .env sourced by run.sh's shell: the URL is read
from the environment at engine construction).
"""

import os

import pytest

from carnetsats_engine import NWCLightningEngine, _decode_bolt11_or_none

NWC_URL = os.environ.get("CARNETSATS_NWC_URL", "")


@pytest.mark.skipif(
    not NWC_URL,
    reason="Live NWC test: needs CARNETSATS_NWC_URL (a testnet wallet). "
           "Set it in .env and run with the URL in the environment.",
)
def test_23_nwc_live_wallet_roundtrip(tmp_path):
    engine = NWCLightningEngine(db_path=str(tmp_path / "nwc-live.db"))
    assert engine.nwc_mode == "live", "engine did not pick up CARNETSATS_NWC_URL"

    info = engine.execute_nip47_request("get_info", {}, role="clerk_ai")
    assert info["error"] is None, f"get_info failed: {info['error']}"
    assert info["result"].get("alias")

    bal = engine.execute_nip47_request("get_balance", {}, role="clerk_ai")
    assert bal["error"] is None, f"get_balance failed: {bal['error']}"
    assert int(bal["result"]["balance"]) >= 0

    inv = engine.execute_nip47_request(
        "make_invoice",
        {"amount": 1000, "description": "CarnetSats live-NWC test (1 sat, expires unpaid)"},
        role="clerk_ai",
    )
    assert inv["error"] is None, f"make_invoice failed: {inv['error']}"
    assert inv["result"]["payment_hash"]
    assert _decode_bolt11_or_none(inv["result"]["invoice"]) is not None

    look = engine.execute_nip47_request(
        "lookup_invoice", {"payment_hash": inv["result"]["payment_hash"]}, role="clerk_ai")
    assert look["error"] is None, f"lookup_invoice failed: {look['error']}"
    assert look["result"]["settled"] is False

    with pytest.raises(ValueError, match="not settled yet"):
        engine.settle_incoming_invoice(inv["result"]["payment_hash"])
