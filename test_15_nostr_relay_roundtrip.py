"""CarnetSats Nostr relay round-trip test (Item #1, v3.7) - LIVE, SKIPPED BY DEFAULT.

What it does
------------
Creates a real signed NIP-78 kind-30078 credit event with
``NostrCreditLedger.create_signed_credit_event`` (real NIP-44 v2 ciphertext,
real BIP-340 Schnorr signature), publishes it to the public relay
``wss://relay.damus.io``, subscribes back by event id, and verifies the event
that comes back: same id, kind 30078, signature verifies, NIP-44 payload
decrypts to the original sale (total 18000 XOF, 8000 XOF still owed).

Why it is skipped by default
----------------------------
It needs live network access to a public relay, so it is NOT deterministic
offline. ``run.sh`` exports ``SKIP_RELAY_TESTS=1`` and the test is gated on
exactly that variable, so ``./run.sh`` never runs it. Run it explicitly with::

    SKIP_RELAY_TESTS=0 .venv/bin/python -m pytest test_15_nostr_relay_roundtrip.py -v

(also runs when the variable is simply unset).

Two bugs from the original proposal are fixed here - do not reintroduce them:
1. ``Filters(event_ids=...)`` does not exist in pynostr 0.7.0; the parameter
   is ``Filters(ids=[...])`` (verified against the installed
   ``pynostr.filters.Filters`` signature).
2. ``RelayManager.run_sync()`` must NEVER be called inside ``asyncio.run()``:
   pynostr 0.7's ``RelayManager`` is built on a tornado ``IOLoop`` and
   ``run_sync()`` drives that loop itself, so calling it from inside an
   already-running asyncio loop raises ``RuntimeError``. The relay
   interaction therefore runs in a separate *process* (``subprocess`` +
   ``sys.executable -c``), which owns a fresh tornado IOLoop and no asyncio
   loop at all.

Ordering inside the worker matters: the EVENT is queued (published) BEFORE
the REQ subscription, so the relay has the event stored before the
subscription arrives and answers with the stored event plus EOSE.
``run_sync()`` returns when EOSE closes the connection (``close_on_eose``)
or after the 20 s relay timeout, whichever comes first.

Status (2026-11-18, this sandbox VM)
--------------------------------------
The test logic is verified up to the network boundary, but the live
round-trip CANNOT complete in this sandbox: direct TCP is blocked by the
sandbox policy (the relay handshake fails with ``SSL: WRONG_VERSION_NUMBER``
and the sandbox answers plain ``Other TCP connections is turned off for
this assistant`` on port 443/80). Only proxied HTTP(S) works here, and
pynostr 0.7's tornado ``RelayManager`` has no HTTP-proxy support. On a
normal machine with direct internet (e.g. the user's PC) the same test is
expected to pass; re-run it there with ``SKIP_RELAY_TESTS=0`` before
claiming a live relay proof.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from carnetsats_engine import NostrCreditLedger

RELAY_URL = "wss://relay.damus.io"
SUBSCRIPTION_ID = "carnetsats-roundtrip-v37"

# Worker executed in a separate process (see module docstring: never run the
# tornado-based RelayManager inside this pytest process's event loop).
_WORKER_CODE = r"""
import json
import sys
import time

repo_dir = sys.argv[1]
sys.path.insert(0, repo_dir)

RELAY_URL = "wss://relay.damus.io"
SUB_ID = "carnetsats-roundtrip-v37"

result = {"ok": False, "event_id": None, "received_id": None, "error": None,
          "n_events": 0, "n_ok": 0, "n_eose": 0}
t0 = time.time()
try:
    from pynostr.event import Event
    from pynostr.filters import Filters, FiltersList
    from pynostr.relay_manager import RelayManager
    from carnetsats_engine import NostrCreditLedger

    ledger = NostrCreditLedger()
    ev = ledger.create_signed_credit_event(
        "Relay Test", ["Riz"], 18000, 10000, 8000, "dd" * 32)
    result["event_id"] = ev["id"]
    event = Event.from_dict({k: ev[k] for k in
                             ("id", "pubkey", "created_at", "kind",
                              "tags", "content", "sig")})

    rm = RelayManager(timeout=20)
    rm.add_relay(RELAY_URL, timeout=20)
    # Publish FIRST, subscribe SECOND (see module docstring for why).
    rm.publish_event(event)
    rm.add_subscription_on_all_relays(
        SUB_ID, FiltersList([Filters(ids=[ev["id"]])]))
    # Own tornado IOLoop in this process; ends on EOSE-close or 20 s timeout.
    rm.run_sync()

    pool = rm.message_pool.get_all()
    result["n_events"] = len(pool["events"])
    result["n_ok"] = len(pool["ok"])
    result["n_eose"] = len(pool["eose"])
    for msg in pool["events"]:
        if msg.event.id == ev["id"]:
            result["received_id"] = msg.event.id
            result["received"] = {
                "id": msg.event.id, "pubkey": msg.event.pubkey,
                "created_at": msg.event.created_at, "kind": msg.event.kind,
                "tags": msg.event.tags, "content": msg.event.content,
                "sig": msg.event.sig,
            }
            break
    result["ok"] = result["received_id"] == ev["id"]
    if not result["ok"]:
        result["error"] = (
            "published event not received back "
            "(events=%d ok=%d eose=%d)" % (
                result["n_events"], result["n_ok"], result["n_eose"]))
except Exception as exc:  # noqa: BLE001 - report everything as JSON
    result["error"] = "%s: %s" % (type(exc).__name__, exc)
result["elapsed_s"] = round(time.time() - t0, 1)
print(json.dumps(result))
sys.exit(0 if result["ok"] else 1)
"""


@pytest.mark.skipif(
    os.environ.get("SKIP_RELAY_TESTS") == "1",
    reason="Live relay test: skipped by default (run.sh sets SKIP_RELAY_TESTS=1). "
           "Run with SKIP_RELAY_TESTS=0 on a machine with direct internet.",
)
def test_15_nostr_relay_roundtrip_live():
    """Publish a signed credit event to relay.damus.io and read it back by id."""
    repo_dir = str(Path(__file__).resolve().parent)
    proc = subprocess.run(
        [sys.executable, "-c", _WORKER_CODE, repo_dir],
        cwd=repo_dir,
        capture_output=True,
        text=True,
        timeout=120,
    )
    try:
        result = json.loads(proc.stdout.strip().splitlines()[-1])
    except (IndexError, ValueError):
        pytest.fail(
            "relay worker produced no JSON output "
            f"(returncode={proc.returncode}, stdout={proc.stdout!r}, "
            f"stderr={proc.stderr[-2000:]!r})"
        )
    assert result["ok"], (
        f"relay round-trip failed: {result.get('error')} "
        f"(event_id={result.get('event_id')}, elapsed={result.get('elapsed_s')}s, "
        f"worker stderr={proc.stderr[-1000:]!r})"
    )

    received = result["received"]
    assert received["id"] == result["event_id"]
    assert received["kind"] == 30078

    # Verify the round-tripped event independently, in this process.
    ledger = NostrCreditLedger()
    assert ledger.verify_event_signature(received) is True
    cleartext = ledger.decrypt_nip44_payload(received["content"])
    assert cleartext["total_xof"] == 18000
    assert cleartext["paid_now_xof"] == 10000
    assert cleartext["debt_remaining_xof"] == 8000
    assert cleartext["items"] == ["Riz"]
