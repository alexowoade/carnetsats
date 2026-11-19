"""CarnetSats FastAPI Server — serves REST API + static Web MVP."""

import hashlib
import os
from pathlib import Path
from typing import Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from carnetsats_engine import (
    BDKColdVault,
    NWCLightningEngine,
    NostrCreditLedger,
    parse_boutique_entry,
)


def _load_dotenv() -> None:
    """Load VAR=value lines from .env next to this file (no new dependency).

    Secrets (NWC URL, merchant key) live ONLY in .env, which is gitignored.
    run.sh creates .env with a fresh merchant key on first start.
    """
    env_path = Path(__file__).parent / ".env"
    try:
        for line in env_path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            value = value.strip()
            # Allow quoted values (needed: the NWC URL contains ? & =).
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ("'", '"'):
                value = value[1:-1]
            os.environ.setdefault(key.strip(), value)
    except FileNotFoundError:
        pass


_load_dotenv()

app = FastAPI(
    title="CarnetSats API — Dakar Bitcoin Hack by BTrust",
    version="3.8.1",
    description="Voice/Receipt POS + Least-Privilege NWC + Real NIP-44 Nostr Credit Ledger + Real BIP-84 Cold Vault",
)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

# SQLite persistence (v3.7): invoices + Nostr ledger events live in
# carnetsats.db next to the app by default; override with CARNETSATS_DB.
# Balance, daily quota and audit logs stay in-memory (out of scope).
_DB_PATH = os.environ.get("CARNETSATS_DB") or None
wallet_engine = NWCLightningEngine(initial_balance_sats=95_000, daily_owner_quota_sats=50_000, db_path=_DB_PATH)
bdk_vault = BDKColdVault()
nostr_ledger = NostrCreditLedger(db_path=_DB_PATH)


class ParseSaleRequest(BaseModel):
    transcript: str
    role: str = "clerk_ai"


class SettleInvoiceRequest(BaseModel):
    payment_hash: str


class RepayTabRequest(BaseModel):
    event_id: str


class SecurityTestRequest(BaseModel):
    role: str = "clerk_ai"
    method: str = "pay_invoice"
    amount_sats: int = 25_000
    raw_log_probe: Optional[str] = "Client Moussa (+221 77 456 78 90) NWC secret=a1b2c3d4e5f60718293a4b5c6d7e8f90"


@app.get("/")
def serve_frontend():
    index_path = Path(__file__).parent / "docs" / "index.html"
    if index_path.exists():
        return FileResponse(index_path)
    return JSONResponse({"status": "CarnetSats API running", "docs": "/docs"})


@app.get("/api/state")
def get_boutique_state():
    sweep_status = bdk_vault.evaluate_sweep_policy(wallet_engine.balance_sats)
    return {
        "boutique": "Boutique Touba — Marché Sandaga, Dakar",
        "balance_sats": wallet_engine.balance_sats,
        "nwc_mode": wallet_engine.nwc_mode,
        "merchant_key_source": nostr_ledger.key_source,
        "nip47_info": wallet_engine.get_nip47_info_event("clerk_ai"),
        "bdk_treasury": sweep_status,
        "nostr_pubkey": nostr_ledger.pubkey_hex,
        "nostr_events_count": len(nostr_ledger.events),
        "audit_logs": wallet_engine.audit_logs[-10:],
    }


@app.get("/api/sweep-policy")
def get_sweep_policy():
    return bdk_vault.evaluate_sweep_policy(wallet_engine.balance_sats)


@app.post("/api/checkout")
def process_voice_or_text_checkout(req: ParseSaleRequest):
    parsed = parse_boutique_entry(req.transcript)
    nwc_resp = wallet_engine.execute_nip47_request(
        method="make_invoice",
        params={
            "amount": parsed.upfront_sats * 1000,
            "description": f"CarnetSats: {', '.join(parsed.items)} ({parsed.paid_upfront_xof} FCFA)",
        },
        role=req.role,
    )
    if nwc_resp.get("error"):
        raise HTTPException(status_code=403, detail=nwc_resp["error"])
    inv_result = nwc_resp["result"]

    nostr_event = nostr_ledger.create_signed_credit_event(
        customer_name=parsed.customer_name,
        items=parsed.items,
        total_xof=parsed.total_amount_xof,
        paid_now_xof=parsed.paid_upfront_xof,
        debt_remaining_xof=parsed.credit_owed_xof,
        payment_hash=inv_result["payment_hash"],
    )
    # Live relay publish (v3.7 rev4): best-effort, in the background, never
    # blocks the sale. The event's publish status is visible via
    # GET /api/nostr-events and the Relay Payload panel.
    nostr_ledger.publish_event_async(nostr_event)

    return {
        "parsed": parsed.model_dump(),
        "nip47_invoice": inv_result,
        "nostr_credit_event": {
            "id": nostr_event["id"],
            "pubkey": nostr_event["pubkey"],
            "kind": nostr_event["kind"],
            "tags": nostr_event["tags"],
            "content": nostr_event["content"],
            "sig": nostr_event["sig"],
            "nip44_spec": nostr_event["nip44_spec"],
            "decrypted_preview": nostr_event["decrypted_preview"],
        },
        "bdk_treasury": bdk_vault.evaluate_sweep_policy(wallet_engine.balance_sats),
    }


@app.post("/api/settle")
def settle_bolt11_invoice(req: SettleInvoiceRequest):
    try:
        settlement = wallet_engine.settle_incoming_invoice(req.payment_hash)
        return {
            "settlement": settlement,
            "bdk_treasury": bdk_vault.evaluate_sweep_policy(wallet_engine.balance_sats),
            "audit_logs": wallet_engine.audit_logs[-10:],
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/api/repay-tab")
def repay_customer_nostr_tab(req: RepayTabRequest):
    """Issue a replacement Kind 30078 event settling a Nostr credit tab.

    Demo mode: creates a small NWC invoice, settles it locally, then
    publishes the NIP-78 replacement (same "d" tag, debt_remaining_xof = 0)
    via the ledger. Live NWC mode: the tab settlement is ledger
    bookkeeping, not a Lightning payment, so NO real invoice is minted
    for it; the replacement references a local deterministic hash instead
    (returned as repayment="ledger-only").
    """
    try:
        if wallet_engine.nwc_mode == "live":
            repayment_hash = hashlib.sha256(f"repay:{req.event_id}".encode()).hexdigest()
            replacement_ev = nostr_ledger.repay_credit_tab(req.event_id, repayment_hash)
            nostr_ledger.publish_event_async(replacement_ev)
            return {
                "repaid": True,
                "replacement_event": replacement_ev,
                "repayment": "ledger-only",
                "new_balance_sats": wallet_engine.balance_sats,
            }
        nwc_resp = wallet_engine.execute_nip47_request(
            method="make_invoice",
            params={"amount": 1000 * 1000, "description": f"Repay Nostr Tab {req.event_id[:10]}"},
            role="clerk_ai",
        )
        if nwc_resp.get("error"):
            raise HTTPException(status_code=403, detail=nwc_resp["error"])
        repay_inv = nwc_resp["result"]
        wallet_engine.settle_incoming_invoice(repay_inv["payment_hash"])
        replacement_ev = nostr_ledger.repay_credit_tab(req.event_id, repay_inv["payment_hash"])
        nostr_ledger.publish_event_async(replacement_ev)
        return {
            "repaid": True,
            "replacement_event": replacement_ev,
            "new_balance_sats": wallet_engine.balance_sats,
        }
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/api/security-test")
def run_red_team_security_check(req: SecurityTestRequest):
    if req.raw_log_probe:
        wallet_engine._log(req.raw_log_probe)
    nip47_resp = wallet_engine.execute_nip47_request(
        method=req.method,
        params={"amount_sats": req.amount_sats, "invoice": "lntbs250u1p..."},
        role=req.role,
    )
    try:
        cold = bdk_vault.derive_cold_address(index=0)
    except RuntimeError as e:
        cold = {"error": str(e)}
    return {
        "nip47_response": nip47_resp,
        "sanitized_logs": wallet_engine.audit_logs[-8:],
        "bdk_vault": cold,
    }


@app.get("/api/nostr-events")
def list_nostr_events():
    """Ledger events with their relay publish status (judge inspection)."""
    return {
        "events": [
            {
                "id": ev["id"],
                "pubkey": ev["pubkey"],
                "created_at": ev["created_at"],
                "kind": ev["kind"],
                "tags": ev["tags"],
                "published_to": ev.get("published_to", []),
                "publish_error": ev.get("publish_error"),
                "decrypted_preview": ev.get("decrypted_preview"),
            }
            for ev in nostr_ledger.events
        ]
    }


@app.post("/api/publish-nostr-event/{event_id}")
def publish_nostr_event(event_id: str):
    """Manually (re)publish one ledger event to the public relay."""
    for ev in nostr_ledger.events:
        if ev["id"] == event_id:
            res = nostr_ledger.publish_event_to_relay(ev)
            nostr_ledger._record_publish(event_id, res)
            return {"event_id": event_id, **res}
    raise HTTPException(status_code=404, detail="Event not found")


@app.get("/api/verify-nostr-event/{event_id}")
def verify_nostr_event(event_id: str):
    for ev in nostr_ledger.events:
        if ev["id"] == event_id:
            return {"verified": nostr_ledger.verify_event_signature(ev), "event_id": event_id}
    raise HTTPException(status_code=404, detail="Event not found")


@app.post("/api/decrypt-nostr-event/{event_id}")
def decrypt_nostr_event(event_id: str):
    for ev in nostr_ledger.events:
        if ev["id"] == event_id:
            try:
                decrypted = nostr_ledger.decrypt_nip44_payload(str(ev["content"]))
                return {"decrypted": decrypted}
            except Exception as e:
                raise HTTPException(status_code=400, detail=f"Decryption failed: {e}")
    raise HTTPException(status_code=404, detail="Event not found")
