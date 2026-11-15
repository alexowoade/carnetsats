"""CarnetSats FastAPI Server — serves REST API + static Web MVP."""

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

app = FastAPI(
    title="CarnetSats API — Dakar Bitcoin Hack by BTrust",
    version="3.3.0",
    description="Voice/Receipt POS + Least-Privilege NWC + Real NIP-44 Nostr Credit Ledger + Real BIP-84 Cold Vault",
)

app.add_middleware(
    CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"],
)

wallet_engine = NWCLightningEngine(initial_balance_sats=95_000, daily_owner_quota_sats=50_000)
bdk_vault = BDKColdVault()
nostr_ledger = NostrCreditLedger()


class ParseSaleRequest(BaseModel):
    transcript: str
    role: str = "clerk_ai"


class SettleInvoiceRequest(BaseModel):
    payment_hash: str


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
