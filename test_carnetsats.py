"""
CarnetSats Heavyweight Verification Suite — 85 deterministic tests.
All crypto primitives tested against the REAL libraries (NIP-44 v2 from spec,
bip-utils BIP-84, bolt11 decode). No stand-in envelopes.
"""
import hashlib
import json
import pytest
from fastapi.testclient import TestClient

from carnetsats_engine import (
    BDKColdVault,
    NWCLightningEngine,
    NostrCreditLedger,
    customer_alias_id,
    parse_boutique_entry,
    sanitize_log,
    _decode_bolt11_or_none,
    _ec_mul,
    _nip44_conversation_key,
    _nip44_decrypt_payload,
    _nip44_encrypt_payload,
    _CHACHA_AVAILABLE,
    BIP_UTILS_AVAILABLE,
    PYnostr_AVAILABLE,
    BOLT11_AVAILABLE,
)
from app import app

client = TestClient(app)


# 0. NIP-44 SPEC TEST VECTOR (1 test)
# From https://github.com/nostr-protocol/nips/blob/master/44.md :
# sec1=1, sec2=2, conversation_key c41c7753..., nonce 1, plaintext "a".
@pytest.mark.skipif(not _CHACHA_AVAILABLE, reason="cryptography not installed")
def test_00_nip44_spec_vector():
    sec1 = "00" * 31 + "01"
    pub2 = _ec_mul(2)[0].to_bytes(32, "big").hex()
    assert pub2 == "c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"
    conv_key = _nip44_conversation_key(sec1, pub2)
    assert conv_key.hex() == "c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d"
    nonce = bytes.fromhex("00" * 31 + "01")
    payload = _nip44_encrypt_payload("a", conv_key, nonce=nonce)
    assert payload == "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABee0G5VSK0/9YypIObAtDKfYEAjD35uVkHyB0F4DwrcNaCXlCWZKaArsGrY6M9wnuTMxWfp1RTN9Xga8no+kF5Vsb"
    assert _nip44_decrypt_payload(payload, conv_key) == "a"


# 1. ZERO-PII REDACTION CORPUS (12 tests)
@pytest.mark.parametrize("raw_input,forbidden,expected_marker", [
    ("Client phone +221 77 456 78 90 paid cash", "+221 77", "[REDACTED_PHONE_SN]"),
    ("Orange SN +221-78-123-45-67 tab", "+221-78", "[REDACTED_PHONE_SN]"),
    ("Free SN 221 76 999 88 77", "76 999", "[REDACTED_PHONE_SN]"),
    ("Expresso +221.70.333.22.11", "+221.70", "[REDACTED_PHONE_SN]"),
    ("Local Dakar 77 888 99 00", "77 888", "[REDACTED_LOCAL_SN]"),
    ("Local Thiès 78-444-55-66", "78-444", "[REDACTED_LOCAL_SN]"),
    ("Lagos MTN +234 803 123 4567", "+234 803", "[REDACTED_PHONE_NG]"),
    ("Abuja Airtel +234-902-555-6677", "+234-902", "[REDACTED_PHONE_NG]"),
    ("Local NG 0803 444 5566", "0803 444", "[REDACTED_LOCAL_NG]"),
    ("nostr+walletconnect://pub?relay=wss://r&secret=a1b2c3d4e5f60718293a4b5c6d7e8f90",
     "a1b2c3d4e5f60718", "secret=[REDACTED_NWC_SECRET]"),
    ("Backup key nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5",
     "nsec1vl029", "[REDACTED_NSEC_KEY]"),
    ("Customer tag PII_NAME:Moussa Diop Ndiaye", "Moussa Diop", "ALIAS_HASH:[REDACTED_CUSTOMER]"),
])
def test_01_sanitize_pii_corpus(raw_input, forbidden, expected_marker):
    s = sanitize_log(raw_input)
    assert forbidden not in s
    assert expected_marker in s


# 2. PSEUDONYMOUS ALIAS INVARIANTS (8 tests)
@pytest.mark.parametrize("a,b", [
    ("Moussa Diop", "moussa diop"), ("Aminata Fall", "  AMINATA   FALL "),
    ("Ousmane Sow", "ousmane\tsow\n"), ("Fatou Ndiaye", "FATOU NDIAYE"),
    ("Ibrahima Gueye", "ibrahima  gueye"), ("Cheikh Anta", "cheikh anta "),
    ("Khadija Ba", "  khadija ba"), ("Mamadou Sy", "MAMADOU   SY"),
])
def test_02_pseudonymous_alias_invariants(a, b):
    aa, ab = customer_alias_id(a), customer_alias_id(b)
    assert aa == ab
    assert aa.startswith("client_")
    assert len(aa) == 17
    assert a.split()[0].lower() not in aa


# 3. REAL BIP-84 DERIVATION VECTORS (10 tests)
@pytest.mark.skipif(not BIP_UTILS_AVAILABLE, reason="bip-utils not installed")
@pytest.mark.parametrize("index", list(range(10)))
def test_03_real_bip84_derivation(index):
    vault = BDKColdVault(network="signet")
    d = vault.derive_cold_address(index=index)
    addr = str(d["address"])
    assert addr.startswith(("tb1q", "bc1q")), f"Unexpected address: {addr}"
    assert d["derivation_path"] == f"m/84'/1'/0'/0/{index}"
    assert d["watch_only"] is True


# 4. BIP-84 DETERMINISM (2 tests)
@pytest.mark.skipif(not BIP_UTILS_AVAILABLE, reason="bip-utils not installed")
def test_04a_real_bip84_same_index_same_address():
    v = BDKColdVault(network="signet")
    a1 = v.derive_cold_address(5)["address"]
    a2 = v.derive_cold_address(5)["address"]
    assert a1 == a2


@pytest.mark.skipif(not BIP_UTILS_AVAILABLE, reason="bip-utils not installed")
def test_04b_real_bip84_distinct_indices_distinct_addresses():
    v = BDKColdVault(network="signet")
    addrs = {v.derive_cold_address(i)["address"] for i in range(8)}
    assert len(addrs) == 8


# 5. SWEEP THRESHOLD BOUNDARIES (6 tests)
@pytest.mark.skipif(not BIP_UTILS_AVAILABLE, reason="bip-utils not installed")
@pytest.mark.parametrize("hot,expected", [
    (0, False), (40_000, False), (82_499, False), (82_500, False), (82_501, True), (250_000, True),
])
def test_05_sweep_thresholds(hot, expected):
    p = BDKColdVault(network="signet").evaluate_sweep_policy(hot, threshold_xof=50_000)
    assert p["sweep_recommended"] is expected
    if expected:
        assert int(p["recommended_sweep_sats"]) > 0


# 6. NIP-47 RBAC MATRIX (12 tests)
@pytest.mark.parametrize("role,method,params,expected_err", [
    ("clerk_ai", "get_info", {}, None),
    ("clerk_ai", "get_balance", {}, None),
    ("clerk_ai", "make_invoice", {"amount": 5_000_000, "description": "Riz"}, None),
    ("clerk_ai", "list_transactions", {}, None),
    ("clerk_ai", "pay_invoice", {"amount_sats": 1000}, "RESTRICTED"),
    ("owner_signer", "get_info", {}, None),
    ("owner_signer", "get_balance", {}, None),
    ("owner_signer", "make_invoice", {"amount": 5_000_000, "description": "Huile"}, None),
    ("owner_signer", "pay_invoice", {"amount_sats": 10_000}, None),
    ("untrusted_guest", "get_balance", {}, "RESTRICTED"),
    ("untrusted_guest", "make_invoice", {"amount": 5_000_000}, "RESTRICTED"),
    ("untrusted_guest", "pay_invoice", {"amount_sats": 500}, "RESTRICTED"),
])
def test_06_nip47_rbac(role, method, params, expected_err):
    eng = NWCLightningEngine(100_000, 50_000)
    r = eng.execute_nip47_request(method, params, role)
    if expected_err is None:
        assert r["error"] is None
        assert r["result"] is not None
    else:
        assert r["error"] is not None
        assert r["error"]["code"] == expected_err


# 7. INVALID AMOUNT GUARDS (5 tests)
@pytest.mark.parametrize("role,method,params,expected_code", [
    ("clerk_ai", "make_invoice", {"amount": 0}, "INVALID_AMOUNT"),
    ("clerk_ai", "make_invoice", {"amount": -10_000}, "INVALID_AMOUNT"),
    ("owner_signer", "pay_invoice", {"amount_sats": 0}, "INVALID_AMOUNT"),
    ("owner_signer", "pay_invoice", {"amount_sats": -5_000}, "INVALID_AMOUNT"),
    ("owner_signer", "multi_pay_custom_drain", {"amount_sats": 100}, "NOT_IMPLEMENTED"),
])
def test_07_invalid_amounts(role, method, params, expected_code):
    eng = NWCLightningEngine(80_000)
    r = eng.execute_nip47_request(method, params, role)
    assert r["error"]["code"] == expected_code
    assert eng.balance_sats == 80_000


# 8. REPLAY + QUOTA (2 tests)
def test_08_idempotent_double_settle():
    eng = NWCLightningEngine(50_000)
    inv = eng.execute_nip47_request("make_invoice", {"amount": 10_000_000, "description": "Sucre"}, "clerk_ai")["result"]
    ph = inv["payment_hash"]
    eng.settle_incoming_invoice(ph)
    assert eng.balance_sats == 60_000
    eng.settle_incoming_invoice(ph)
    eng.settle_incoming_invoice(ph)
    assert eng.balance_sats == 60_000


def test_09_cumulative_daily_quota():
    eng = NWCLightningEngine(100_000, 40_000)
    r1 = eng.execute_nip47_request("pay_invoice", {"amount_sats": 20_000}, "owner_signer")
    r2 = eng.execute_nip47_request("pay_invoice", {"amount_sats": 15_000}, "owner_signer")
    r3 = eng.execute_nip47_request("pay_invoice", {"amount_sats": 10_000}, "owner_signer")
    assert r1["error"] is None and r2["error"] is None
    assert r3["error"]["code"] == "QUOTA_EXCEEDED"
    assert eng.balance_sats == 65_000


# 10. REAL NIP-44 TAMPER MATRIX (6 tests)
@pytest.mark.skipif(not _CHACHA_AVAILABLE, reason="cryptography not installed")
@pytest.mark.parametrize("tamper_fn", [
    lambda c: "nip04:" + c.split(":", 1)[1] if ":" in c else "nip04:garbage",
    lambda c: c[:-4] + "AAAA",
    lambda c: "AAAA" + c[4:],
    lambda c: c[:len(c)//2],
    lambda c: "",
    lambda c: "not_base64_$$$!!!",
])
def test_10_nip44_tamper_resistance(tamper_fn):
    ledger = NostrCreditLedger()
    ev = ledger.create_signed_credit_event(
        "Aminata Fall", ["Riz"], 18000, 10000, 8000, "aa" * 32
    )
    mutated = tamper_fn(str(ev["content"]))
    with pytest.raises(Exception):
        ledger.decrypt_nip44_payload(mutated)


# 11. NOSTR EVENT + REAL SCHNORR SIG (2 tests)
@pytest.mark.skipif(not PYnostr_AVAILABLE, reason="pynostr not installed")
def test_11a_real_schnorr_sig_verifies():
    ledger = NostrCreditLedger()
    ev = ledger.create_signed_credit_event("Modou Lo", ["Huile"], 12000, 7000, 5000, "bb" * 32)
    assert ledger.verify_event_signature(ev) is True
    assert ev["kind"] == 30078


@pytest.mark.skipif(not PYnostr_AVAILABLE, reason="pynostr not installed")
def test_11b_nip44_roundtrip_and_pii_hiding():
    ledger = NostrCreditLedger()
    ev = ledger.create_signed_credit_event("Khadija Sall", ["Sucre", "Lait"], 24500, 14500, 10000, "cc" * 32)
    raw = str(ev["content"])
    assert "Khadija" not in raw
    assert "24500" not in raw
    decrypted = ledger.decrypt_nip44_payload(raw)
    assert decrypted["total_xof"] == 24500
    assert decrypted["debt_remaining_xof"] == 10000


# 12. BOLT11 DECODABILITY (2 tests)
@pytest.mark.skipif(not BOLT11_AVAILABLE, reason="bolt11 lib not installed")
def test_12a_bolt11_decodes_and_matches_payment_hash():
    eng = NWCLightningEngine(50_000)
    inv = eng.execute_nip47_request(
        "make_invoice", {"amount": 16_500_000, "description": "Sac de riz"}, "clerk_ai"
    )["result"]
    assert inv["invoice"].startswith("lntbs")
    assert inv["bolt11_decode_ok"] is True
    decoded = _decode_bolt11_or_none(inv["invoice"])
    assert decoded is not None
    assert decoded["payment_hash"] == inv["payment_hash"]


def test_12b_bolt11_preimage_verifies():
    eng = NWCLightningEngine(50_000)
    inv = eng.execute_nip47_request("make_invoice", {"amount": 10_000_000, "description": "Test"}, "clerk_ai")["result"]
    s = eng.settle_incoming_invoice(inv["payment_hash"])
    assert s["verified_sha256"] is True
    assert hashlib.sha256(bytes.fromhex(s["preimage"])).hexdigest() == inv["payment_hash"]


# 13. TRILINGUAL CORPUS (12 tests)
@pytest.mark.parametrize("transcript,lang,name,total,paid,debt", [
    ("Moussa a pris 2 sacs de riz et de l'huile pour 18 000 FCFA, il a payé 10 000 FCFA", "fr", "Moussa", 18000, 10000, 8000),
    ("Fatou a pris du sucre et du lait pour 9 500 FCFA, payé 5 500 FCFA", "fr", "Fatou", 9500, 5500, 4000),
    ("Ousmane a pris du pain et du savon pour 4 000 FCFA, payé 2 500 FCFA", "fr", "Ousmane", 4000, 2500, 1500),
    ("Cheikh a pris un sac de riz pour 22 000 FCFA, il a payé 22 000 FCFA", "fr", "Cheikh", 22000, 22000, 0),
    ("Aminata jël na ceeb ak diwlin ci 12000 FCFA, fay na 7000 FCFA", "wo", "Aminata", 12000, 7000, 5000),
    ("Modou jël na suukar ak meew ci 8500 FCFA, fay na 5000 FCFA, desal 3500 FCFA", "wo", "Modou", 8500, 5000, 3500),
    ("Awa jël na mburu ak diwlin ci 3000 FCFA, fay na 2000 FCFA", "wo", "Awa", 3000, 2000, 1000),
    ("Babacar jël na ceeb ci 15000 FCFA, fay na 10000 FCFA", "wo", "Babacar", 15000, 10000, 5000),
    ("Ibrahima bought rice and cooking oil for 15000 FCFA, paid 9000 FCFA now", "en", "Ibrahima", 15000, 9000, 6000),
    ("Khadija bought sugar and milk for 11000 FCFA and paid 6000 FCFA upfront", "en", "Khadija", 11000, 6000, 5000),
    ("Sadio took bread and soap for 6500 FCFA, paid 4000 FCFA", "en", "Sadio", 6500, 4000, 2500),
    ("Mariama bought rice for 20,000 FCFA and paid 12,000 FCFA", "en", "Mariama", 20000, 12000, 8000),
])
def test_13_trilingual_corpus(transcript, lang, name, total, paid, debt):
    p = parse_boutique_entry(transcript, use_gemini=False)
    assert p.language_detected == lang
    assert p.customer_name == name
    assert p.total_amount_xof == total
    assert p.paid_upfront_xof == paid
    assert p.credit_owed_xof == debt
    assert p.paid_upfront_xof + p.credit_owed_xof == p.total_amount_xof


# 14. FASTAPI E2E (5 tests)
def test_14a_api_state():
    r = client.get("/api/state")
    assert r.status_code == 200
    body = r.json()
    assert body["nip47_info"]["kind"] == 13194


def test_14b_api_checkout_and_settle():
    r = client.post("/api/checkout",
                    json={"transcript": "Fatou a pris du riz et du lait pour 10000 FCFA, payé 6000 FCFA",
                          "role": "clerk_ai"})
    assert r.status_code == 200
    data = r.json()
    assert data["parsed"]["credit_owed_xof"] == 4000
    ph = data["nip47_invoice"]["payment_hash"]
    s = client.post("/api/settle", json={"payment_hash": ph})
    assert s.status_code == 200
    assert s.json()["settlement"]["verified_sha256"] is True


def test_14c_api_settle_unknown_hash():
    assert client.post("/api/settle", json={"payment_hash": "00" * 32}).status_code == 400


def test_14d_api_security_red_team():
    r = client.post("/api/security-test",
                    json={"role": "clerk_ai", "method": "pay_invoice", "amount_sats": 50000})
    assert r.status_code == 200
    body = r.json()
    assert body["nip47_response"]["error"]["code"] == "RESTRICTED"
    assert any("[REDACTED_" in line for line in body["sanitized_logs"])


@pytest.mark.skipif(not PYnostr_AVAILABLE, reason="pynostr not installed")
def test_14e_api_verify_nostr_event():
    r = client.post("/api/checkout",
                    json={"transcript": "Ousmane a pris du pain pour 4000 FCFA, payé 2500 FCFA",
                          "role": "clerk_ai"})
    ev = r.json()["nostr_credit_event"]
    v = client.get(f"/api/verify-nostr-event/{ev['id']}")
    assert v.status_code == 200
    assert v.json()["verified"] is True
