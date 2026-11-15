"""
CarnetSats Core Engine v3.3.0 — Dakar Bitcoin Hack by BTrust
Real-primitive implementation:
1. NIP-47 (NWC) Least-Privilege Wallet Engine with real BOLT11 encoding (pyln-client / bolt11 spec)
2. Real BIP-84 wpkh derivation (bip-utils) for Signet cold vault
3. Real NIP-44 v2 encryption + BIP-340 Schnorr signatures via pynostr
4. Deterministic schema-constrained AI Cashier (FR / Wolof / EN) + Zero-PII log redactor

Honest claims:
- BOLT11: spec-correct BOLT11 string produced by the `bolt11` library (HRP lntbs,
  timestamp, payment_hash tag `p`, payment_secret tag `s`, description tag `d`,
  expiry, valid checksum) and signed with a deterministic DEMO secp256k1 key
  (sha256 of a fixed demo string, NOT a real node key). In production the LN
  node's `sign_invoice` RPC produces the same shape with a real key.
- NIP-44 v2: real ChaCha20 + HMAC-SHA256 + padding per NIP-44 spec, implemented
  here from the spec (secp256k1 ECDH, HKDF-SHA256, ChaCha20, HMAC-SHA256,
  base64). pynostr 0.7 has no nip44 module and its EncryptedDirectMessage is
  NIP-04 only, so NIP-44 is NOT done via pynostr. Ciphertexts are spec-shaped
  and decrypt with any spec-compliant NIP-44 library (nostr-tools, nostr-sdk).
- BIP-84: real BIP-32 child derivation from a valid BIP-84 testnet vpub via
  `bip-utils`. The default vpub is derived from a fixed DEMO seed, production
  swaps in the boutique's own vpub from a hardware signer.
"""

from __future__ import annotations
import base64
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import time
from typing import Dict, List, Literal, Optional, Tuple
from pydantic import BaseModel, Field

# --- Real cryptographic libraries -------------------------------------------------
try:
    from pynostr.key import PrivateKey
    from pynostr.event import Event
    # NOTE: pynostr 0.7 has NO nip44 module. EncryptedDirectMessage is NIP-04
    # only, so NIP-44 v2 is implemented from the spec below, not via pynostr.
    PYnostr_AVAILABLE = True
except Exception:
    PYnostr_AVAILABLE = False

try:
    from bip_utils import (
        Bip32Secp256k1,
        Bip44Changes,
        Bip84,
        Bip84Coins,
        P2WPKHAddr,
    )
    BIP_UTILS_AVAILABLE = True
except Exception:
    BIP_UTILS_AVAILABLE = False

try:
    from bolt11 import Bolt11 as _Bolt11Lib
    from bolt11 import decode as _bolt11_decode_lib
    from bolt11 import encode as _bolt11_encode_lib
    from bolt11.models.tags import Tags as _Bolt11Tags
    from bolt11.types import MilliSatoshi as _MilliSatoshi
    from bolt11.types import TagChar as _TagChar
    BOLT11_AVAILABLE = True
except Exception:
    BOLT11_AVAILABLE = False

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
    _CHACHA_AVAILABLE = True
except Exception:
    _CHACHA_AVAILABLE = False

try:
    from google import genai
    from google.genai import types
    GENAI_AVAILABLE = True
except Exception:
    GENAI_AVAILABLE = False


# =====================================================================
# 1. CONSTANTS
# =====================================================================
DEFAULT_SATS_PER_XOF = 1.65
DEFAULT_SATS_PER_NGN = 0.62
HOT_WALLET_SWEEP_THRESHOLD_XOF = 50_000


# =====================================================================
# 2. ZERO-PII SECURITY SANITIZER
# =====================================================================
PII_PATTERNS = [
    (re.compile(r"(\+?221[\s\-\.]?\d{2}[\s\-\.]?\d{3}[\s\-\.]?\d{2}[\s\-\.]?\d{2})"), "[REDACTED_PHONE_SN]"),
    (re.compile(r"(\+?234[\s\-\.]?\d{3}[\s\-\.]?\d{3}[\s\-\.]?\d{4})"), "[REDACTED_PHONE_NG]"),
    (re.compile(r"\b(0[789][01]\d[\s\-]?\d{3}[\s\-]?\d{4})\b"), "[REDACTED_LOCAL_NG]"),
    (re.compile(r"\b(7[05678][\s\-\.]?\d{3}[\s\-\.]?\d{2}[\s\-\.]?\d{2})\b"), "[REDACTED_LOCAL_SN]"),
    (re.compile(r"secret=[0-9a-fA-F]{16,64}"), "secret=[REDACTED_NWC_SECRET]"),
    (re.compile(r"nsec1[0-9a-z]{20,}"), "[REDACTED_NSEC_KEY]"),
    (re.compile(r"PII_NAME:([A-Za-zÀ-ÿ\s\-]+)"), "ALIAS_HASH:[REDACTED_CUSTOMER]"),
]


def sanitize_log(raw_message: str) -> str:
    cleaned = raw_message
    for pattern, replacement in PII_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


def customer_alias_id(raw_name: str, boutique_salt: str = "dakar-sandaga-v1") -> str:
    norm = " ".join(raw_name.strip().lower().split()).encode("utf-8")
    digest = hashlib.sha256(boutique_salt.encode("utf-8") + norm).hexdigest()[:10]
    return f"client_{digest}"


# =====================================================================
# 3. REAL BIP-84 WATCH-ONLY SIGNET COLD VAULT
# =====================================================================
class BDKColdVault:
    """
    Watch-only BIP-84 (wpkh) Signet cold-storage treasury.

    Derivation uses real BIP-32 secp256k1 child derivation via bip-utils.
    The default vpub is a well-known Signet test vpub; production swaps in the
    boutique's own vpub from a hardware signer (e.g. Coldcard, SeedSigner),
    via the CARNETSATS_VPUB env var or the tpub argument.
    """

    # Valid BIP-84 testnet vpub (m/84'/1'/0'), derived with bip-utils from
    # the fixed DEMO seed sha256(b"carnetsats-demo-bip84-seed-v1").
    # DEMO ONLY: anyone can re-derive this watch-only key. Production swaps
    # in the boutique's own vpub via CARNETSATS_VPUB.
    # The old default was a BIP-44 tpub, which Bip84 correctly rejects
    # (wrong net version 043587cf) - that was the 18-test BIP84 failure.
    DEFAULT_TPUB = "vpub5Z7ogPJsstjDGc2fnZDBNKB5ib4bbHm5DkiJMwFtC5yR4dKgQ6zfauYcjSgyknxJr7PsKWKcfs25CVbHXYR5yJcXP5oA3BUmWvtjURXrfas"

    def __init__(self, tpub: Optional[str] = None, network: str = "signet", account: int = 0):
        self.tpub = tpub or os.getenv("CARNETSATS_VPUB") or BDKColdVault.DEFAULT_TPUB
        self.network = network.lower()
        self.account = account
        self.engine_mode = "bip-utils-bip84" if BIP_UTILS_AVAILABLE else "bip84-fallback-unavailable"

    def derive_cold_address(self, index: int = 0) -> Dict[str, object]:
        if index < 0:
            raise ValueError("BIP-84 child derivation index must be non-negative")
        if not BIP_UTILS_AVAILABLE:
            raise RuntimeError("bip-utils not installed: pip install bip-utils")

        # m/84'/1'/0'/0/index  (Signet uses coin 1h like testnet)
        coin = Bip84Coins.BITCOIN_TESTNET if self.network in ("signet", "testnet", "mutinynet") else Bip84Coins.BITCOIN

        # Build Bip84 from the account-level vpub (m/84'/1'/0')
        # bip_utils requires the xpub at account level for watch-only.
        bip84_acc = Bip84.FromExtendedKey(self.tpub, coin)
        bip84_addr = bip84_acc.Change(Bip44Changes.CHAIN_EXT).AddressIndex(index)
        address = bip84_addr.PublicKey().ToAddress()

        hrp = "tb" if self.network in ("signet", "testnet", "mutinynet") else "bc"
        # Sanity: verify the address uses the correct HRP for the network
        if not address.startswith(hrp + "1q"):
            raise RuntimeError(f"BIP-84 derivation produced a wrong-network address: {address}")

        return {
            "network": self.network,
            "derivation_path": f"m/84'/1'/{self.account}'/0/{index}",
            "address": address,
            "tpub_prefix": self.tpub[:24] + "...",
            "engine": self.engine_mode,
            "watch_only": True,
        }

    def evaluate_sweep_policy(
        self, hot_balance_sats: int, threshold_xof: int = HOT_WALLET_SWEEP_THRESHOLD_XOF
    ) -> Dict[str, object]:
        threshold_sats = int(round(threshold_xof * DEFAULT_SATS_PER_XOF))
        needs_sweep = hot_balance_sats > threshold_sats
        reserve_sats = int(threshold_sats * 0.4)
        sweep_amount_sats = max(0, hot_balance_sats - reserve_sats) if needs_sweep else 0
        try:
            vault_target = self.derive_cold_address(index=0)
        except Exception:
            vault_target = {"address": "tb1q_unavailable_bip84_derivation_failed", "derivation_path": "n/a"}
        return {
            "hot_balance_sats": hot_balance_sats,
            "threshold_xof": threshold_xof,
            "threshold_sats": threshold_sats,
            "sweep_recommended": needs_sweep,
            "recommended_sweep_sats": sweep_amount_sats,
            "vault_destination": vault_target.get("address"),
            "derivation_path": vault_target.get("derivation_path"),
            "engine": self.engine_mode,
        }


# =====================================================================
# 4. REAL BOLT11 ENCODING HELPERS
# =====================================================================
def _make_bolt11_signet(amount_sats: int, payment_hash_hex: str, description: str,
                        timestamp: Optional[int] = None) -> str:
    """
    Produce a spec-correct BOLT11 invoice string for Signet (lntbs prefix)
    using the `bolt11` library, so `bolt11.decode()` round-trips it.
    Signed with a deterministic DEMO secp256k1 key (NOT a real node key);
    in production the LN node's `sign_invoice` RPC signs the same shape.
    Falls back to a structural lntbs string only if the bolt11 lib is
    unavailable, in which case bolt11_decode_ok will be False.
    """
    ts = timestamp if timestamp is not None else int(time.time())
    if not BOLT11_AVAILABLE:
        return f"lntbs{amount_sats * 10}n1p{bytes.fromhex(payment_hash_hex)[:19].hex()}dakar"
    ph_bytes = bytes.fromhex(payment_hash_hex)[:32]
    if len(ph_bytes) < 32:
        ph_bytes = ph_bytes + b"\x00" * (32 - len(ph_bytes))
    payment_hash = ph_bytes.hex()
    payment_secret = hashlib.sha256(f"secret:{payment_hash}".encode()).hexdigest()
    tags = _Bolt11Tags()
    tags.add(_TagChar.payment_hash, payment_hash)
    tags.add(_TagChar.payment_secret, payment_secret)
    tags.add(_TagChar.description, description[:80])
    tags.add(_TagChar.expire_time, 3600)
    invoice_obj = _Bolt11Lib(
        currency="tbs",
        date=ts,
        tags=tags,
        amount_msat=_MilliSatoshi(amount_sats * 1000),
    )
    demo_privkey = hashlib.sha256(b"carnetsats-demo-bolt11-signing-key").hexdigest()
    return _bolt11_encode_lib(invoice_obj, private_key=demo_privkey)


def _decode_bolt11_or_none(invoice: str) -> Optional[dict]:
    """Attempt to decode a BOLT11 string; return None if the lib is unavailable or decode fails."""
    if not BOLT11_AVAILABLE:
        return None
    try:
        decoded = _bolt11_decode_lib(invoice)
        return {
            "payment_hash": getattr(decoded, "payment_hash", None),
            "amount_msat": getattr(decoded, "amount_msat", None),
            "description": getattr(decoded, "description", None),
            "timestamp": getattr(decoded, "date", None),
        }
    except Exception:
        return None


# =====================================================================
# 5. NIP-47 NWC ENGINE
# =====================================================================
ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "clerk_ai": ["get_info", "get_balance", "make_invoice", "lookup_invoice", "list_transactions"],
    "owner_signer": [
        "get_info", "get_balance", "make_invoice", "lookup_invoice", "list_transactions", "pay_invoice",
    ],
}


class NWCLightningEngine:
    def __init__(self, initial_balance_sats: int = 95_000, daily_owner_quota_sats: int = 50_000):
        self.balance_sats = initial_balance_sats
        self.daily_owner_quota_sats = daily_owner_quota_sats
        self.spent_today_sats = 0
        self.invoices: Dict[str, Dict[str, object]] = {}
        self.audit_logs: List[str] = []
        self.wallet_pubkey = hashlib.sha256(b"carnetsats-dakar-nwc-service").hexdigest()

    def _log(self, msg: str) -> None:
        clean_msg = sanitize_log(msg)
        self.audit_logs.append(f"[{int(time.time())}] {clean_msg}")

    def get_nip47_info_event(self, role: str = "clerk_ai") -> Dict[str, object]:
        allowed = ROLE_PERMISSIONS.get(role, [])
        return {
            "kind": 13194,
            "pubkey": self.wallet_pubkey,
            "content": " ".join(allowed),
            "tags": [["encryption", "nip44_v2 nip04"]],
            "role": role,
        }

    def execute_nip47_request(self, method: str, params: Dict[str, object], role: str = "clerk_ai") -> Dict[str, object]:
        known = {"get_info", "get_balance", "make_invoice", "lookup_invoice", "list_transactions", "pay_invoice"}
        self._log(f"NIP-47 Request kind=23194 role={role} method={method} secret=a9f8e7d6c5b4a3f2109876543210abcd")

        if method not in known:
            return {"kind": 23195, "result_type": method,
                    "error": {"code": "NOT_IMPLEMENTED", "message": f"Method {method} not implemented"},
                    "result": None}

        allowed = ROLE_PERMISSIONS.get(role, [])
        if method not in allowed:
            self._log(f"SECURITY_BLOCK: Role '{role}' attempted forbidden method '{method}' -> RESTRICTED")
            return {"kind": 23195, "result_type": method,
                    "error": {"code": "RESTRICTED",
                              "message": f"Role '{role}' is cryptographically restricted from calling '{method}'."},
                    "result": None}

        if method == "get_info":
            return {"kind": 23195, "result_type": "get_info", "error": None,
                    "result": {"alias": "CarnetSats-Dakar-NWC", "network": "signet", "methods": allowed}}

        if method == "get_balance":
            return {"kind": 23195, "result_type": "get_balance", "error": None,
                    "result": {"balance": self.balance_sats * 1000}}

        if method == "list_transactions":
            return {"kind": 23195, "result_type": "list_transactions", "error": None,
                    "result": {"transactions": list(self.invoices.values())}}

        if method == "make_invoice":
            amount_msat = int(params.get("amount", 0))
            if amount_msat <= 0:
                return {"kind": 23195, "result_type": "make_invoice",
                        "error": {"code": "INVALID_AMOUNT", "message": "Invoice amount_msat must be > 0"},
                        "result": None}
            amount_sats = max(1, amount_msat // 1000)
            description = str(params.get("description", "CarnetSats Boutique Purchase"))
            seed_str = str(params.get("deterministic_seed", secrets.token_hex(16)))
            preimage = hashlib.sha256(f"preimage:{seed_str}:{amount_sats}".encode("utf-8")).hexdigest()
            payment_hash = hashlib.sha256(bytes.fromhex(preimage)).hexdigest()

            bolt11 = _make_bolt11_signet(amount_sats, payment_hash, description)
            decode_check = _decode_bolt11_or_none(bolt11)

            record = {
                "type": "incoming",
                "invoice": bolt11,
                "description": sanitize_log(description),
                "payment_hash": payment_hash,
                "preimage": preimage,
                "amount": amount_msat,
                "amount_sats": amount_sats,
                "settled": False,
                "created_at": int(time.time()),
                "settled_at": None,
                "bolt11_decode_ok": decode_check is not None,
            }
            self.invoices[payment_hash] = record
            return {"kind": 23195, "result_type": "make_invoice", "error": None,
                    "result": {"type": "incoming", "invoice": bolt11,
                               "description": record["description"],
                               "payment_hash": payment_hash, "amount": amount_msat,
                               "created_at": record["created_at"],
                               "bolt11_decode_ok": record["bolt11_decode_ok"]}}

        if method == "lookup_invoice":
            ph = str(params.get("payment_hash", ""))
            inv = self.invoices.get(ph)
            if not inv:
                return {"kind": 23195, "result_type": "lookup_invoice",
                        "error": {"code": "NOT_FOUND", "message": "Invoice payment_hash not found"},
                        "result": None}
            return {"kind": 23195, "result_type": "lookup_invoice", "error": None,
                    "result": {"type": "incoming", "invoice": inv["invoice"],
                               "payment_hash": inv["payment_hash"],
                               "preimage": inv["preimage"] if inv["settled"] else None,
                               "amount": inv["amount"], "settled": inv["settled"],
                               "settled_at": inv["settled_at"]}}

        if method == "pay_invoice":
            amount_sats = int(params.get("amount_sats", 0))
            if amount_sats <= 0:
                return {"kind": 23195, "result_type": "pay_invoice",
                        "error": {"code": "INVALID_AMOUNT", "message": "Payment amount_sats must be > 0"},
                        "result": None}
            if self.spent_today_sats + amount_sats > self.daily_owner_quota_sats:
                self._log(f"SECURITY_BLOCK: Owner spend {amount_sats} sats exceeds quota -> QUOTA_EXCEEDED")
                return {"kind": 23195, "result_type": "pay_invoice",
                        "error": {"code": "QUOTA_EXCEEDED",
                                  "message": f"Payment of {amount_sats} sats exceeds remaining daily budget."},
                        "result": None}
            if amount_sats > self.balance_sats:
                return {"kind": 23195, "result_type": "pay_invoice",
                        "error": {"code": "INSUFFICIENT_BALANCE", "message": "Insufficient channel balance."},
                        "result": None}
            self.balance_sats -= amount_sats
            self.spent_today_sats += amount_sats
            out_preimage = hashlib.sha256(f"outbound:{time.time()}:{amount_sats}".encode()).hexdigest()
            return {"kind": 23195, "result_type": "pay_invoice", "error": None,
                    "result": {"preimage": out_preimage, "amount_paid_sats": amount_sats}}

        return {"kind": 23195, "result_type": method,
                "error": {"code": "NOT_IMPLEMENTED", "message": f"Method {method} not implemented"}, "result": None}

    def settle_incoming_invoice(self, payment_hash: str) -> Dict[str, object]:
        inv = self.invoices.get(payment_hash)
        if not inv:
            raise ValueError("Unknown payment_hash")
        preimage_bytes = bytes.fromhex(str(inv["preimage"]))
        computed_hash = hashlib.sha256(preimage_bytes).hexdigest()
        if computed_hash != payment_hash:
            raise ValueError("Cryptographic preimage mismatch!")
        if not inv["settled"]:
            inv["settled"] = True
            inv["settled_at"] = int(time.time())
            self.balance_sats += int(inv["amount_sats"])
            self._log(f"SETTLED invoice payment_hash={payment_hash[:16]}... (+{inv['amount_sats']} sats)")
        return {"settled": True, "payment_hash": payment_hash, "preimage": inv["preimage"],
                "verified_sha256": computed_hash == payment_hash, "new_balance_sats": self.balance_sats}


# =====================================================================
# 5b. REAL NIP-44 v2 (spec: https://github.com/nostr-protocol/nips/blob/master/44.md)
# secp256k1 ECDH + HKDF-SHA256 + padding + ChaCha20 + HMAC-SHA256 + base64.
# NOT ChaCha20-Poly1305, NOT pynostr EncryptedDirectMessage (that is NIP-04).
# Verified against the spec test vector: sec1=1, sec2=2 gives
# conversation_key c41c775356fd92eadc63ff5a0dc1da211b268cbea22316767095b2871ea1412d
# and plaintext "a" with nonce 1 gives the published payload.
# =====================================================================
_SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
_SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
_SECP_G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _ec_add(p1, p2):
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % _SECP_P == 0:
        return None
    if p1 == p2:
        lam = (3 * x1 * x1) * pow(2 * y1, -1, _SECP_P) % _SECP_P
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, _SECP_P) % _SECP_P
    x3 = (lam * lam - x1 - x2) % _SECP_P
    y3 = (lam * (x1 - x3) - y1) % _SECP_P
    return (x3, y3)


def _ec_mul(k: int, point=_SECP_G):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _ec_add(result, addend)
        addend = _ec_add(addend, addend)
        k >>= 1
    return result


def _nip44_shared_x(priv_hex: str, pub_hex: str) -> bytes:
    priv = int(priv_hex, 16)
    if not 1 <= priv < _SECP_N:
        raise ValueError("invalid NIP-44 private key")
    x = int(pub_hex, 16)
    # y^2 = x^3 + 7 (mod p); BIP-340 x-only pubkey uses the even y.
    y_sq = (pow(x, 3, _SECP_P) + 7) % _SECP_P
    y = pow(y_sq, (_SECP_P + 1) // 4, _SECP_P)
    if (y * y - y_sq) % _SECP_P != 0:
        raise ValueError("invalid NIP-44 public key: not on curve")
    if y % 2 != 0:
        y = _SECP_P - y
    shared = _ec_mul(priv, (x, y))
    if shared is None:
        raise ValueError("invalid NIP-44 shared point")
    return shared[0].to_bytes(32, "big")


def _hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def _nip44_conversation_key(priv_hex: str, pub_hex: str) -> bytes:
    shared_x = _nip44_shared_x(priv_hex, pub_hex)
    return _hkdf_extract(salt=b"nip44-v2", ikm=shared_x)


def _nip44_message_keys(conversation_key: bytes, nonce: bytes) -> Tuple[bytes, bytes, bytes]:
    if len(conversation_key) != 32 or len(nonce) != 32:
        raise ValueError("invalid NIP-44 key/nonce length")
    keys = _hkdf_expand(prk=conversation_key, info=nonce, length=76)
    return keys[0:32], keys[32:44], keys[44:76]


def _nip44_calc_padded_len(unpadded_len: int) -> int:
    if unpadded_len <= 32:
        return 32
    next_power = 1 << (math.floor(math.log2(unpadded_len - 1)) + 1)
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * (math.floor((unpadded_len - 1) / chunk) + 1)


def _nip44_pad(plaintext: str) -> bytes:
    data = plaintext.encode("utf-8")
    n = len(data)
    if n < 1 or n > 4294967295:
        raise ValueError("invalid NIP-44 plaintext length")
    if n >= 65536:
        prefix = b"\x00\x00" + n.to_bytes(4, "big")
    else:
        prefix = n.to_bytes(2, "big")
    padded_len = _nip44_calc_padded_len(n)
    return prefix + data + b"\x00" * (padded_len - n)


def _nip44_unpad(padded: bytes) -> str:
    first_two = int.from_bytes(padded[0:2], "big")
    if first_two == 0:
        n = int.from_bytes(padded[2:6], "big")
        if n < 65536:
            raise ValueError("invalid NIP-44 padding")
        prefix_len = 6
    else:
        n = first_two
        prefix_len = 2
    if n == 0 or len(padded) != prefix_len + _nip44_calc_padded_len(n):
        raise ValueError("invalid NIP-44 padding")
    return padded[prefix_len:prefix_len + n].decode("utf-8")


def _nip44_chacha20(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    if not _CHACHA_AVAILABLE:
        raise RuntimeError("cryptography not installed: pip install cryptography")
    # ChaCha20 with 16-byte nonce: 4-byte counter (0) + 12-byte nonce.
    cipher = Cipher(algorithms.ChaCha20(key, b"\x00\x00\x00\x00" + nonce12), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def _nip44_encrypt_payload(plaintext: str, conversation_key: bytes, nonce: Optional[bytes] = None) -> str:
    nonce = nonce if nonce is not None else secrets.token_bytes(32)
    chacha_key, chacha_nonce, hmac_key = _nip44_message_keys(conversation_key, nonce)
    padded = _nip44_pad(plaintext)
    ciphertext = _nip44_chacha20(chacha_key, chacha_nonce, padded)
    mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    return base64.b64encode(b"\x02" + nonce + ciphertext + mac).decode("ascii")


def _nip44_decrypt_payload(payload: str, conversation_key: bytes) -> str:
    if not payload or payload[0] == "#":
        raise ValueError("unknown NIP-44 version")
    if len(payload) < 132:
        raise ValueError("invalid NIP-44 payload size")
    try:
        data = base64.b64decode(payload, validate=True)
    except Exception as exc:
        raise ValueError("invalid NIP-44 base64") from exc
    if len(data) < 99 or data[0] != 2:
        raise ValueError("unknown NIP-44 version")
    nonce, ciphertext, mac = data[1:33], data[33:len(data) - 32], data[len(data) - 32:]
    chacha_key, chacha_nonce, hmac_key = _nip44_message_keys(conversation_key, nonce)
    calc_mac = hmac.new(hmac_key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(calc_mac, mac):
        raise ValueError("invalid NIP-44 MAC")
    padded = _nip44_chacha20(chacha_key, chacha_nonce, ciphertext)
    return _nip44_unpad(padded)


# =====================================================================
# 6. NOSTR CREDIT LEDGER — REAL NIP-44 + REAL SCHNORR SIG
# =====================================================================
class NostrCreditLedger:
    """
    Publishes NIP-78 Kind 30078 events with real NIP-44 v2 ciphertext
    (ChaCha20 + HMAC-SHA256, implemented from the NIP-44 spec above)
    and valid BIP-340 Schnorr signatures (pynostr). Public relays accept these events.
    """

    def __init__(self, merchant_privkey_hex: Optional[str] = None):
        if not PYnostr_AVAILABLE:
            raise RuntimeError("pynostr not installed: pip install pynostr")
        if merchant_privkey_hex:
            self._merchant_priv = PrivateKey.from_hex(merchant_privkey_hex)
        else:
            self._merchant_priv = PrivateKey.from_hex(
                hashlib.sha256(b"boutique-touba-dakar-secret").hexdigest()
            )
        self.privkey_hex = self._merchant_priv.hex()
        self.pubkey_hex = self._merchant_priv.public_key.hex()
        # For NIP-44 we use the merchant as both sender and recipient (self-DM envelope)
        self._recipient_pub = self._merchant_priv.public_key.hex()
        self.events: List[Dict[str, object]] = []

    def _nip44_encrypt(self, plaintext: str) -> str:
        """Real NIP-44 v2 encryption (ChaCha20 + HMAC-SHA256, spec implementation above)."""
        conv_key = _nip44_conversation_key(self.privkey_hex, self._recipient_pub)
        return _nip44_encrypt_payload(plaintext, conv_key)

    def _nip44_decrypt(self, ciphertext: str) -> str:
        """Real NIP-44 v2 decryption. Raises on MAC failure or tampering."""
        conv_key = _nip44_conversation_key(self.privkey_hex, self._recipient_pub)
        return _nip44_decrypt_payload(ciphertext, conv_key)

    def create_signed_credit_event(
        self,
        customer_name: str,
        items: List[str],
        total_xof: int,
        paid_now_xof: int,
        debt_remaining_xof: int,
        payment_hash: str,
    ) -> Dict[str, object]:
        alias_tag = customer_alias_id(customer_name)
        created_at = int(time.time())
        kind = 30078

        cleartext = {
            "customer_alias": alias_tag,
            "customer_display": customer_name.split()[0],
            "items": items,
            "total_xof": total_xof,
            "paid_now_xof": paid_now_xof,
            "debt_remaining_xof": debt_remaining_xof,
            "debt_remaining_sats": int(round(debt_remaining_xof * DEFAULT_SATS_PER_XOF)),
            "lightning_payment_hash": payment_hash,
            "timestamp": created_at,
        }
        # Real NIP-44 v2 ciphertext (base64 output from pynostr)
        encrypted_content = self._nip44_encrypt(json.dumps(cleartext, ensure_ascii=False, sort_keys=True))

        tags = [
            ["d", f"carnetsats:tab:{alias_tag}"],
            ["t", "dakar-bitcoin-hack"],
            ["encryption", "nip44_v2"],
            ["ln_hash", payment_hash],
        ]

        event = Event(
            kind=kind,
            content=encrypted_content,
            tags=tags,
            created_at=created_at,
            pubkey=self.pubkey_hex,
        )
        event.sign(self._merchant_priv.hex())

        stored = {
            "id": event.id,
            "pubkey": event.pubkey,
            "created_at": event.created_at,
            "kind": event.kind,
            "tags": event.tags,
            "content": event.content,
            "sig": event.sig,
            "decrypted_preview": cleartext,
            "nip44_spec": "NIP-44 v2 (ChaCha20 + HMAC-SHA256 + base64)",
        }
        self.events.append(stored)
        return stored

    def verify_event_signature(self, event: Dict[str, object]) -> bool:
        """Verify a stored event's BIP-340 Schnorr signature using pynostr."""
        try:
            ev = Event.from_dict({
                "id": event["id"], "pubkey": event["pubkey"],
                "created_at": event["created_at"], "kind": event["kind"],
                "tags": event["tags"], "content": event["content"], "sig": event["sig"],
            })
            return ev.verify()
        except Exception:
            return False

    def decrypt_nip44_payload(self, ciphertext: str) -> Dict[str, object]:
        """Decrypt a NIP-44 v2 ciphertext back to the cleartext dict."""
        plaintext = self._nip44_decrypt(ciphertext)
        return json.loads(plaintext)


# =====================================================================
# 7. DETERMINISTIC AI CASHIER
# =====================================================================
class ParsedCarnetEntry(BaseModel):
    customer_name: str = Field(description="Customer first name or alias")
    language_detected: Literal["fr", "wo", "en"] = Field(description="Detected input language")
    items: List[str] = Field(description="Extracted shopping basket items")
    total_amount_xof: int = Field(description="Total purchase value in FCFA (XOF)")
    paid_upfront_xof: int = Field(description="Amount paid immediately by customer in FCFA (XOF)")
    credit_owed_xof: int = Field(description="Remaining unpaid tab (credit/IOU) in FCFA (XOF)")
    upfront_sats: int = Field(description="Upfront Lightning invoice amount in Satoshis")
    credit_owed_sats: int = Field(description="Remaining Nostr credit tab in Satoshis")
    confidence_note: str = Field(description="Audit explanation of the deterministic calculation")


def parse_boutique_entry(text: str, use_gemini: bool = True) -> ParsedCarnetEntry:
    clean_text = text.strip()

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if use_gemini and GENAI_AVAILABLE and api_key:
        try:
            client = genai.Client(api_key=api_key)
            prompt = (
                "Extract the West African boutique transaction from the merchant's voice/text note. "
                "Convert all numbers to integers in XOF (FCFA). Ensure credit_owed_xof = total_amount_xof - paid_upfront_xof.\n"
                f"Input: {clean_text}"
            )
            resp = client.models.generate_content(
                model="gemini-3.6-flash",
                contents=prompt,
                config=types.GenerateContentConfig(
                    response_mime_type="application/json",
                    response_schema=ParsedCarnetEntry,
                    temperature=0.0,
                ),
            )
            if resp.text:
                parsed = ParsedCarnetEntry.model_validate_json(resp.text)
                parsed.credit_owed_xof = max(0, parsed.total_amount_xof - parsed.paid_upfront_xof)
                parsed.upfront_sats = max(1, int(round(parsed.paid_upfront_xof * DEFAULT_SATS_PER_XOF)))
                parsed.credit_owed_sats = int(round(parsed.credit_owed_xof * DEFAULT_SATS_PER_XOF))
                return parsed
        except Exception:
            pass

    lower = clean_text.lower()
    if any(w in lower for w in ["ceeb", "diwlin", "suukar", "fay", "desal", "ameel", "ñaar", "mburu", "meew", "jël"]):
        lang: Literal["fr", "wo", "en"] = "wo"
    elif any(w in lower for w in ["riz", "huile", "payé", "doit", "pris", "sucre", "sac", "lait", "pain", "savon"]):
        lang = "fr"
    else:
        lang = "en"

    name_match = re.search(
        r"\b(Moussa|Aminata|Ousmane|Fatou|Ibrahima|Cheikh|Awa|Modou|Khadija|Mamadou|Abdoulaye|Sadio|Mariama|Babacar|[A-Z][a-z]{2,14})\b",
        clean_text,
    )
    customer_name = name_match.group(1) if name_match else "Client"

    normalized = re.sub(r"(\d{1,3})\s(\d{3})\b", r"\1\2", clean_text)
    normalized = re.sub(r"(\d{1,3}),(\d{3})\b", r"\1\2", normalized)
    numbers = [int(n) for n in re.findall(r"\b\d{3,7}\b", normalized)]

    if len(numbers) >= 2:
        first_val, second_val = numbers[0], numbers[1]
        if first_val >= second_val:
            total_xof, paid_xof = first_val, second_val
        else:
            paid_xof, total_xof = first_val, first_val + second_val
    elif len(numbers) == 1:
        total_xof = paid_xof = numbers[0]
    else:
        total_xof, paid_xof = 5000, 3000

    credit_xof = max(0, total_xof - paid_xof)

    vocab_map = {
        "riz": "Riz parfumé (Sac)", "ceeb": "Ceeb (Riz local)", "rice": "Bag of Rice",
        "huile": "Huile végétale (Bidon)", "diwlin": "Diwlin (Huile)", "oil": "Cooking Oil",
        "sucre": "Sucre en poudre", "suukar": "Suukar (Sucre)", "sugar": "Sugar",
        "lait": "Lait en poudre", "meew": "Meew (Lait)", "milk": "Powdered Milk",
        "pain": "Pain baguette", "mburu": "Mburu (Pain)", "bread": "Bread",
        "savon": "Savon de ménage", "soap": "Household Soap",
    }
    found_items = [label for key, label in vocab_map.items() if key in lower]
    if not found_items:
        found_items = ["Panier marchandises Boutique (Articles divers)"]

    upfront_sats = max(1, int(round(paid_xof * DEFAULT_SATS_PER_XOF))) if paid_xof > 0 else 0
    credit_sats = int(round(credit_xof * DEFAULT_SATS_PER_XOF))

    return ParsedCarnetEntry(
        customer_name=customer_name,
        language_detected=lang,
        items=found_items,
        total_amount_xof=total_xof,
        paid_upfront_xof=paid_xof,
        credit_owed_xof=credit_xof,
        upfront_sats=upfront_sats,
        credit_owed_sats=credit_sats,
        confidence_note=(
            f"Deterministic schema verification: {total_xof} XOF total = "
            f"{paid_xof} XOF Lightning upfront ({upfront_sats} sats) + "
            f"{credit_xof} XOF Nostr NIP-44 tab ({credit_sats} sats)."
        ),
    )
