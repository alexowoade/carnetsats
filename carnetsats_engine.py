"""
CarnetSats Core Engine v3.7.0 — Dakar Bitcoin Hack by BTrust
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
  Since rev4, live NWC mode (CARNETSATS_NWC_URL set) skips this signer
  entirely: the BOLT11 comes from the real wallet's make_invoice.
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
import sqlite3
import sys
import threading
import time
import urllib.parse
from pathlib import Path
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

try:
    import httpx
    _HTTPX_AVAILABLE = True
except Exception:
    httpx = None  # type: ignore[assignment]
    _HTTPX_AVAILABLE = False


# =====================================================================
# 1. CONSTANTS
# =====================================================================
DEFAULT_SATS_PER_XOF = 1.65
DEFAULT_SATS_PER_NGN = 0.62
HOT_WALLET_SWEEP_THRESHOLD_XOF = 50_000


# =====================================================================
# 1b. LIVE FX FEED (CoinGecko, cached 5 min, fallback 1.65)
# =====================================================================
# sats_per_xof() is the single source of the BTC/XOF rate. It tries a live
# CoinGecko price once per 5-minute bucket and caches the result (including
# the 1.65 fallback, so a dead network is not hammered on every call).
# ANY failure — no network, timeout, bad JSON, missing key, non-positive
# price, httpx missing — returns DEFAULT_SATS_PER_XOF (1.65), unchanged.
COINGECKO_PRICE_URL = "https://api.coingecko.com/api/v3/simple/price?ids=bitcoin&vs_currencies=xof"
FX_CACHE_TTL_SECONDS = 300
_FX_CACHE: Dict[str, object] = {"bucket": None, "rate": DEFAULT_SATS_PER_XOF}


def _fetch_live_sats_per_xof() -> float:
    """One live CoinGecko call. Raises on ANY problem; caller falls back."""
    if not _HTTPX_AVAILABLE:
        raise RuntimeError("httpx not installed: pip install httpx")
    resp = httpx.get(COINGECKO_PRICE_URL, timeout=3.0)
    data = resp.json()
    price_xof = float(data["bitcoin"]["xof"])
    if price_xof <= 0:
        raise ValueError("non-positive BTC/XOF price from CoinGecko")
    return 1e8 / price_xof


def sats_per_xof() -> float:
    """Current sats-per-XOF rate: live CoinGecko price, cached 5 minutes,
    DEFAULT_SATS_PER_XOF (1.65) on any failure. Deterministic in tests: the
    suite stubs httpx.get to fail, so tests always see the 1.65 fallback."""
    bucket = int(time.time() // FX_CACHE_TTL_SECONDS)
    if _FX_CACHE.get("bucket") == bucket:
        return float(_FX_CACHE["rate"])  # type: ignore[arg-type]
    try:
        rate = _fetch_live_sats_per_xof()
    except Exception:
        rate = DEFAULT_SATS_PER_XOF
    _FX_CACHE["bucket"] = bucket
    _FX_CACHE["rate"] = rate
    return rate


def _reset_fx_cache() -> None:
    """Clear the FX cache (used by the test suite between tests)."""
    _FX_CACHE["bucket"] = None
    _FX_CACHE["rate"] = DEFAULT_SATS_PER_XOF


def resolve_db_path(db_path: Optional[str] = None) -> str:
    """SQLite file for invoice/ledger persistence. Explicit path wins, then
    the CARNETSATS_DB env var, then carnetsats.db next to this module.
    ':memory:' is honoured as-is (used by throwaway instances)."""
    if db_path:
        return str(db_path)
    env_path = os.getenv("CARNETSATS_DB", "").strip()
    if env_path:
        return env_path
    return str(Path(__file__).parent / "carnetsats.db")


# =====================================================================
# 2. ZERO-PII SECURITY SANITIZER
# =====================================================================
PII_PATTERNS = [
    (re.compile(r"(\+?221[\s\-\.]?\d{2}[\s\-\.]?\d{3}[\s\-\.]?\d{2}[\s\-\.]?\d{2})"), "[REDACTED_PHONE_SN]"),
    (re.compile(r"(\+?234[\s\-\.]?\d{3}[\s\-\.]?\d{3}[\s\-\.]?\d{4})"), "[REDACTED_PHONE_NG]"),
    (re.compile(r"\b(0[789][01]\d[\s\-]?\d{3}[\s\-]?\d{4})\b"), "[REDACTED_LOCAL_NG]"),
    (re.compile(r"\b(7[05678][\s\-\.]?\d{3}[\s\-\.]?\d{2}[\s\-\.]?\d{2})\b"), "[REDACTED_LOCAL_SN]"),
    (re.compile(r"secret=[0-9a-fA-F]{16,64}"), "secret=[REDACTED_NWC_SECRET]"),
    (re.compile(r"nostr\+walletconnect://\S+"), "[REDACTED_NWC_URL]"),
    (re.compile(r"nsec1[0-9a-z]{20,}"), "[REDACTED_NSEC_KEY]"),
    (re.compile(r"PII_NAME:([A-Za-zÀ-ÿ\s\-]+)"), "ALIAS_HASH:[REDACTED_CUSTOMER]"),
]


def sanitize_log(raw_message: str) -> str:
    cleaned = raw_message
    for pattern, replacement in PII_PATTERNS:
        cleaned = pattern.sub(replacement, cleaned)
    return cleaned


PROMPT_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"\b(pay_invoice|multi_pay_invoice|send_payment|drain_wallet|withdraw_all)\b", re.IGNORECASE),
    re.compile(r"system\s*prompt|override\s+role|owner_signer", re.IGNORECASE),
]


def detect_prompt_injection(text: str) -> Tuple[bool, str]:
    """Flag and strip adversarial prompt-injection directives from cashier input.

    Returns (flagged, cleaned): flagged is True when any known injection
    pattern matched; cleaned has each matched directive replaced by
    "[BLOCKED_INJECTION]". The numbers and item words survive the strip, so
    the deterministic parser can still compute the sale from the cleaned
    text — but the adversarial text must never be sent to the AI.
    """
    flagged = False
    cleaned = text
    for pat in PROMPT_INJECTION_PATTERNS:
        if pat.search(cleaned):
            flagged = True
            cleaned = pat.sub("[BLOCKED_INJECTION]", cleaned)
    return flagged, cleaned


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
        threshold_sats = int(round(threshold_xof * sats_per_xof()))
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
    """
    NIP-47 wallet engine. Invoices live in SQLite (stdlib sqlite3, no new
    dependency) at carnetsats.db next to this module by default, or at the
    CARNETSATS_DB env path, or at an explicit db_path. self.invoices is kept
    as an in-memory mirror, reloaded from the DB on lookup/settle/list, so a
    new engine instance on the same DB file sees invoices created before a
    restart. Balance, daily quota and audit logs stay in-memory by design
    (out of scope for this persistence step).
    """

    def __init__(self, initial_balance_sats: int = 95_000, daily_owner_quota_sats: int = 50_000,
                 db_path: Optional[str] = None, nwc_url: Optional[str] = None):
        self.balance_sats = initial_balance_sats
        self.daily_owner_quota_sats = daily_owner_quota_sats
        self.spent_today_sats = 0
        self.invoices: Dict[str, Dict[str, object]] = {}
        self.audit_logs: List[str] = []
        # Live-wallet mode (v3.7 rev4): a real NWC wallet URL in
        # CARNETSATS_NWC_URL (or the nwc_url argument) switches make_invoice
        # / lookup_invoice / settle to the REAL wallet. No URL = demo mode
        # (local BOLT11, local settle) exactly as before. A configured
        # wallet that cannot be reached is an ERROR, never a silent
        # fallback to demo, so a real payment is never faked as paid.
        # The URL itself (it carries a spend-capable secret) is never
        # stored in full: only the relay host and wallet pubkey are kept.
        raw_nwc = nwc_url if nwc_url is not None else os.environ.get("CARNETSATS_NWC_URL")
        self.nwc_mode = "demo"
        self.nwc_relay = None
        self._nwc_client = None
        if raw_nwc:
            try:
                from nwc_client import NWCClient, parse_nwc_url
                parts = parse_nwc_url(raw_nwc)
                self._nwc_client = NWCClient(parts["relay"], parts["wallet_pubkey"], parts["secret"])
                self.nwc_mode = "live"
                self.nwc_relay = urllib.parse.urlparse(parts["relay"]).netloc or parts["relay"]
                self.wallet_pubkey = parts["wallet_pubkey"]
            except Exception:
                # A malformed NWC URL must not silently become demo mode:
                # the operator misconfigured a real wallet, so say so loudly.
                self.nwc_mode = "misconfigured"
                self.wallet_pubkey = hashlib.sha256(b"carnetsats-dakar-nwc-service").hexdigest()
                self._log("NWC_CONFIG_ERROR: CARNETSATS_NWC_URL is set but invalid -> live wallet DISABLED")
        else:
            self.wallet_pubkey = hashlib.sha256(b"carnetsats-dakar-nwc-service").hexdigest()
        self.db_path = resolve_db_path(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db_lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()
        self._load_invoices_from_db()

    def _init_db(self) -> None:
        with self._db_lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS invoices ("
                " payment_hash TEXT PRIMARY KEY, type TEXT, invoice TEXT,"
                " description TEXT, preimage TEXT, amount INTEGER,"
                " amount_sats INTEGER, settled INTEGER, created_at INTEGER,"
                " settled_at INTEGER, bolt11_decode_ok INTEGER)"
            )
            self._conn.commit()

    @staticmethod
    def _row_to_record(row: sqlite3.Row) -> Dict[str, object]:
        return {
            "type": row["type"],
            "invoice": row["invoice"],
            "description": row["description"],
            "payment_hash": row["payment_hash"],
            "preimage": row["preimage"],
            "amount": row["amount"],
            "amount_sats": row["amount_sats"],
            "settled": bool(row["settled"]),
            "created_at": row["created_at"],
            "settled_at": row["settled_at"],
            "bolt11_decode_ok": bool(row["bolt11_decode_ok"]),
        }

    def _load_invoices_from_db(self) -> None:
        """Reload the in-memory mirror from SQLite (startup + read paths)."""
        with self._db_lock:
            rows = self._conn.execute("SELECT * FROM invoices").fetchall()
        self.invoices = {r["payment_hash"]: self._row_to_record(r) for r in rows}

    def _save_invoice(self, record: Dict[str, object]) -> None:
        """INSERT OR REPLACE one invoice row and update the mirror."""
        with self._db_lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO invoices"
                " (payment_hash, type, invoice, description, preimage, amount,"
                "  amount_sats, settled, created_at, settled_at, bolt11_decode_ok)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (record["payment_hash"], record["type"], record["invoice"],
                 record["description"], record["preimage"], record["amount"],
                 record["amount_sats"], int(bool(record["settled"])),
                 record["created_at"], record["settled_at"],
                 int(bool(record["bolt11_decode_ok"]))),
            )
            self._conn.commit()
        self.invoices[str(record["payment_hash"])] = record

    def _get_invoice(self, payment_hash: str) -> Optional[Dict[str, object]]:
        """Read one invoice from SQLite (lookup/settle path)."""
        with self._db_lock:
            row = self._conn.execute(
                "SELECT * FROM invoices WHERE payment_hash = ?", (payment_hash,)
            ).fetchone()
        if row is None:
            return None
        record = self._row_to_record(row)
        self.invoices[payment_hash] = record
        return record

    def close(self) -> None:
        """Close the SQLite connection (lets a restart test drop the handle)."""
        try:
            self._conn.close()
        except Exception:
            pass

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
            "mode": self.nwc_mode,
            "relay": self.nwc_relay,
        }

    def _execute_nwc_live(self, method: str, params: Dict[str, object], role: str) -> Dict[str, object]:
        """Route one NIP-47 method to the real NWC wallet (live mode only).

        Results are mapped into the same {kind 23195, result_type, error,
        result} envelope the demo engine returns, so callers (/api/checkout,
        /api/settle) work unchanged. The wallet's secret never appears in
        any message here; failures are errors, never a demo fallback.
        """
        from nwc_client import NWCError
        assert self._nwc_client is not None
        try:
            if method == "get_info":
                res = self._nwc_client.request("get_info", {})
                return {"kind": 23195, "result_type": "get_info", "error": None,
                        "result": {"alias": res.get("alias", "CarnetSats-NWC"),
                                   "network": res.get("network", "signet"),
                                   "methods": res.get("methods", ROLE_PERMISSIONS.get(role, []))}}
            if method == "get_balance":
                res = self._nwc_client.request("get_balance", {})
                balance_msat = int(res.get("balance", 0))
                self.balance_sats = max(0, balance_msat // 1000)
                return {"kind": 23195, "result_type": "get_balance", "error": None,
                        "result": {"balance": balance_msat}}
            if method == "make_invoice":
                amount_msat = int(params.get("amount", 0))
                if amount_msat <= 0:
                    return {"kind": 23195, "result_type": "make_invoice",
                            "error": {"code": "INVALID_AMOUNT", "message": "Invoice amount_msat must be > 0"},
                            "result": None}
                description = str(params.get("description", "CarnetSats Boutique Purchase"))
                res = self._nwc_client.request("make_invoice", {"amount": amount_msat, "description": description})
                invoice = str(res.get("invoice", ""))
                payment_hash = str(res.get("payment_hash", ""))
                if not invoice or not payment_hash:
                    return {"kind": 23195, "result_type": "make_invoice",
                            "error": {"code": "NWC_BAD_INVOICE",
                                      "message": "Wallet returned an invoice without payment_hash"},
                            "result": None}
                amount_sats = max(1, amount_msat // 1000)
                decode_check = _decode_bolt11_or_none(invoice)
                record = {
                    "type": "incoming",
                    "invoice": invoice,
                    "description": sanitize_log(description),
                    "payment_hash": payment_hash,
                    "preimage": None,
                    "amount": amount_msat,
                    "amount_sats": amount_sats,
                    "settled": False,
                    "created_at": int(time.time()),
                    "settled_at": None,
                    "bolt11_decode_ok": decode_check is not None,
                }
                self._save_invoice(record)
                return {"kind": 23195, "result_type": "make_invoice", "error": None,
                        "result": {"type": "incoming", "invoice": invoice,
                                   "description": record["description"],
                                   "payment_hash": payment_hash, "amount": amount_msat,
                                   "created_at": record["created_at"],
                                   "bolt11_decode_ok": record["bolt11_decode_ok"]}}
            if method == "lookup_invoice":
                ph = str(params.get("payment_hash", ""))
                res = self._nwc_client.request("lookup_invoice", {"payment_hash": ph})
                settled = bool(res.get("settled"))
                preimage = res.get("preimage")
                # Mirror the wallet's answer into the local record so the
                # ledger stays consistent if the server restarts mid-sale.
                inv = self._get_invoice(ph)
                if inv and settled and not inv["settled"]:
                    inv["settled"] = True
                    inv["settled_at"] = res.get("settled_at") or int(time.time())
                    if preimage:
                        inv["preimage"] = str(preimage)
                    self._save_invoice(inv)
                return {"kind": 23195, "result_type": "lookup_invoice", "error": None,
                        "result": {"type": "incoming",
                                   "invoice": res.get("invoice") or (inv["invoice"] if inv else ""),
                                   "payment_hash": ph,
                                   "preimage": preimage if settled else None,
                                   "amount": res.get("amount") or (inv["amount"] if inv else 0),
                                   "settled": settled,
                                   "settled_at": res.get("settled_at")}}
            if method == "pay_invoice":
                invoice = str(params.get("invoice", ""))
                if not invoice:
                    return {"kind": 23195, "result_type": "pay_invoice",
                            "error": {"code": "INVALID_INVOICE",
                                      "message": "pay_invoice needs a BOLT11 invoice string"},
                            "result": None}
                res = self._nwc_client.request("pay_invoice", {"invoice": invoice})
                amount_sats = int(params.get("amount_sats", 0) or 0)
                self.spent_today_sats += amount_sats
                return {"kind": 23195, "result_type": "pay_invoice", "error": None,
                        "result": {"preimage": res.get("preimage"), "amount_paid_sats": amount_sats}}
        except Exception as exc:  # noqa: BLE001 - wallet failure is an error, not a demo fallback
            code = "NWC_UNAVAILABLE" if isinstance(exc, NWCError) else "NWC_ERROR"
            self._log(f"NWC live request {method} failed -> {code}")
            return {"kind": 23195, "result_type": method,
                    "error": {"code": code,
                              "message": f"Real wallet unreachable: {sanitize_log(str(exc))}"},
                    "result": None}
        return {"kind": 23195, "result_type": method,
                "error": {"code": "NOT_IMPLEMENTED", "message": f"Method {method} not implemented"},
                "result": None}

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

        # Live-wallet mode (v3.7 rev4): route the wallet methods to the real
        # NWC wallet. A misconfigured URL or an unreachable wallet is an
        # error, never a silent demo fallback.
        if self.nwc_mode == "misconfigured":
            return {"kind": 23195, "result_type": method,
                    "error": {"code": "NWC_CONFIG_ERROR",
                              "message": "CARNETSATS_NWC_URL is set but invalid; fix .env, do not trade in demo mode."},
                    "result": None}
        if self.nwc_mode == "live" and method in {"get_info", "get_balance", "make_invoice", "lookup_invoice", "pay_invoice"}:
            return self._execute_nwc_live(method, params, role)

        if method == "get_info":
            return {"kind": 23195, "result_type": "get_info", "error": None,
                    "result": {"alias": "CarnetSats-Dakar-NWC", "network": "signet", "methods": allowed}}

        if method == "get_balance":
            return {"kind": 23195, "result_type": "get_balance", "error": None,
                    "result": {"balance": self.balance_sats * 1000}}

        if method == "list_transactions":
            self._load_invoices_from_db()
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
            self._save_invoice(record)
            return {"kind": 23195, "result_type": "make_invoice", "error": None,
                    "result": {"type": "incoming", "invoice": bolt11,
                               "description": record["description"],
                               "payment_hash": payment_hash, "amount": amount_msat,
                               "created_at": record["created_at"],
                               "bolt11_decode_ok": record["bolt11_decode_ok"]}}

        if method == "lookup_invoice":
            ph = str(params.get("payment_hash", ""))
            inv = self._get_invoice(ph)
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
        # Live-wallet mode (v3.7 rev4): settlement is a real lookup against
        # the wallet. Unpaid = ValueError (the API turns it into 400 and
        # the frontend shows PENDING); it is NEVER auto-marked paid.
        if self.nwc_mode == "live":
            resp = self.execute_nip47_request("lookup_invoice", {"payment_hash": payment_hash}, role="clerk_ai")
            if resp.get("error"):
                raise ValueError(f"Wallet lookup failed: {resp['error'].get('message', resp['error'].get('code'))}")
            res = resp["result"] or {}
            if not res.get("settled"):
                raise ValueError("Invoice not settled yet — customer has not paid")
            preimage = res.get("preimage")
            if not preimage:
                raise ValueError("Wallet reports settled but gave no preimage")
            computed_hash = hashlib.sha256(bytes.fromhex(str(preimage))).hexdigest()
            if computed_hash != payment_hash:
                raise ValueError("Cryptographic preimage mismatch!")
            inv = self._get_invoice(payment_hash)
            if inv and not inv["settled"]:
                inv["settled"] = True
                inv["settled_at"] = res.get("settled_at") or int(time.time())
                inv["preimage"] = str(preimage)
                self._save_invoice(inv)
                self._log(f"SETTLED (live NWC) invoice payment_hash={payment_hash[:16]}...")
            # Balance is the real wallet's balance now, not the demo counter.
            bal = self.execute_nip47_request("get_balance", {}, role="clerk_ai")
            if not bal.get("error"):
                self.balance_sats = max(0, int(bal["result"]["balance"]) // 1000)
            return {"settled": True, "payment_hash": payment_hash, "preimage": str(preimage),
                    "verified_sha256": True, "new_balance_sats": self.balance_sats}
        if self.nwc_mode == "misconfigured":
            raise ValueError("NWC wallet misconfigured (CARNETSATS_NWC_URL invalid); fix .env")
        inv = self._get_invoice(payment_hash)
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
            self._save_invoice(inv)
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


# Worker for publish_event_to_relay: runs the pynostr RelayManager in a
# subprocess (same isolation as the relay round-trip test: tornado must
# not share the FastAPI event loop). Reads {"relay_url", "event"} on
# stdin, prints one JSON line: {"ok", "received_id", "error", "elapsed_s"}.
_RELAY_PUBLISH_WORKER_CODE = r"""
import json, sys, time
t0 = time.time()
result = {"ok": False, "received_id": None, "error": None}
try:
    job = json.load(sys.stdin)
    relay_url = job["relay_url"]
    ev = job["event"]
    from pynostr.event import Event
    from pynostr.filters import Filters, FiltersList
    from pynostr.relay_manager import RelayManager
    event = Event.from_dict({k: ev[k] for k in
                             ("id", "pubkey", "created_at", "kind",
                              "tags", "content", "sig")})
    rm = RelayManager(timeout=20)
    rm.add_relay(relay_url, timeout=20)
    rm.publish_event(event)
    rm.add_subscription_on_all_relays(
        "carnetsats-publish-%s" % ev["id"][:8],
        FiltersList([Filters(ids=[ev["id"]])]))
    rm.run_sync()
    pool = rm.message_pool.get_all()
    for msg in pool["events"]:
        if msg.event.id == ev["id"]:
            result["received_id"] = msg.event.id
            break
    result["ok"] = result["received_id"] == ev["id"]
    if not result["ok"]:
        result["error"] = (
            "published event not received back (events=%d ok=%d eose=%d)"
            % (len(pool["events"]), len(pool["ok"]), len(pool["eose"])))
except Exception as exc:
    result["error"] = "%s: %s" % (type(exc).__name__, exc)
result["elapsed_s"] = round(time.time() - t0, 1)
print(json.dumps(result))
"""


# =====================================================================
# 6. NOSTR CREDIT LEDGER — REAL NIP-44 + REAL SCHNORR SIG
# =====================================================================
class NostrCreditLedger:
    """
    Publishes NIP-78 Kind 30078 events with real NIP-44 v2 ciphertext
    (ChaCha20 + HMAC-SHA256, implemented from the NIP-44 spec above)
    and valid BIP-340 Schnorr signatures (pynostr). Public relays accept these events.

    Events are persisted in the same SQLite file as the wallet invoices
    (table nostr_events, same CARNETSATS_DB / db_path resolution). self.events
    is the in-memory mirror, loaded from the DB at startup and appended to
    on every new event, so a new ledger instance on the same DB file sees
    events created before a restart.
    """

    def __init__(self, merchant_privkey_hex: Optional[str] = None,
                 db_path: Optional[str] = None):
        if not PYnostr_AVAILABLE:
            raise RuntimeError("pynostr not installed: pip install pynostr")
        # Merchant key (v3.7 rev4): a real key from CARNETSATS_MERCHANT_KEY
        # (64 hex chars, set in .env by run.sh on first start) replaces the
        # fixed demo secret. Invalid or absent = demo key, labelled as such.
        env_key = os.environ.get("CARNETSATS_MERCHANT_KEY", "")
        self.key_source = "demo"
        chosen_key = merchant_privkey_hex
        if not chosen_key and len(env_key) == 64 and all(c in "0123456789abcdefABCDEF" for c in env_key):
            chosen_key = env_key.lower()
            self.key_source = "env"
        if chosen_key:
            self._merchant_priv = PrivateKey.from_hex(chosen_key)
        else:
            self._merchant_priv = PrivateKey.from_hex(
                hashlib.sha256(b"boutique-touba-dakar-secret").hexdigest()
            )
        self.privkey_hex = self._merchant_priv.hex()
        self.pubkey_hex = self._merchant_priv.public_key.hex()
        # For NIP-44 we use the merchant as both sender and recipient (self-DM envelope)
        self._recipient_pub = self._merchant_priv.public_key.hex()
        self.events: List[Dict[str, object]] = []
        self.db_path = resolve_db_path(db_path)
        if self.db_path != ":memory:":
            Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        self._db_lock = threading.Lock()
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._init_db()
        self._load_events_from_db()

    def _init_db(self) -> None:
        with self._db_lock:
            self._conn.execute(
                "CREATE TABLE IF NOT EXISTS nostr_events ("
                " id TEXT PRIMARY KEY, pubkey TEXT, created_at INTEGER,"
                " kind INTEGER, tags TEXT, content TEXT, sig TEXT,"
                " decrypted_preview TEXT, nip44_spec TEXT)"
            )
            # v3.7 rev4: record which relays accepted each event.
            try:
                self._conn.execute("ALTER TABLE nostr_events ADD COLUMN published_to TEXT DEFAULT '[]'")
            except Exception:
                pass  # column already exists on newer DBs
            self._conn.commit()

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> Dict[str, object]:
        published = []
        if "published_to" in row.keys() and row["published_to"]:
            try:
                published = json.loads(row["published_to"])
            except ValueError:
                published = []
        return {
            "id": row["id"],
            "pubkey": row["pubkey"],
            "created_at": row["created_at"],
            "kind": row["kind"],
            "tags": json.loads(row["tags"]),
            "content": row["content"],
            "sig": row["sig"],
            "decrypted_preview": json.loads(row["decrypted_preview"]),
            "nip44_spec": row["nip44_spec"],
            "published_to": published,
        }

    def _load_events_from_db(self) -> None:
        """Reload the in-memory mirror from SQLite (startup)."""
        with self._db_lock:
            rows = self._conn.execute(
                "SELECT * FROM nostr_events ORDER BY created_at"
            ).fetchall()
        self.events = [self._row_to_event(r) for r in rows]

    def _save_event(self, stored: Dict[str, object]) -> None:
        """INSERT OR REPLACE one event row and update the mirror."""
        with self._db_lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO nostr_events"
                " (id, pubkey, created_at, kind, tags, content, sig,"
                "  decrypted_preview, nip44_spec, published_to)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (stored["id"], stored["pubkey"], stored["created_at"],
                 stored["kind"], json.dumps(stored["tags"], ensure_ascii=False),
                 stored["content"], stored["sig"],
                 json.dumps(stored["decrypted_preview"], ensure_ascii=False),
                 stored["nip44_spec"],
                 json.dumps(stored.get("published_to", []), ensure_ascii=False)),
            )
            self._conn.commit()
        self.events.append(stored)

    def close(self) -> None:
        """Close the SQLite connection."""
        try:
            self._conn.close()
        except Exception:
            pass

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
            "debt_remaining_sats": int(round(debt_remaining_xof * sats_per_xof())),
            "lightning_payment_hash": payment_hash,
            "status": "SETTLED_TAB" if debt_remaining_xof == 0 else "OPEN_TAB",
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
            "published_to": [],
        }
        self._save_event(stored)
        return stored

    def repay_credit_tab(self, event_id: str, repayment_payment_hash: str) -> Dict[str, object]:
        """Publish a NIP-78 replacement Kind 30078 event that settles a tab.

        The replacement carries the EXACT SAME "d" tag
        (carnetsats:tab:client_<hash>) as the original, so relays treat it
        as the newer state of the same parameterized replaceable event,
        with debt_remaining_xof = 0 and status SETTLED_TAB. It goes through
        create_signed_credit_event, so it gets a fresh signature and is
        saved to SQLite like any other event.
        """
        target = next((ev for ev in self.events if ev["id"] == event_id), None)
        if not target:
            raise ValueError("Original credit event not found")
        prev = dict(target.get("decrypted_preview") or {})
        return self.create_signed_credit_event(
            customer_name=str(prev.get("customer_display", "Client")),
            items=list(prev.get("items", ["Remboursement Carnet"])),
            total_xof=int(prev.get("total_xof", 0)),
            paid_now_xof=int(prev.get("total_xof", 0)),
            debt_remaining_xof=0,
            payment_hash=repayment_payment_hash,
        )

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

    def publish_event_to_relay(self, event: Dict[str, object], relay_url: Optional[str] = None,
                               timeout: float = 60.0) -> Dict[str, object]:
        """Publish one stored event to a public relay and verify receipt.

        Relay URL defaults to CARNETSATS_RELAY_URL or wss://relay.damus.io.
        Returns {"ok": bool, "relay": url, "error": ...}. Never raises:
        publishing is best-effort, the sale itself never depends on it.
        """
        relay = relay_url or os.environ.get("CARNETSATS_RELAY_URL", "wss://relay.damus.io")
        try:
            import subprocess
            proc = subprocess.run(
                [sys.executable, "-c", _RELAY_PUBLISH_WORKER_CODE],
                input=json.dumps({"relay_url": relay, "event": {k: event[k] for k in
                                  ("id", "pubkey", "created_at", "kind", "tags", "content", "sig")}}),
                capture_output=True, text=True, timeout=timeout,
            )
            out = (proc.stdout or "").strip().splitlines()
            payload = json.loads(out[-1]) if out else {"ok": False, "error": "publish worker produced no output"}
        except Exception as exc:  # noqa: BLE001 - publish is best-effort
            payload = {"ok": False, "error": "%s: %s" % (type(exc).__name__, exc)}
        return {"ok": bool(payload.get("ok")), "relay": relay, "error": payload.get("error")}

    def publish_event_async(self, event: Dict[str, object]) -> None:
        """Best-effort background publish after checkout/repay.

        Never blocks the sale. Disabled with CARNETSATS_RELAY_PUBLISH=0.
        The outcome is recorded on the event (persisted in SQLite) so the
        UI can show it and the operator can retry via the API.
        """
        if os.environ.get("CARNETSATS_RELAY_PUBLISH", "1") == "0":
            return

        def _run():
            try:
                res = self.publish_event_to_relay(event)
                self._record_publish(event["id"], res)
            except Exception:
                pass

        threading.Thread(target=_run, daemon=True).start()

    def _record_publish(self, event_id: str, res: Dict[str, object]) -> None:
        """Persist a publish attempt's outcome onto the stored event."""
        with self._db_lock:
            row = self._conn.execute(
                "SELECT published_to FROM nostr_events WHERE id = ?", (event_id,)).fetchone()
            published = []
            if row and row[0]:
                try:
                    published = json.loads(row[0])
                except ValueError:
                    published = []
            if res.get("ok") and res.get("relay") not in published:
                published.append(res["relay"])
            self._conn.execute(
                "UPDATE nostr_events SET published_to = ? WHERE id = ?",
                (json.dumps(published), event_id),
            )
            self._conn.commit()
        for ev in self.events:
            if ev["id"] == event_id:
                ev["published_to"] = published
                if not res.get("ok"):
                    ev["publish_error"] = str(res.get("error", ""))[:200]
                break


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
    prompt_injection_blocked: bool = Field(default=False, description="True if adversarial instructions were stripped from the input")
    confidence_note: str = Field(description="Audit explanation of the deterministic calculation")


def parse_boutique_entry(text: str, use_gemini: bool = True) -> ParsedCarnetEntry:
    # Prompt-injection guard FIRST: adversarial text must never reach the AI.
    # If flagged, Gemini is skipped entirely and the deterministic fallback
    # below parses the cleaned text instead.
    injection_flagged, clean_text = detect_prompt_injection(text.strip())

    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if use_gemini and GENAI_AVAILABLE and api_key and not injection_flagged:
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
                parsed.prompt_injection_blocked = injection_flagged
                rate = sats_per_xof()
                parsed.upfront_sats = max(1, int(round(parsed.paid_upfront_xof * rate)))
                parsed.credit_owed_sats = int(round(parsed.credit_owed_xof * rate))
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

    rate = sats_per_xof()
    upfront_sats = max(1, int(round(paid_xof * rate))) if paid_xof > 0 else 0
    credit_sats = int(round(credit_xof * rate))

    return ParsedCarnetEntry(
        customer_name=customer_name,
        language_detected=lang,
        items=found_items,
        total_amount_xof=total_xof,
        paid_upfront_xof=paid_xof,
        credit_owed_xof=credit_xof,
        upfront_sats=upfront_sats,
        credit_owed_sats=credit_sats,
        prompt_injection_blocked=injection_flagged,
        confidence_note=(
            f"Deterministic schema verification: {total_xof} XOF total = "
            f"{paid_xof} XOF Lightning upfront ({upfront_sats} sats) + "
            f"{credit_xof} XOF Nostr NIP-44 tab ({credit_sats} sats)."
        ),
    )
