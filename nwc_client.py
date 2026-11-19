"""CarnetSats NWC (NIP-47) live-wallet client — v3.7 rev4.

Talks to a REAL Lightning wallet over Nostr Wallet Connect:

* ``parse_nwc_url`` parses a ``nostr+walletconnect://`` URL into its
  relay URL, wallet pubkey and client secret. The secret is a spend-capable
  credential: it is NEVER logged, NEVER returned by any API, and MUST live
  only in ``.env`` (``CARNETSATS_NWC_URL``), never in git, never in chat,
  never in a video frame.
* ``NWCClient.request`` sends one NIP-47 request (kind 23194, NIP-04
  encrypted — the transport every NWC wallet supports) to the wallet's
  relay and waits for the kind 23195 response. The websocket work runs in
  a short-lived subprocess so the FastAPI/pytest event loop is never
  involved (same isolation reason as the relay test worker).

When no ``CARNETSATS_NWC_URL`` is configured the engine stays in demo
mode (local BOLT11, local settle) exactly as before. When it IS configured
there is NO silent fallback to demo: a wallet failure is an error the
clerk can see, so a real payment is never faked as paid.
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.parse
from typing import Dict, Optional


class NWCError(Exception):
    """The real wallet could not be reached or rejected the request."""


def parse_nwc_url(url: str) -> Dict[str, str]:
    """Parse a ``nostr+walletconnect://`` URL.

    Accepted shape (what Alby / LNbits / most NWC wallets emit)::

        nostr+walletconnect://<wallet_pubkey_hex>?relay=wss://...&secret=<client_secret_hex>

    Returns ``{"relay": ..., "wallet_pubkey": ..., "secret": ...}``.
    Raises ValueError on anything else. The returned secret must be
    treated as a credential (see module docstring).
    """
    if not isinstance(url, str) or not url.startswith("nostr+walletconnect://"):
        raise ValueError("NWC URL must start with nostr+walletconnect://")
    rest = url[len("nostr+walletconnect://"):]
    wallet_pubkey, _, query = rest.partition("?")
    if len(wallet_pubkey) != 64 or any(c not in "0123456789abcdefABCDEF" for c in wallet_pubkey):
        raise ValueError("NWC URL wallet pubkey must be 64 hex characters")
    params = urllib.parse.parse_qs(query)
    relays = params.get("relay", [])
    secrets = params.get("secret", [])
    if not relays or not secrets:
        raise ValueError("NWC URL must carry relay= and secret= query parameters")
    secret = secrets[0]
    if len(secret) != 64 or any(c not in "0123456789abcdefABCDEF" for c in secret):
        raise ValueError("NWC URL secret must be 64 hex characters")
    return {"relay": relays[0], "wallet_pubkey": wallet_pubkey.lower(), "secret": secret.lower()}


def redact_nwc_secret(text: str, secret: Optional[str]) -> str:
    """Scrub a client secret out of any string (defence in depth)."""
    if secret and secret in text:
        return text.replace(secret, "[REDACTED_NWC_SECRET]")
    return text


# Worker executed in a short-lived subprocess (see module docstring).
# Reads one JSON blob on stdin:
#   {"relay": ..., "wallet_pubkey": ..., "secret": ...,
#    "method": ..., "params": {...}, "timeout": ...}
# Prints exactly one JSON line on stdout:
#   {"ok": true, "result": {...}}  or  {"ok": false, "error": "..."}
# The secret travels on stdin (never argv, never stdout).
_NWC_WORKER_CODE = r"""
import json, sys, time
import websocket
from pynostr.encrypted_dm import EncryptedDirectMessage
from pynostr.event import Event
from pynostr.key import PrivateKey

def fail(msg):
    print(json.dumps({"ok": False, "error": msg}))
    sys.exit(0)

try:
    job = json.load(sys.stdin)
    relay_url = job["relay"]
    wallet_pubkey = job["wallet_pubkey"]
    secret = job["secret"]
    method = job["method"]
    params = job.get("params") or {}
    timeout = float(job.get("timeout") or 20)
except Exception as exc:
    fail("bad NWC job: %s: %s" % (type(exc).__name__, exc))

t0 = time.time()
try:
    client_priv = PrivateKey.from_hex(secret)
    client_pub = client_priv.public_key.hex()
    request_obj = {"method": method, "params": params}
    dm = EncryptedDirectMessage()
    dm.encrypt(secret, json.dumps(request_obj), wallet_pubkey)
    req_event = Event(
        kind=23194,
        content=dm.encrypted_message,
        tags=[["p", wallet_pubkey]],
        pubkey=client_pub,
    )
    req_event.sign(secret)
    sub_id = "carnetsats-nwc-%s" % req_event.id[:12]
    req_filter = {
        "kinds": [23195],
        "authors": [wallet_pubkey],
        "#p": [client_pub],
        "#e": [req_event.id],
    }
    ws = websocket.create_connection(relay_url, timeout=timeout)
    try:
        ws.send(json.dumps(["REQ", sub_id, req_filter]))
        ws.send(req_event.to_message())
        result = None
        while time.time() - t0 < timeout:
            try:
                raw = ws.recv()
            except websocket.WebSocketTimeoutException:
                break
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(msg, list) or len(msg) < 3:
                continue
            if msg[0] == "EVENT" and msg[1] == sub_id:
                ev = msg[2]
                if ev.get("kind") != 23195:
                    continue
                # Only accept the reply to THIS request. The relay also sends
                # stored replies to older requests; taking the first one
                # returns the previous sale's invoice.
                ev_tags = ev.get("tags") or []
                if not any(isinstance(t, list) and len(t) > 1 and t[0] == "e" and t[1] == req_event.id for t in ev_tags):
                    continue
                try:
                    dm2 = EncryptedDirectMessage()
                    dm2.decrypt(secret, ev.get("content", ""), wallet_pubkey)
                    payload = json.loads(dm2.cleartext_content or "{}")
                except Exception:
                    continue
                if "result" in payload or "error" in payload:
                    result = payload
                    break
            elif msg[0] == "EOSE" and msg[1] == sub_id:
                continue
        if result is None:
            fail("no NIP-47 response from wallet within %.0fs" % timeout)
        if result.get("error"):
            err = result["error"]
            fail("wallet error %s: %s" % (
                err.get("code", "UNKNOWN") if isinstance(err, dict) else "UNKNOWN",
                err.get("message", err) if isinstance(err, dict) else err))
        print(json.dumps({"ok": True, "result": result.get("result")}))
    finally:
        try:
            ws.close()
        except Exception:
            pass
except Exception as exc:
    fail("%s: %s" % (type(exc).__name__, exc))
"""


class NWCClient:
    """One-shot NIP-47 client for a real wallet (see module docstring)."""

    def __init__(self, relay_url: str, wallet_pubkey: str, secret: str, timeout: float = 20.0):
        self.relay_url = relay_url
        self.wallet_pubkey = wallet_pubkey
        self.secret = secret
        self.timeout = float(timeout)

    @classmethod
    def from_url(cls, url: str, timeout: float = 20.0) -> "NWCClient":
        parts = parse_nwc_url(url)
        return cls(parts["relay"], parts["wallet_pubkey"], parts["secret"], timeout=timeout)

    def request(self, method: str, params: Optional[Dict] = None) -> Dict:
        """Send one NIP-47 request; returns the wallet's ``result`` dict.

        Raises NWCError on transport failure, timeout, or a wallet error.
        The secret is never in the raised message.
        """
        job = {
            "relay": self.relay_url,
            "wallet_pubkey": self.wallet_pubkey,
            "secret": self.secret,
            "method": method,
            "params": params or {},
            "timeout": self.timeout,
        }
        try:
            proc = subprocess.run(
                [sys.executable, "-c", _NWC_WORKER_CODE],
                input=json.dumps(job),
                capture_output=True,
                text=True,
                timeout=self.timeout + 15,
            )
        except subprocess.TimeoutExpired:
            raise NWCError("NWC request timed out (wallet/relay unreachable)")
        out = (proc.stdout or "").strip().splitlines()
        if not out:
            raise NWCError("NWC worker produced no output (stderr: %s)" % redact_nwc_secret(
                (proc.stderr or "")[-500:], self.secret))
        try:
            payload = json.loads(out[-1])
        except ValueError:
            raise NWCError("NWC worker produced invalid output: %r" % out[-1][:200])
        if not payload.get("ok"):
            raise NWCError(redact_nwc_secret(str(payload.get("error", "unknown NWC error")), self.secret))
        result = payload.get("result")
        if not isinstance(result, dict):
            raise NWCError("NWC wallet returned a malformed result")
        return result
