# CarnetSats — Voice/Text Boutique POS on Lightning + Nostr

Dakar Bitcoin Hack by BTrust 2026. A voice/text point-of-sale for a Dakar
boutique (FR / Wolof / EN): a clerk speaks or types a sale, the AI cashier
parses it, a Lightning invoice is issued under least-privilege NIP-47, and
the unpaid credit goes on a Nostr credit tab encrypted with real NIP-44 v2.
Surplus hot-wallet funds are swept to a BIP-84 watch-only cold vault by
policy. No customer PII ever reaches a log.

**85 automated tests — verifiable in the terminal via `./run.sh`.**

## Honest claims (from `carnetsats_engine.py`, verbatim)

- BOLT11: spec-correct BOLT11 string produced by the `bolt11` library
  (HRP lntbs, timestamp, payment_hash tag `p`, payment_secret tag `s`,
  description tag `d`, expiry, valid checksum) and signed with a
  deterministic DEMO secp256k1 key (sha256 of a fixed demo string, NOT a
  real node key). In production the LN node's `sign_invoice` RPC produces
  the same shape with a real key.
- NIP-44 v2: real ChaCha20 + HMAC-SHA256 + padding per NIP-44 spec,
  implemented here from the spec (secp256k1 ECDH, HKDF-SHA256, ChaCha20,
  HMAC-SHA256, base64). pynostr 0.7 has no nip44 module and its
  EncryptedDirectMessage is NIP-04 only, so NIP-44 is NOT done via
  pynostr. Ciphertexts are spec-shaped and decrypt with any
  spec-compliant NIP-44 library (nostr-tools, nostr-sdk).
  **Verified against the published NIP-44 test vector in
  `test_00_nip44_spec_vector`.**
- BIP-84: real BIP-32 child derivation from a valid BIP-84 testnet vpub
  via `bip-utils`. The default vpub is derived from a fixed DEMO seed,
  production swaps in the boutique's own vpub from a hardware signer
  via `CARNETSATS_VPUB`.

Demo-only keys: the BIP-84 vpub, the BOLT11 signing key and the Nostr
merchant key are all derived from fixed public demo strings. Swap them
for real keys in production. The vpub is watch-only, no funds can be
spent from it.

## Live Hosted MVP (Render — Full FastAPI Backend)

- **Live App (`MODE: LIVE FASTAPI`):** https://carnetsats.onrender.com
- Python 3.12 (`PYTHON_VERSION=3.12.0` on Render; coincurve does not build on Python 3.13). Free tier sleeps after 15 minutes of inactivity, so the first visit can take about a minute to wake up.

## Quickstart

```bash
./run.sh
# runs 85 tests, then serves the live MVP at http://localhost:8000
```

Or with Docker:

```bash
docker compose up --build
# env: GEMINI_API_KEY (optional, deterministic parser if unset)
#      CARNETSATS_VPUB (optional, demo vpub if unset or empty)
```

## API

| Endpoint | Method | What it does |
|---|---|---|
| `/api/state` | GET | Balance, NIP-47 info, sweep policy, Nostr pubkey |
| `/api/checkout` | POST | Parse a sale, issue BOLT11, create NIP-44 credit event |
| `/api/settle` | POST | Settle an invoice, verify SHA-256 preimage |
| `/api/security-test` | POST | Red-team: blocked pay_invoice, sanitised logs |
| `/api/sweep-policy` | GET | BIP-84 sweep recommendation only, no execution |
| `/api/verify-nostr-event/{id}` | GET | Verify a Schnorr-signed credit event |
| `/api/decrypt-nostr-event/{id}` | POST | Decrypt a credit event with NIP-44 v2 |

The sweep button is a **policy viewer only**: it shows the recommended
amount and vault destination. It does not move funds and does not change
the displayed balance. Production wires a BDK PSBT builder.

## Static fallback (GitHub Pages)

`docs/index.html` also runs without a backend. In that mode everything
is labelled `[STATIC]`, the QR is a deterministic pseudo-matrix (not a
real QR code) captioned `[STATIC DEMO QR - run ./run.sh for real
BOLT11]`, and the BOLT11 / NIP-44 data shown is a static demo envelope.
With the live backend (`MODE: LIVE FASTAPI`, local or Render) the QR is a
real scannable ISO/IEC 18004 QR code for the real BOLT11 invoice.
Run `./run.sh` for the real backend.

## Files

- `carnetsats_engine.py` — NIP-47, BIP-84, NIP-44 v2, Schnorr, parser, PII redactor
- `app.py` — FastAPI backend
- `test_carnetsats.py` — 85 deterministic tests
- `docs/index.html` — frontend (live backend or static fallback)
- `requirements.txt`, `run.sh`, `Dockerfile`, `docker-compose.yml`
