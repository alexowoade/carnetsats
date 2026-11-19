# CarnetSats — Voice/Text Boutique POS on Lightning + Nostr

![tests](https://github.com/alexowoade/carnetsats/actions/workflows/test.yml/badge.svg)

Dakar Bitcoin Hack by BTrust 2026. A voice/text point-of-sale for a Dakar
boutique (FR / Wolof / EN): a clerk speaks or types a sale, the AI cashier
parses it, a Lightning invoice is issued under least-privilege NIP-47, and
the unpaid credit goes on a Nostr credit tab encrypted with real NIP-44 v2.
Surplus hot-wallet funds are swept to a BIP-84 watch-only cold vault by
policy. No customer PII ever reaches a log.

**235 automated tests (+ 1 live Nostr relay round-trip test + 1 live NWC wallet test) — verifiable in the terminal via `./run.sh`.**

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

## Live Hosted MVP (AWS EC2 — always on)

- **Live App (`MODE: LIVE FASTAPI`):** https://carnetsats.duckdns.org
- Always on: AWS EC2 (t3.micro, Ubuntu 24.04) + Caddy HTTPS + live Mutinynet Alby Hub + credit records published to wss://nos.lol.
- Python 3.12 (`PYTHON_VERSION=3.12.0`; coincurve does not build on Python 3.13).

## Quickstart

```bash
./run.sh
# runs 235 tests, then serves the live MVP at http://localhost:8000
```

Or with Docker:

```bash
docker compose up --build
# env: GROQ_API_KEY (optional, deterministic parser if unset)
#      CARNETSATS_VPUB (optional, demo vpub if unset or empty)
#      CARNETSATS_NWC_URL (optional, testnet wallet; demo mode if unset)
#      CARNETSATS_MERCHANT_KEY (optional, generated into .env by run.sh)
```

## Live wallet mode (rev4) — real Lightning, real relay

With a testnet NWC wallet URL in `.env` (`CARNETSATS_NWC_URL`, see
`.env.example`), the app stops simulating payments:

- `make_invoice` calls the real wallet; the QR is the wallet's real
  BOLT11, payable with any Lightning wallet.
- `/api/settle` asks the wallet (`lookup_invoice`); an unpaid invoice
  stays PENDING and is never marked paid. A wallet that cannot be
  reached is an error, never a silent demo fallback.
- Every Nostr credit event is published to a public relay in the
  background after checkout/repay (`CARNETSATS_RELAY_URL`, default
  `wss://relay.damus.io`); `GET /api/nostr-events` shows `published_to`.
- The merchant signing key comes from `CARNETSATS_MERCHANT_KEY`
  (run.sh generates a fresh one into `.env` on first start).

Without `CARNETSATS_NWC_URL` the app runs in demo mode exactly as
before (local BOLT11, local settle, `MODE: LIVE FASTAPI`). Still
simulated even in live mode: the sweep is a policy recommendation only
(no PSBT/broadcast — that needs a real node), the static GitHub Pages
fallback is an openly labelled demo, and tab repayment is ledger-only
(no Lightning payment is made for a tab settlement).

## API

| Endpoint | Method | What it does |
|---|---|---|
| `/api/state` | GET | Balance, NIP-47 info, NWC mode, sweep policy, Nostr pubkey |
| `/api/checkout` | POST | Parse a sale, issue BOLT11, create NIP-44 credit event |
| `/api/settle` | POST | Settle an invoice, verify SHA-256 preimage |
| `/api/repay-tab` | POST | Repay a Nostr credit tab via NIP-78 replacement Kind 30078 event |
| `/api/nostr-events` | GET | Ledger events with relay publish status |
| `/api/publish-nostr-event/{id}` | POST | Manually (re)publish one event to the relay |
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
With the live backend (`MODE: LIVE FASTAPI`, local or the live EC2 host) the QR is a
real scannable ISO/IEC 18004 QR code for the real BOLT11 invoice.
Run `./run.sh` for the real backend.

## Files

- `carnetsats_engine.py` — NIP-47, BIP-84, NIP-44 v2, Schnorr, parser, PII redactor
- `nwc_client.py` — real NWC (NIP-47) transport to a live wallet (rev4)
- `app.py` — FastAPI backend
- `test_carnetsats.py` — 235 deterministic tests
- `test_15_nostr_relay_roundtrip.py` — live relay round-trip (skipped offline)
- `test_23_nwc_live.py` — live NWC wallet round-trip (skipped without CARNETSATS_NWC_URL)
- `docs/index.html` — frontend (live backend or static fallback)
- `requirements.txt`, `run.sh`, `Dockerfile`, `docker-compose.yml`
