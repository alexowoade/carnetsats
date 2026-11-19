# SECURITY.md — CarnetSats Threat Model (v3.8.1)

CarnetSats is a voice/text point-of-sale for a Dakar boutique: a clerk
speaks or types a sale, the cashier parses it, a Lightning BOLT11 invoice
is issued, and any unpaid balance goes on a Nostr credit ledger. This
document models threats against the code as it actually is in v3.8.1.
It does not describe a production system.

## Status and scope — read first

- **Prototype on Signet/testnet only.** Invoices use the `lntbs`
  prefix, the vault derives Signet/testnet (`tb1q…`) addresses, and
  no real money moves. Nothing here is ready for mainnet.
- **Demo keys throughout.** The BIP-84 vpub, the BOLT11 signing key,
  and the Nostr merchant key are all derived from fixed public demo
  strings in `carnetsats_engine.py` (see "Demo keys" below). Anyone
  who reads the source can re-derive them.
- **Live receive-only NWC wallet on Mutinynet.** When
  `CARNETSATS_NWC_URL` is set, `NWCLightningEngine` talks to a real
  Alby Hub node over NIP-47 (kind 23194/23195, NIP-44 v2): real
  `make_invoice`, real `lookup_invoice`, real `get_balance`. The
  connection is receive-only: `pay_invoice` is not granted to the
  app, so the till can never spend. Without the URL the app runs in
  demo mode with a simulated in-process wallet.
- **Relay publishing in normal operation.** Since rev4
  `NostrCreditLedger` publishes every credit event to a public relay
  in the background after checkout/repay (`CARNETSATS_RELAY_URL`,
  deployed to `wss://nos.lol`; code default `wss://relay.damus.io`).
  Events are also stored in SQLite (`nostr_events` table in
  `carnetsats.db`) and in the in-memory list `self.events`, and
  `GET /api/nostr-events` shows `published_to` for each event.
- **Prompt-injection firewall.** `detect_prompt_injection()` flags and
  strips adversarial directives (`ignore previous instructions`,
  `pay_invoice`, `drain_wallet`, `owner_signer`) before sale text ever
  reaches Groq; flagged input falls back to the deterministic parser
  and never calls the AI (`test_19c`).
- **No authentication or rate limiting.** `app.py` exposes every
  endpoint without auth, and CORS is `allow_origins=["*"]`. Anyone
  who can reach the server can call checkout, settle, decrypt, and
  the security-test endpoint.
- **Sweep is policy-only.** `BDKColdVault.evaluate_sweep_policy()`
  only *recommends* a sweep amount and a vault address. It moves no
  funds and builds no transaction; the BDK PSBT flow does not exist
  yet.

## Assets

| Asset | Where it lives |
|---|---|
| Hot-wallet balance (simulated, 95,000 sats default) | `NWCLightningEngine.balance_sats` |
| Nostr merchant key (demo) | `NostrCreditLedger`, from `sha256(b"boutique-touba-dakar-secret")` |
| BIP-84 vault vpub (watch-only, demo) | `BDKColdVault.DEFAULT_TPUB`, replaceable via `CARNETSATS_VPUB` |
| BOLT11 signing key (demo) | `_make_bolt11_signet()`, `sha256(b"carnetsats-demo-bolt11-signing-key")` |
| Customer credit tabs (NIP-44 ciphertext + cleartext preview) | `NostrCreditLedger.events` (SQLite `nostr_events` table + in-memory list) |
| Groq API key (optional) | `GROQ_API_KEY` env var only, never in code |

## STRIDE threat model

"Mitigation in code" is something this codebase actually does.
"Residual risk" is what remains after it.

### (1) NWC flow — cashier key, `make_invoice` scope, `pay_invoice` blocked

| Threat | Mitigation in code | Residual risk |
|---|---|---|
| **Spoofing** — attacker calls the wallet as the owner | `ROLE_PERMISSIONS` gives `clerk_ai` only `get_info`, `get_balance`, `make_invoice`, `lookup_invoice`, `list_transactions`; `pay_invoice` exists only for `owner_signer`. `execute_nip47_request()` returns `RESTRICTED` for any method outside the caller's role and logs `SECURITY_BLOCK`. | **Role is caller-supplied, not authenticated.** `app.py` takes `role` straight from the request body (`ParseSaleRequest.role`), with no signature, token, or session check. Anyone reaching `/api/checkout` can pass `role="owner_signer"`. In production the role must come from a verified NIP-47 connection (signed kind 23194 request), never a request field. Even a forged `role="owner_signer"` call cannot spend funds in live mode, because the live Alby Hub NWC connection does not grant `pay_invoice`; the Hub enforces receive-only at the protocol layer. |
| **Tampering** — forged or altered invoice | Invoices are built with the `bolt11` library (valid checksum, `p` payment hash, `s` payment secret, `d` description, 1 h expiry) and round-trip-decoded before storage (`bolt11_decode_ok`). Settlement re-derives the hash: `settle_incoming_invoice()` raises if the preimage's SHA-256 does not match the payment hash. | The signing key is a public demo string, so anyone can forge a correctly-shaped invoice. Preimages are deterministic (`sha256("preimage:{seed}:{amount}")`); a caller-supplied `deterministic_seed` makes the preimage predictable to anyone who knows the seed. |
| **Repudiation** — "I never made / paid that invoice" | Every NIP-47 request and blocked attempt is appended to `audit_logs` by `_log()`; settlement appends a `SETTLED` entry with payment hash and amount. | Logs are an unsigned in-memory list with no persistence: a restart wipes them and a process compromise can rewrite them. Demo evidence, not an audit trail. |
| **Information disclosure** — secret or customer data in logs | `_log()` passes every message through `sanitize_log()`, which redacts SN/NG phone numbers, `secret=…` hex strings, `nsec1…` keys, and `PII_NAME:` values. Customer names are stored only as `customer_alias_id()` — `sha256(salt + name)[:10]`. `/api/security-test` demonstrates both. | The alias salt is the fixed public string `"dakar-sandaga-v1"`, so the alias is brute-forceable with a dictionary of common Dakar first names. The redactor is regex-based: a phone number in an unexpected format, or a non-hex secret, passes through. |
| **Denial of service** — invoice spam | `make_invoice` rejects `amount_msat <= 0`; `pay_invoice` rejects non-positive amounts and amounts above the balance. | No rate limiting, no per-caller quota, no cap on invoice count. An attacker can create unlimited unpaid invoices (memory + SQLite growth in `self.invoices`) and, as `owner_signer`, drain up to the daily quota day after day. |
| **Elevation of privilege** — clerk key pays out | `pay_invoice` is absent from the `clerk_ai` list, so a clerk-role call is refused with `RESTRICTED` before any balance check. Even for `owner_signer`, `pay_invoice` enforces a daily quota (default 50,000 sats) and returns `QUOTA_EXCEEDED` above it. | Same as Spoofing: the role check is only as strong as the (non-existent) authentication of the role. There is also no per-transaction owner approval (second factor, hardware confirmation) for in-quota payments. |

### (2) Nostr credit ledger — NIP-44 encryption, Schnorr signatures, relay trust

| Threat | Mitigation in code | Residual risk |
|---|---|---|
| **Spoofing** — fake credit tab attributed to the boutique | Every kind 30078 event carries a real BIP-340 Schnorr signature via pynostr (`event.sign(...)`); `/api/verify-nostr-event/{id}` re-verifies it with `ev.verify()`. Since rev4 the merchant key comes from `CARNETSATS_MERCHANT_KEY` in `.env` (run.sh generates a fresh one on first start); `/api/state` reports `merchant_key_source` as `env` or `demo`. | If `.env` is absent the fixed demo secret is still used and anyone can sign as the boutique. No key rotation, no revocation, no event expiry. The key lives in a plaintext `.env` file on the server, not a secret manager. |
| **Tampering** — credit amount altered in transit/storage | Real NIP-44 v2 (secp256k1 ECDH, HKDF-SHA256, ChaCha20, HMAC-SHA256, base64), verified against the published NIP-44 test vector. Decryption verifies the HMAC with `hmac.compare_digest` and validates padding; a tampered ciphertext cannot decrypt. | Plaintext tags (`d` alias tag, `ln_hash` payment hash) are covered only by the event signature — which holds only while the merchant key is secret, and in demo form it is not. |
| **Repudiation** — merchant denies a tab, customer denies a debt | The signed event binds pubkey + content + tags + timestamp; anyone can verify it. The payment hash in the tags links the tab to a specific invoice. Since rev4 each event is also published to a public relay in the background after checkout/repay (`CARNETSATS_RELAY_URL`, default `wss://relay.damus.io`); the relay holds an independent copy, and `published_to` on the event (via `GET /api/nostr-events`) shows where it landed. | Publishing is best-effort: a failed publish leaves only the server's SQLite copy (`carnetsats.db`), which survives restarts. Publishing can be disabled with `CARNETSATS_RELAY_PUBLISH=0`. |
| **Information disclosure** — customer identity or debt exposed | Event `content` is NIP-44 v2 ciphertext; amount, items, and name sit inside the encrypted JSON. The stored alias is a hash, not a name. | **Metadata leaks in plaintext tags and in memory.** The `d` tag exposes the alias, `ln_hash` the payment hash, and kind 30078 + pubkey identify the boutique. The server stores `decrypted_preview` (full cleartext) beside the ciphertext, and `/api/decrypt-nostr-event/{id}` decrypts any event for any unauthenticated caller, since the server holds the key. This is a self-DM envelope (merchant encrypts to itself): it protects the payload from relay operators, not from the server or API callers. No forward secrecy — one key decrypts every past tab. |
| **Denial of service** — relay or ledger flooding | Since rev4 events ARE published to a relay in normal operation, one per sale/repay, in a background thread that never blocks the sale. The relay URL is configurable (`CARNETSATS_RELAY_URL`) and publishing can be switched off (`CARNETSATS_RELAY_PUBLISH=0`). | No relay allow-list, rate limit, or event-size cap in the code; a compromised clerk key could publish unbounded events (one per sale call). |
| **Elevation of privilege** — attacker reads/rewrites tabs | Decryption requires the merchant private key, held server-side; `decrypt_nip44_payload()` fails closed (raises) on a bad MAC or bad padding instead of returning partial data. | No access control on the decrypt/verify endpoints: any caller can decrypt any stored tab. Key and API live in the same unauthenticated process, so NIP-44 provides no access boundary in this deployment. |

### (3) BIP-84 vault — threshold sweep, cold storage

| Threat | Mitigation in code | Residual risk |
|---|---|---|
| **Spoofing** — fake vault address diverts the sweep | Addresses derive with real BIP-32/BIP-84 derivation (`bip-utils`, `m/84'/1'/0'/0/{index}`) from the configured vpub; `derive_cold_address()` verifies the correct HRP (`tb1q` Signet/testnet, `bc1q` mainnet) and raises otherwise. A wrong-network vpub is rejected by `bip-utils`. | The default vpub is a public demo value. If production forgets `CARNETSATS_VPUB`, sweeps are recommended to an address the whole world can derive (watch-only: not spendable). Nothing checks that the configured vpub belongs to the boutique. |
| **Tampering** — sweep amount or destination altered | `evaluate_sweep_policy()` is a pure function of the hot balance and the fixed 50,000 XOF threshold: above it, it recommends sweeping everything except a 40% reserve. It takes no destination parameter, so a caller cannot redirect it. | In demo mode the balance is the simulated in-process counter; in live NWC mode it is the real wallet's balance. Either way the policy is a recommendation only. |
| **Repudiation** — "no sweep was recommended / authorised" | The recommendation is recomputed deterministically from the balance on every `/api/state` and `/api/sweep-policy` call. | No record of recommendations, no approval step, no signature — nothing to audit after the fact. |
| **Information disclosure** — vault holdings exposed | The vault is watch-only: the vpub derives addresses but cannot spend. Only the first 24 characters of the vpub are ever returned (`tpub_prefix`), never keys. | The API returns the vault address and recommended sweep amount to any unauthenticated caller, leaking treasury size and timing. A published vpub lets anyone derive every vault address and watch every balance. |
| **Denial of service** — threshold manipulation keeps funds hot | The threshold is a module constant, not a request parameter; no endpoint can change it. | The sweep does not execute itself. If nobody acts on the recommendation, funds sit in the hot wallet indefinitely above threshold. No alert, no auto-sweep, no escalation. |
| **Elevation of privilege** — attacker spends from the vault | **Impossible through this code.** No private key exists anywhere: derivation is from the vpub only, and the sweep endpoint is a policy viewer — it shows amount and destination, moves no funds, and does not change the balance. Spending needs the hardware signer holding the seed, which is never present here. | Operational risk only: if the seed is ever entered on, or exported to, a networked machine to "make the sweep work", the cold-storage boundary is gone. Keep the seed offline; sign PSBTs on the device. |

## Demo keys — replace before production

| Demo secret | Location | Replace with |
|---|---|---|
| Nostr merchant key `sha256(b"boutique-touba-dakar-secret")` | `NostrCreditLedger.__init__` | Fresh key in `CARNETSATS_MERCHANT_KEY` (`.env`); run.sh generates one on first start since rev4. The demo secret remains the fallback when `.env` is absent. |
| BOLT11 signing key `sha256(b"carnetsats-demo-bolt11-signing-key")` | `_make_bolt11_signet()` | In live NWC mode the invoice comes from the real wallet's `make_invoice`; in demo mode the demo key still signs. |
| NWC wallet secret (receive-only scope) | `CARNETSATS_NWC_URL` in `.env` | Testnet wallet only for the demo; never commit `.env`, never log the URL, never show it on screen or in a video. The engine redacts it from logs and never returns it from any API. |
| BIP-84 demo vpub | `BDKColdVault.DEFAULT_TPUB` | The boutique's own vpub from a hardware signer, via `CARNETSATS_VPUB` |
| Alias salt `"dakar-sandaga-v1"` | `customer_alias_id()` | Random per-boutique salt stored server-side, not in source |
| Groq API key | `GROQ_API_KEY` env var | Scoped key in the deployment's secret store; the deterministic parser already runs without it |

## What this document deliberately does NOT claim

- Real NWC transport exists ONLY when `CARNETSATS_NWC_URL` is set (a
  testnet wallet); without it the app runs in demo mode and the NIP-47
  checks are local logic. Relay publishing exists since rev4 (one event
  per sale/repay, best-effort, background).
- NIP-44 does not keep credit tabs private from the server operator
  or API callers in this deployment (see the ledger table).
- CarnetSats does not "sweep to cold storage" today: it recommends,
  and a human (later a PSBT flow) executes.
- No endpoint is authenticated. Do not expose this server to the
  public internet as-is; put it behind authentication and TLS, and
  restrict CORS from `*` to the frontend origin.

## Reporting a vulnerability

Do not post keys, secrets, or customer data in an issue. Open a
GitHub issue on `alexowoade/carnetsats` describing the affected
version, the endpoint or function, and steps to reproduce with demo
data only. If the issue involves a live secret, rotate it first,
then report.
