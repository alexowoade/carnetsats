# CarnetSats v3.8.1 — Video Voiceover Script (2:40)

Synced to v3.8.1 and 235 tests. Record from the live link after installing v3.8.1 on the PC.
Deadline: Fri 20 Nov 2026, 21:00 CET (Dakar Bitcoin Hack by BTrust).

## Scene 1 (0:00 – 0:25) | The Problem

"Hello everyone! Across Dakar and West Africa, neighborhood shopkeepers sell daily staples on split payments: a customer pays part upfront and puts the rest in a paper credit notebook. Paper notebooks get lost or disputed, and leaving an unlocked Bitcoin wallet on a shop counter risks unauthorized drains. Shopkeepers fear a hacker, a prompt injection, or a stolen phone emptying their day's sales. CarnetSats is strictly receive-only: `pay_invoice` is blocked in code and never granted in Alby Hub, so payments flow one way into the owner's hub — and only the owner moves funds inside Alby Hub. This is **CarnetSats v3.8**: a voice and text point-of-sale on Lightning and Nostr."

## Scene 2 (0:25 – 1:10) | Trilingual Cashier, Live FX & Scannable BOLT11 Invoice

Stage directions: Click `🎙️ FR (Moussa)`, `🎙️ Wolof (Aminata)`, then `🇬🇧 EN`; click `✅ Simulate Tap`, then point out `📲 WhatsApp Receipt`.

"The interface switches every label across English, French, and Wolof in one click, using live CoinGecko BTC-to-CFA rates with a deterministic offline fallback. When a clerk enters a sale, our parser strips any prompt-injection attempt and splits the basket into an upfront Lightning payment and a Nostr credit tab. On the right, our FastAPI backend issues a spec-compliant Signet BOLT11 invoice with a real scannable QR code and WebLN support, verifies the SHA-256 preimage on settlement, and formats a WhatsApp receipt."

## Scene 3 (1:10 – 1:45) | Real NIP-44 v2 Credit Book & NIP-78 Repayment

Stage directions: Click `🔎 Schnorr/NIP-44` on the top row of Panel 2, then click `💳 Repay`.

"Unpaid credit is persisted in SQLite and signed as a Nostr Kind 30078 event with a BIP-340 Schnorr signature and spec-compliant NIP-44 v2 encryption. Clicking Audit verifies the Schnorr signature and decrypts the NIP-44 payload on the server, and clicking Repay publishes a replacement Kind 30078 event with the same `d` tag setting the remaining debt to zero."

## Scene 4 (1:45 – 2:15) | Least-Privilege NIP-47 Firewall & BIP-84 Cold Vault

Stage directions: Click `🛡️ pay_invoice Attack → RESTRICTED`, then click `🏦 Sweep to BIP-84 Vault`.

"For Security by Design, the counter's `clerk_ai` role is restricted to read and invoice methods. Simulating a `pay_invoice` drain attack is blocked with `RESTRICTED` while redacting phone numbers and secrets from logs. The counter is receive-only by design: clerks and attackers cannot drain funds, and only the owner moves money inside Alby Hub. Above 50,000 CFA, our BIP-84 engine derives a watch-only Signet cold address (`tb1q...`) from the shop's `vpub`."

## Scene 5 (2:15 – 2:40) | 235 Automated Tests, Live Relay Proof & Honest Scope

Stage directions: Switch to terminal showing `236 passed, 1 skipped`, plus the passing `SKIP_RELAY_TESTS=0` relay round-trip.

"In the terminal, 235 deterministic offline tests pass — covering the full `paulmillr` NIP-44 vector suite, Hypothesis fuzz tests, SQLite restart persistence, NIP-47 RBAC, and 18 BIP-84 and sweep checks — plus a live round-trip test against `wss://nos.lol`, and a live wallet round-trip test once a testnet NWC URL is configured. All demo boundaries are documented in `SECURITY.md`. Thank you!"

## Verified facts behind this script

- 236 passed, 1 skipped (verified live on EC2, 2026-11-19).
- Live NWC test needs a testnet wallet via CARNETSATS_NWC_URL (gated; skipped without it).
- 18 BIP-84 and sweep checks = test_03 (10 parametrized indices) + test_04a (1) + test_04b (1) + test_05 (6 threshold cases).
- All named buttons exist in docs/index.html with exactly these labels.
- Live relay test target is wss://nos.lol (gated by SKIP_RELAY_TESTS).
