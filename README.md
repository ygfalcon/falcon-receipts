# falcon-receipts

Offline verifier for **Falcon Shield** receipts. Falcon Shield is a pre-sign check for Solana transactions that agents and wallets call before signing.

> **Status: Falcon Shield is currently paused and not accepting paid calls.** This verifier works fully offline and still verifies every receipt Shield has issued.

Every verdict (`BLOCK`, `WARN`, `NO_MATCH`) is returned with an ed25519-signed, hash-chained receipt. This repo lets anyone verify that receipt themselves, with no network access and no dependencies. That makes it usable for audits, disputes, and agent-to-agent trust.

- **Browser:** https://falcon-receipts.falcon-sol.workers.dev. Paste a receipt and nothing is uploaded.
- **Node:** `npx falcon-receipts verify response.json --tx <base64>`
  - Note: the `falcon-receipts` package is not on npm yet. Until it is, run it from a clone: `node js/bin.js verify response.json --tx <base64>`.
- **Python:** `python3 python/receipt_verify.py receipts.jsonl --signer 3HBA6GFnDU6Ez5KrNtWrjLTkWFRJgcmVneEPukRJ2ULW`

```js
const { verifyReceipt } = require("falcon-receipts");
const r = verifyReceipt(JSON.stringify(shieldResponse), { txBase64 });  // pins the production signer by default
if (!r.ok) throw new Error("untrusted verdict: " + r.problems.join(","));
```

```python
from receipt_verify import verify_receipt
verify_receipt(resp["receipt"], tx_b64=tx)   # {'ok': True, 'verdict': 'BLOCK', ...}
```

## What it checks

- The hash recomputes from `{seq, logged_at, prev, event}`, so any edit to the verdict or reasons is caught.
- The ed25519 signature is valid and comes from the pinned production signer.
- Optionally, the receipt's `tx_sha256` matches the transaction bytes you hold.
- For full chains: seq and prev linkage, checkpoints (which catch truncation, rollback, and forks), duplicate keys, BOM and CRLF quirks, and unsigned extra fields.

## Tests

Python and Node each pass 32 adversarial chain cases plus the single-receipt tests:

```
python3 tests/run_cases.py && node tests/run_cases.js && python3 tests/test_single.py && node tests/test_single.js
```

See [docs/FORMAT.md](docs/FORMAT.md) for the byte-level format.

## Limits

A receipt proves what Shield said and when. `NO_MATCH` means no known-bad pattern matched. It is not a safety guarantee.

MIT licensed. Built by falcon.sol.

## Live proof (Solana mainnet, 2026-10-30)
A real paid (historical, pre-pause) `POST /guard/check` (settlement tx `454f6i85TwEfFtrEFJjBJmUsuFkUCHsc678wJqeSN4Mp5895iaf7sKxdsHDEwaLNNnm1QdNQ9fzyzhZPF1o4P4UY`) returned a BLOCK receipt. It is saved in `fixtures/live-mainnet-guard-check-2026-10-30.json` with the exact tx in `.tx.b64`, and verifies offline with the Node CLI, the Python `verify_receipt`, and the browser explorer code (signer `3HBA6G…2ULW`, tx_sha256 matches):

    node js/bin.js verify fixtures/live-mainnet-guard-check-2026-10-30.json --tx fixtures/live-mainnet-guard-check-2026-10-30.tx.b64
