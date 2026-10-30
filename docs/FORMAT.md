# Receipt format

One canonical-JSON object per line (`receipts.jsonl`), or one object in the Shield API response under `receipt`.

| field | meaning |
|---|---|
| `seq` | position in the chain, starting at 0 |
| `logged_at` | UTC time, `YYYY-MM-DDTHH:MM:SSZ` |
| `prev` | `hash` of the previous entry (`"0"*64` for seq 0) |
| `event` | what was decided, e.g. `{"kind":"tx_verdict","verdict":"BLOCK","tx_sha256":…,"msg_sha256":…,"reasons":[…]}` |
| `hash` | `sha256(canon({seq, logged_at, prev, event}))`, hex |
| `sig` | ed25519 signature over the 32 raw bytes of `hash`, base58 |
| `signer` | signer public key, base58 |
| `pq` | optional ML-DSA-44 (FIPS 204) co-signature over the same hash; not covered by `hash` |

`canon(o) = json.dumps(o, sort_keys=True, separators=(",",":"), ensure_ascii=True)`.

- `tx_sha256` is the sha256 of the exact transaction bytes Shield checked.
- `msg_sha256` is the sha256 of the message only, so it still matches after the wallet adds signatures.

Pin the signer out of band. The production Falcon Shield key is `3HBA6GFnDU6Ez5KrNtWrjLTkWFRJgcmVneEPukRJ2ULW`. A receipt signed by any other key proves nothing about Falcon Shield.

Receipts issued before Oct 30, 2026 omit `prev` and `event`. Verify those against the full chain with `--receipt` and the `receipts.jsonl` file.
