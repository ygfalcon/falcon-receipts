#!/usr/bin/env node
// node js/cli.js receipts.jsonl --signer <base58> [--checkpoint SEQ:HASH] [--json]
// Exit: 0 verified+authenticated, 1 FAILED, 2 usage/IO, 3 consistent but unauthenticated.
const fs = require("fs"), RV = require("./receipt-verify.js");
const a = process.argv.slice(2), file = a.find((x, i) => !x.startsWith("--") && !["--signer", "--checkpoint", "--tx-sha256"].includes(a[i - 1]));
const all = (f) => a.flatMap((x, i) => (x === f ? [a[i + 1]] : []));
if (!file) { console.error("usage: cli.js FILE [--signer PUBKEY]... [--checkpoint SEQ:HASH]... [--tx-sha256 HEX] [--allow-unpinned] [--json]"); process.exit(2); }
let text; try { text = RV.decodeUtf8(new Uint8Array(fs.readFileSync(file === "-" ? 0 : file))); } catch (e) { console.error("error:", e.message); process.exit(2); }
const r = RV.verifyChain(text, { pinnedSigners: all("--signer"), checkpoints: all("--checkpoint").map((s) => [parseInt(s.split(":")[0], 10), s.split(":")[1]]) });
const code = !r.ok ? 1 : (r.authenticated || a.includes("--allow-unpinned") ? 0 : 3);
const tx = all("--tx-sha256")[0] ? RV.findTx(r, all("--tx-sha256")[0].toLowerCase()).map((e) => ({ seq: Number(e.seq), verdict: e.event.verdict, hash: e.hash })) : undefined;
if (a.includes("--json")) console.log(JSON.stringify({ ok: r.ok, authenticated: r.authenticated, count: r.count, head: r.head, head_seq: r.head_seq, signers: r.signers, errors: r.errors, warnings: r.warnings, bad_entries: r.entries.filter((x) => !x.ok).map((x) => x.index), tx_matches: tx, exit: code }, null, 1));
else {
  console.log(`entries: ${r.count}   head: seq ${r.head_seq}  ${r.head}\nsigners: ${r.signers.join(", ") || "-"}`);
  r.warnings.forEach((w) => console.log(`  warn  ${w.code} ${w.index !== null ? "#" + w.index + " " : ""}${w.message}`));
  r.errors.slice(0, 50).forEach((x) => console.log(`  FAIL  ${x.code} ${x.index !== null ? "#" + x.index + " " : ""}${x.message}`));
  if (tx) tx.forEach((m) => console.log(`  tx match: seq ${m.seq} ${m.verdict}`));
  console.log(!r.ok ? "RESULT: FAILED" : r.authenticated ? "RESULT: VERIFIED — chain intact, every entry signed by a pinned signer" : "RESULT: CONSISTENT BUT UNAUTHENTICATED — chain is intact but no --signer pin given, so anyone could have written it");
}
process.exit(code);
