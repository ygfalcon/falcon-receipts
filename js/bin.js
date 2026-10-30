#!/usr/bin/env node
// falcon-receipts verify <response.json> [--tx <base64|file>] [--any-signer]   |   falcon-receipts chain <receipts.jsonl> [--signer K]...
const fs = require("fs"), R = require("./receipt-verify.js"), a = process.argv.slice(2);
const opt = (f) => { const i = a.indexOf(f); return i >= 0 ? a[i + 1] : undefined; };
if (a[0] === "verify" && a[1]) {
  const o = a.includes("--any-signer") ? { pinnedSigners: [] } : {}; let tx = opt("--tx");
  if (tx && fs.existsSync(tx)) tx = fs.readFileSync(tx, "utf8"); if (tx) o.txBase64 = tx;
  const r = R.verifyReceipt(fs.readFileSync(a[1] === "-" ? 0 : a[1], "utf8"), o);
  console.log(JSON.stringify(r, null, 1)); process.exit(r.ok ? 0 : 1);
} else if (a[0] === "chain" && a[1]) { process.argv.splice(2, 1); require("./cli.js"); }
else { console.error("usage: falcon-receipts verify <response.json> [--tx B64|FILE] [--any-signer]\n       falcon-receipts chain <receipts.jsonl> [--signer PUBKEY]... [--checkpoint SEQ:HASH]"); process.exit(2); }
