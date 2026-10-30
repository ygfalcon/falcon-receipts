const R = require("../js/receipt-verify.js"), fs = require("fs"), path = require("path");
const D = path.join(__dirname, "..", "fixtures", "single"), P = { pinnedSigners: ["GgHie9LuzXPAU64iLsfA6jxbZoXv9RaSZk6rsMz44XpY"] };
let n = 0, ok = 0; const chk = (c, m) => { n++; if (c) ok++; console.log((c ? "PASS " : "FAIL ") + m); };
for (const name of ["drainer_approve_plus_sweep", "jupiter_swap"]) {
  const t = fs.readFileSync(path.join(D, name + ".json"), "utf8"), tx = fs.readFileSync(path.join(D, name + ".tx"), "utf8");
  const other = name === "jupiter_swap" ? "drainer_approve_plus_sweep" : "jupiter_swap";
  chk(R.verifyReceipt(t, { ...P, txBase64: tx }).ok, name + " valid");
  chk(R.verifyReceipt(t).problems.includes("SIGNER_NOT_PINNED"), name + " rejected under production pin");
  const j = JSON.parse(t); j.receipt.event.verdict = j.receipt.event.verdict === "NO_MATCH" ? "BLOCK" : "NO_MATCH";
  chk(R.verifyReceipt(JSON.stringify(j), P).problems.includes("HASH_MISMATCH"), name + " verdict tamper");
  chk(R.verifyReceipt(t, { ...P, txBase64: fs.readFileSync(path.join(D, other + ".tx"), "utf8") }).problems.includes("TX_MISMATCH"), name + " wrong tx");
}
console.log(`single-js: ${ok}/${n} passed`); process.exit(ok === n ? 0 : 1);
