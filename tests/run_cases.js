const fs = require("fs"), path = require("path"), RV = require("../js/receipt-verify.js");
const dir = path.join(__dirname, "cases"), exp = JSON.parse(fs.readFileSync(path.join(dir, "expected.json"), "utf8")); let bad = 0;
const key = (c) => JSON.stringify([c[0] === null ? "None" : c[0], c[1]]), norm = (a) => [...new Set(a.map(key))].sort();
for (const name of Object.keys(exp).sort()) {
  const x = exp[name], buf = new Uint8Array(fs.readFileSync(path.join(dir, name + ".jsonl"))); let r;
  try { r = RV.verifyChain(RV.decodeUtf8(buf), { pinnedSigners: x.pins, checkpoints: x.checkpoints }); }
  catch (e) { r = { ok: false, authenticated: false, errors: [{ index: null, code: "BAD_ENCODING" }] }; }
  // Python sorts str(None)/ints as strings via key=str; compare as normalised sets instead
  const got = norm(r.errors.map((e) => [e.index, e.code])), want = norm(x.codes);
  const good = r.ok === x.ok && JSON.stringify(got) === JSON.stringify(want) && (x.authenticated === null || r.authenticated === x.authenticated);
  if (!good) bad++; console.log((good ? "PASS " : "FAIL ") + name + (good ? "" : "\n   got " + got + " ok=" + r.ok + "\n   want " + want + " ok=" + x.ok));
}
console.log(`node: ${Object.keys(exp).length - bad}/${Object.keys(exp).length} passed`); process.exit(bad ? 1 : 0);
