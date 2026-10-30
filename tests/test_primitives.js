const crypto = require("crypto"), fs = require("fs"), path = require("path"), RV = require("../js/receipt-verify.js");
let fails = 0; const t = (name, ok) => { if (!ok) fails++; console.log((ok ? "PASS " : "FAIL ") + name); };
const rnd = (n) => new Uint8Array(crypto.randomBytes(n));
// sha256/sha512 vs node over all lengths around block boundaries
let ok256 = true, ok512 = true;
for (let n = 0; n < 300; n++) { const m = rnd(n); ok256 &&= RV.hex(RV.sha256(m)) === crypto.createHash("sha256").update(m).digest("hex"); ok512 &&= RV.hex(RV.sha512(m)) === crypto.createHash("sha512").update(m).digest("hex"); }
t("sha256 == node for len 0..299", ok256); t("sha512 == node for len 0..299", ok512);
// RFC 8032 test vector 1 + 2
const v1 = ["d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "", "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"];
const v2 = ["3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72", "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"];
t("ed25519 RFC8032 vector 1", RV.ed25519Verify(RV.unhex(v1[0]), RV.unhex(v1[1]), RV.unhex(v1[2])));
t("ed25519 RFC8032 vector 2", RV.ed25519Verify(RV.unhex(v2[0]), RV.unhex(v2[1]), RV.unhex(v2[2])));
t("ed25519 rejects wrong message", !RV.ed25519Verify(RV.unhex(v2[0]), RV.unhex("73"), RV.unhex(v2[2])));
// random keys signed by node's OpenSSL, verified by our pure-JS; and 1-bit-flip rejection
let okSign = true, okFlip = true;
for (let i = 0; i < 40; i++) {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519"), pub = new Uint8Array(publicKey.export({ format: "der", type: "spki" }).subarray(-32)), msg = rnd(32), sig = new Uint8Array(crypto.sign(null, msg, privateKey));
  okSign &&= RV.ed25519Verify(pub, msg, sig); const bad = sig.slice(); bad[(i * 7) % 64] ^= 1 << (i % 8); okFlip &&= !RV.ed25519Verify(pub, msg, bad);
}
t("ed25519 pure-JS verifies 40 OpenSSL signatures", okSign); t("ed25519 rejects 40 bit-flipped signatures", okFlip);
t("base58 known: 1112 -> 00 00 00 0x", RV.hex(RV.b58decode("1112")) === "00000001");
// canonical-JSON differential fuzz against python json.dumps
const fz = JSON.parse(fs.readFileSync(path.join(__dirname, "cases", "fuzz.json"), "utf8")); let mism = 0, first = null;
for (const d of fz) { let c; try { c = RV.canon(RV.parseJSON(d.raw)); } catch (e) { c = "ERR " + e.message; } if (c !== d.canon) { mism++; first = first || { raw: d.raw, js: c, py: d.canon }; } }
t(`canon(js) == canon(python) on ${fz.length} random docs (${mism} mismatches)`, mism === 0); if (first) console.log(first);
// strict parser rejects
for (const [n, s] of [["leading zero", '{"a":01}'], ["trailing comma", "[1,]"], ["NaN", "NaN"], ["1e999", "1e999"], ["dup key", '{"a":1,"a":2}'], ["raw control char", '"a\tb"'], ["trailing junk", "1 2"], ["bad escape", '"\\x"']]) {
  let threw = false; try { RV.parseJSON(s); } catch (e) { threw = true; } t("parser rejects " + n, threw);
}
t("__proto__ key does not pollute", (() => { const o = RV.parseJSON('{"__proto__":{"x":1}}'); return Object.keys(o).join() === "__proto__" && ({}).x === undefined; })());
process.exit(fails ? 1 : 0);
