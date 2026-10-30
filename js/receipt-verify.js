/* Standalone receipt-chain verifier (browser + Node). No dependencies, no network access.
 * Mirrors python/receipt_verify.py exactly; see docs/FORMAT.md for the byte-level spec.
 * hash = sha256(canon({seq,logged_at,prev,event})); sig = ed25519(signer, hashBytes). */
(function (root, factory) {
  if (typeof module === "object" && module.exports) module.exports = factory();
  else root.ReceiptVerify = factory();
})(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // ---------------------------------------------------------------- hex / base58
  const hex = (u8) => Array.from(u8, (b) => b.toString(16).padStart(2, "0")).join("");
  const unhex = (s) => { const o = new Uint8Array(s.length / 2); for (let i = 0; i < o.length; i++) o[i] = parseInt(s.substr(i * 2, 2), 16); return o; };
  const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  function b58decode(s) {
    let n = 0n;
    for (const c of s) { const i = B58.indexOf(c); if (i < 0) throw new Error("invalid base58 character"); n = n * 58n + BigInt(i); }
    let h = n === 0n ? "" : n.toString(16); if (h.length % 2) h = "0" + h;
    let z = 0; while (z < s.length && s[z] === "1") z++;
    const body = unhex(h), out = new Uint8Array(z + body.length); out.set(body, z); return out;
  }
  const ascii = (s) => { const o = new Uint8Array(s.length); for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); if (c > 127) throw new Error("non-ASCII in canonical text"); o[i] = c; } return o; };

  // ---------------------------------------------------------------- SHA-256
  const K256 = new Uint32Array([0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]);
  function sha256(m) {
    const l = m.length, n = ((l + 9 + 63) >> 6) << 6, b = new Uint8Array(n); b.set(m); b[l] = 0x80;
    const dv = new DataView(b.buffer); dv.setUint32(n - 8, Math.floor(l / 0x20000000)); dv.setUint32(n - 4, (l << 3) >>> 0);
    const H = new Uint32Array([0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19]), w = new Uint32Array(64);
    const rr = (x, k) => (x >>> k) | (x << (32 - k));
    for (let o = 0; o < n; o += 64) {
      for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4);
      for (let i = 16; i < 64; i++) { const s0 = rr(w[i-15],7) ^ rr(w[i-15],18) ^ (w[i-15] >>> 3), s1 = rr(w[i-2],17) ^ rr(w[i-2],19) ^ (w[i-2] >>> 10); w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0; }
      let [a,b2,c,d,e,f,g,h] = H;
      for (let i = 0; i < 64; i++) {
        const t1 = (h + (rr(e,6) ^ rr(e,11) ^ rr(e,25)) + ((e & f) ^ (~e & g)) + K256[i] + w[i]) | 0;
        const t2 = ((rr(a,2) ^ rr(a,13) ^ rr(a,22)) + ((a & b2) ^ (a & c) ^ (b2 & c))) | 0;
        h = g; g = f; f = e; e = (d + t1) | 0; d = c; c = b2; b2 = a; a = (t1 + t2) | 0;
      }
      H[0] += a; H[1] += b2; H[2] += c; H[3] += d; H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    }
    const out = new Uint8Array(32), odv = new DataView(out.buffer); for (let i = 0; i < 8; i++) odv.setUint32(i * 4, H[i]); return out;
  }

  // ---------------------------------------------------------------- SHA-512 (BigInt)
  const M64 = (1n << 64n) - 1n;
  const K512 = ("428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc 3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118 d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2 72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694 e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65 2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5 983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4 c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70 27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df 650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30 d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8 19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8 391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3 748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec 90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178 06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b 28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c 4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817").split(" ").map((x) => BigInt("0x" + x));
  function sha512(m) {
    const l = m.length, n = ((l + 17 + 127) >> 7) << 7, b = new Uint8Array(n); b.set(m); b[l] = 0x80;
    const dv = new DataView(b.buffer); dv.setUint32(n - 4, (l << 3) >>> 0); dv.setUint32(n - 8, Math.floor(l / 0x20000000));
    const H = [0x6a09e667f3bcc908n,0xbb67ae8584caa73bn,0x3c6ef372fe94f82bn,0xa54ff53a5f1d36f1n,0x510e527fade682d1n,0x9b05688c2b3e6c1fn,0x1f83d9abfb41bd6bn,0x5be0cd19137e2179n];
    const rr = (x, k) => ((x >> BigInt(k)) | (x << BigInt(64 - k))) & M64, w = new Array(80);
    for (let o = 0; o < n; o += 128) {
      for (let i = 0; i < 16; i++) w[i] = dv.getBigUint64(o + i * 8);
      for (let i = 16; i < 80; i++) { const s0 = rr(w[i-15],1) ^ rr(w[i-15],8) ^ (w[i-15] >> 7n), s1 = rr(w[i-2],19) ^ rr(w[i-2],61) ^ (w[i-2] >> 6n); w[i] = (w[i-16] + s0 + w[i-7] + s1) & M64; }
      let [a,b2,c,d,e,f,g,h] = H;
      for (let i = 0; i < 80; i++) {
        const t1 = (h + (rr(e,14) ^ rr(e,18) ^ rr(e,41)) + ((e & f) ^ (~e & M64 & g)) + K512[i] + w[i]) & M64;
        const t2 = ((rr(a,28) ^ rr(a,34) ^ rr(a,39)) + ((a & b2) ^ (a & c) ^ (b2 & c))) & M64;
        h = g; g = f; f = e; e = (d + t1) & M64; d = c; c = b2; b2 = a; a = (t1 + t2) & M64;
      }
      const v = [a,b2,c,d,e,f,g,h]; for (let i = 0; i < 8; i++) H[i] = (H[i] + v[i]) & M64;
    }
    const out = new Uint8Array(64), odv = new DataView(out.buffer); for (let i = 0; i < 8; i++) odv.setBigUint64(i * 8, H[i]); return out;
  }

  // ---------------------------------------------------------------- Ed25519 verify (RFC 8032, cofactorless, S < L enforced)
  const P = (1n << 255n) - 19n, L = (1n << 252n) + 27742317777372353535851937790883648493n;
  const mod = (a) => { const r = a % P; return r >= 0n ? r : r + P; };
  const pow = (b, e, m = P) => { let r = 1n; b %= m; while (e > 0n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
  const inv = (a) => pow(mod(a), P - 2n);
  const D = mod(-121665n * inv(121666n)), SQRTM1 = pow(2n, (P - 1n) / 4n);
  function recoverX(y, sign) {
    if (y >= P) return null;
    const x2 = mod((y * y - 1n) * inv(D * y * y + 1n));
    if (x2 === 0n) return sign ? null : 0n;
    let x = pow(x2, (P + 3n) / 8n);
    if (mod(x * x - x2) !== 0n) x = mod(x * SQRTM1);
    if (mod(x * x - x2) !== 0n) return null;
    if ((x & 1n) !== BigInt(sign)) x = P - x;
    return x;
  }
  const leToBig = (u8) => { let n = 0n; for (let i = u8.length - 1; i >= 0; i--) n = (n << 8n) | BigInt(u8[i]); return n; };
  function decodePoint(u8) {
    if (u8.length !== 32) return null;
    const n = leToBig(u8), y = n & ((1n << 255n) - 1n), x = recoverX(y, Number(n >> 255n));
    return x === null ? null : [x, y, 1n, mod(x * y)];
  }
  function padd(p, q) {
    const a = mod((p[1] - p[0]) * (q[1] - q[0])), b = mod((p[1] + p[0]) * (q[1] + q[0])), c = mod(2n * p[3] * q[3] * D), d = mod(2n * p[2] * q[2]);
    const e = b - a, f = d - c, g = d + c, h = b + a; return [mod(e * f), mod(g * h), mod(f * g), mod(e * h)];
  }
  function pmul(s, p) { let q = [0n, 1n, 1n, 0n]; while (s > 0n) { if (s & 1n) q = padd(q, p); p = padd(p, p); s >>= 1n; } return q; }
  function encodePoint(p) {
    const zi = inv(p[2]), x = mod(p[0] * zi), y = mod(p[1] * zi), v = y | ((x & 1n) << 255n), o = new Uint8Array(32);
    for (let i = 0; i < 32; i++) o[i] = Number((v >> BigInt(8 * i)) & 0xffn); return o;
  }
  const BY = mod(4n * inv(5n)), BX = recoverX(BY, 0), BASE = [BX, BY, 1n, mod(BX * BY)];
  function ed25519Verify(pub, msg, sig) {
    if (pub.length !== 32 || sig.length !== 64) return false;
    const A = decodePoint(pub), R = decodePoint(sig.subarray(0, 32)), s = leToBig(sig.subarray(32));
    if (!A || !R || s >= L) return false;
    const buf = new Uint8Array(64 + msg.length); buf.set(sig.subarray(0, 32)); buf.set(pub, 32); buf.set(msg, 64);
    const k = leToBig(sha512(buf)) % L;
    return hex(encodePoint(pmul(s, BASE))) === hex(encodePoint(padd(R, pmul(k, A))));
  }

  // ---------------------------------------------------------------- strict JSON parser (ints -> BigInt, floats -> Number, dup keys rejected)
  function parseJSON(src) {
    let i = 0;
    const fail = (m) => { throw new Error(m + " at char " + i); };
    const ws = () => { while (i < src.length && " \t\n\r".indexOf(src[i]) >= 0) i++; };
    function str() {
      i++; let out = "";
      for (;;) {
        if (i >= src.length) fail("unterminated string");
        const c = src[i];
        if (c === '"') { i++; return out; }
        if (c.charCodeAt(0) < 0x20) fail("control character in string");
        if (c === "\\") {
          const e = src[i + 1]; i += 2;
          if (e === "u") { const h = src.substr(i, 4); if (!/^[0-9a-fA-F]{4}$/.test(h)) fail("bad \\u escape"); out += String.fromCharCode(parseInt(h, 16)); i += 4; }
          else { const m = { '"': '"', "\\": "\\", "/": "/", b: "\b", f: "\f", n: "\n", r: "\r", t: "\t" }[e]; if (m === undefined) fail("bad escape"); out += m; }
        } else { out += c; i++; }
      }
    }
    function val() {
      ws(); const c = src[i];
      if (c === "{") {
        i++; const o = Object.create(null); ws();
        if (src[i] === "}") { i++; return o; }
        for (;;) {
          ws(); if (src[i] !== '"') fail("expected key"); const k = str(); ws();
          if (src[i] !== ":") fail("expected ':'"); i++;
          if (k in o) fail("duplicate key " + JSON.stringify(k));
          o[k] = val(); ws();
          if (src[i] === ",") { i++; continue; } if (src[i] === "}") { i++; return o; } fail("expected ',' or '}'");
        }
      }
      if (c === "[") {
        i++; const a = []; ws(); if (src[i] === "]") { i++; return a; }
        for (;;) { a.push(val()); ws(); if (src[i] === ",") { i++; continue; } if (src[i] === "]") { i++; return a; } fail("expected ',' or ']'"); }
      }
      if (c === '"') return str();
      if (src.startsWith("true", i)) { i += 4; return true; }
      if (src.startsWith("false", i)) { i += 5; return false; }
      if (src.startsWith("null", i)) { i += 4; return null; }
      const m = /^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?/.exec(src.slice(i, i + 400));
      if (!m) fail("unexpected token"); i += m[0].length;
      if (m[2] === undefined && m[3] === undefined) return BigInt(m[0]);
      const f = Number(m[0]); if (!isFinite(f)) fail("non-finite number"); return f;
    }
    const v = val(); ws(); if (i !== src.length) fail("trailing data"); return v;
  }

  // ---------------------------------------------------------------- canonical JSON (exact port of Python json.dumps(sort_keys, (",",":"), ensure_ascii))
  function pyFloat(x) {
    if (Object.is(x, -0)) return "-0.0";
    const neg = x < 0 ? "-" : "", [mant, ex] = Math.abs(x).toExponential().split("e"), e = parseInt(ex, 10), digits = mant.replace(".", "");
    if (x === 0) return "0.0";
    if (e < -4 || e >= 16) return neg + digits[0] + (digits.length > 1 ? "." + digits.slice(1) : "") + "e" + (e < 0 ? "-" : "+") + String(Math.abs(e)).padStart(2, "0");
    if (e >= 0) { const ip = digits.length > e + 1 ? digits.slice(0, e + 1) : digits.padEnd(e + 1, "0"), fp = digits.length > e + 1 ? digits.slice(e + 1) : "0"; return neg + ip + "." + fp; }
    return neg + "0." + "0".repeat(-e - 1) + digits;
  }
  const SHORT = { 8: "\\b", 9: "\\t", 10: "\\n", 12: "\\f", 13: "\\r", 34: '\\"', 92: "\\\\" };
  function escStr(s) {
    let o = '"';
    for (let i = 0; i < s.length; i++) { const c = s.charCodeAt(i); o += SHORT[c] || (c < 0x20 || c > 0x7e ? "\\u" + c.toString(16).padStart(4, "0") : s[i]); }
    return o + '"';
  }
  function cmpCodepoints(a, b) {
    let i = 0, j = 0;
    while (i < a.length && j < b.length) { const x = a.codePointAt(i), y = b.codePointAt(j); if (x !== y) return x < y ? -1 : 1; i += x > 0xffff ? 2 : 1; j += y > 0xffff ? 2 : 1; }
    return (a.length - i) > 0 ? 1 : (b.length - j) > 0 ? -1 : 0;
  }
  function canon(v) {
    if (v === null) return "null";
    switch (typeof v) {
      case "boolean": return v ? "true" : "false";
      case "bigint": return v.toString();
      case "number": if (!isFinite(v)) throw new Error("non-finite number"); return pyFloat(v);
      case "string": return escStr(v);
    }
    if (Array.isArray(v)) return "[" + v.map(canon).join(",") + "]";
    return "{" + Object.keys(v).sort(cmpCodepoints).map((k) => escStr(k) + ":" + canon(v[k])).join(",") + "}";
  }

  // ---------------------------------------------------------------- chain verification
  const GENESIS = "0".repeat(64), FIELDS = ["seq", "logged_at", "prev", "event", "hash", "sig", "signer"], HEX64 = /^[0-9a-f]{64}$/;
  const entryHash = (e) => hex(sha256(ascii(canon({ seq: e.seq, logged_at: e.logged_at, prev: e.prev, event: e.event }))));

  function verifyChain(text, opts) {
    opts = opts || {};
    const pins = new Set(opts.pinnedSigners || []), checkpoints = opts.checkpoints || [], errors = [], warnings = [], entries = [];
    const err = (i, code, message) => errors.push({ index: i, code, message });
    const lines = text.split("\n"); if (lines.length && lines[lines.length - 1] === "") lines.pop();
    let prev = GENESIS, prevTime = null; const signers = [], bySeq = new Map();
    lines.forEach((raw, i) => {
      const row = { index: i, ok: true, problems: [] }; entries.push(row);
      const bad = (code, msg) => { row.ok = false; row.problems.push(code); err(i, code, msg); };
      const line = raw.endsWith("\r") ? raw.slice(0, -1) : raw;
      let e;
      try { e = parseJSON(line); if (e === null || typeof e !== "object" || Array.isArray(e)) throw new Error("not a JSON object"); }
      catch (ex) { bad("BAD_JSON", "line " + (i + 1) + ": " + ex.message); return; }
      const missing = FIELDS.filter((f) => !(f in e));
      if (missing.length) { bad("MISSING_FIELD", "missing " + missing.join(",")); return; }
      const extra = Object.keys(e).filter((k) => FIELDS.indexOf(k) < 0);
      if (extra.length && !opts.allowUnsignedFields) bad("UNSIGNED_FIELD", "fields not covered by hash/signature: " + extra.join(","));
      else if (extra.length) warnings.push({ index: i, code: "UNSIGNED_FIELD", message: extra.join(",") });
      if (!(typeof e.seq === "bigint" && typeof e.logged_at === "string" && typeof e.prev === "string" && typeof e.hash === "string" && typeof e.sig === "string" && typeof e.signer === "string")) { bad("BAD_TYPE", "field has wrong JSON type"); return; }
      row.entry = e; row.seq = Number(e.seq);
      if (e.seq !== BigInt(i)) bad("BAD_SEQ", "seq " + e.seq + " at position " + i);
      if (e.prev !== prev) bad("BAD_PREV", i ? "prev does not match hash of entry " + (i - 1) : "first entry prev is not all zeros");
      let h;
      try { h = entryHash(e); } catch (ex) { bad("BAD_JSON", "cannot canonicalise: " + ex.message); return; }
      if (!HEX64.test(e.hash) || h !== e.hash) bad("BAD_HASH", "recomputed " + h.slice(0, 16) + "… != stored " + e.hash.slice(0, 16) + "…");
      let sigOk = false;
      try { const pub = b58decode(e.signer), sig = b58decode(e.sig); sigOk = pub.length === 32 && sig.length === 64 && ed25519Verify(pub, unhex(h), sig); } catch (_) { /* invalid base58 -> bad sig */ }
      if (!sigOk) bad("BAD_SIG", "ed25519 signature invalid for signer " + e.signer);
      if (pins.size && !pins.has(e.signer)) bad("SIGNER_NOT_PINNED", "signer " + e.signer + " is not in the pinned set");
      if (signers.indexOf(e.signer) < 0) { signers.push(e.signer); if (signers.length > 1) warnings.push({ index: i, code: "SIGNER_CHANGED", message: "signer changed to " + e.signer }); }
      if (prevTime !== null && e.logged_at < prevTime) warnings.push({ index: i, code: "TIME_REGRESSION", message: "logged_at earlier than previous entry" });
      prevTime = e.logged_at; bySeq.set(i, e.hash); prev = e.hash;
    });
    for (const [seq, hx] of checkpoints) if (bySeq.get(seq) !== hx) err(null, "CHECKPOINT_MISMATCH", "checkpoint " + seq + ":" + hx.slice(0, 16) + "… not found in chain (truncated, rolled back, or forked)");
    if (lines.length < (opts.minEntries || 0)) err(null, "TOO_SHORT", lines.length + " entries < required " + opts.minEntries);
    if (!lines.length) warnings.push({ index: null, code: "EMPTY", message: "no entries" });
    const ok = !errors.length && lines.length > 0;
    return { ok, authenticated: ok && pins.size > 0, count: lines.length, head: lines.length ? prev : null, head_seq: lines.length ? lines.length - 1 : null, signers, entries, errors, warnings };
  }
  const decodeUtf8 = (u8) => new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(u8);
  const txSha256 = (u8) => hex(sha256(u8));
  function b64decode(s) { s = s.trim(); if (!/^[A-Za-z0-9+/]*={0,2}$/.test(s) || s.length % 4) throw new Error("not valid base64"); const bin = atob(s), o = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) o[i] = bin.charCodeAt(i); return o; }
  function findTx(report, txHash) { return report.entries.filter((r) => r.ok && r.entry && r.entry.event && r.entry.event.tx_sha256 === txHash).map((r) => r.entry); }

  const FALCON_SHIELD_SIGNER = "3HBA6GFnDU6Ez5KrNtWrjLTkWFRJgcmVneEPukRJ2ULW";
  // Verify ONE receipt from the Shield API (JSON text of the receipt, or of the whole API response), offline.
  function verifyReceipt(text, opts) {
    opts = opts || {}; const pins = new Set(opts.pinnedSigners || [FALCON_SHIELD_SIGNER]), problems = [];
    let r; try { r = parseJSON(text.trim()); } catch (ex) { return { ok: false, problems: ["BAD_JSON"], error: ex.message }; }
    if (r && typeof r === "object" && r.receipt && typeof r.receipt === "object") r = r.receipt;
    if (!r || typeof r !== "object" || FIELDS.some((f) => !(f in r))) return { ok: false, problems: ["MISSING_FIELDS"], hint: "older receipts omit prev/event; verify those against the full receipts.jsonl chain" };
    let h; try { h = entryHash(r); } catch (ex) { return { ok: false, problems: ["MALFORMED"] }; }
    if (h !== r.hash) problems.push("HASH_MISMATCH");
    let sigOk = false; try { const pub = b58decode(r.signer), sig = b58decode(r.sig); sigOk = pub.length === 32 && sig.length === 64 && ed25519Verify(pub, unhex(String(r.hash)), sig); } catch (_) {}
    if (!sigOk) problems.push("BAD_SIG");
    if (pins.size && !pins.has(r.signer)) problems.push("SIGNER_NOT_PINNED");
    const ev = r.event || {};
    if (opts.txBase64 != null) { try { if (txSha256(b64decode(opts.txBase64.replace(/\s+/g, ""))) !== ev.tx_sha256) problems.push("TX_MISMATCH"); } catch (_) { problems.push("BAD_TX"); } }
    return { ok: !problems.length, problems, signer: r.signer, seq: Number(r.seq), logged_at: r.logged_at, verdict: ev.verdict, reasons: ev.reasons, tx_sha256: ev.tx_sha256 };
  }

  return { verifyChain, verifyReceipt, FALCON_SHIELD_SIGNER, canon, parseJSON, entryHash, sha256, sha512, ed25519Verify, b58decode, hex, unhex, decodeUtf8, txSha256, b64decode, findTx, pyFloat };
});
