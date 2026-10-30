#!/usr/bin/env python3
"""Standalone verifier for hash-chained, ed25519-signed receipt logs (Falcon Shield / alertlog format).

Zero dependencies (stdlib only). Does not talk to any network or API: everything is recomputed from the file.

Entry format (one canonical-JSON object per line):
  {"seq","logged_at","prev","event","hash","sig","signer"}
  hash = sha256(canon({"seq","logged_at","prev","event"}))  (hex)
  sig  = ed25519 over the 32 raw bytes of `hash`, by `signer` (base58 pubkey); sig is base58 (64 bytes)
  prev = previous entry's hash ("0"*64 for seq 0)
canon(o) = json.dumps(o, sort_keys=True, separators=(",",":"))  [ensure_ascii=True]
"""
import sys, json, hashlib, base64, argparse

# ---------------------------------------------------------------- base58 / ed25519 (RFC 8032, verify only)
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_B58IDX = {c: i for i, c in enumerate(_B58)}


def b58decode(s):
    n = 0
    for c in s:
        if c not in _B58IDX:
            raise ValueError("invalid base58 character %r" % c)
        n = n * 58 + _B58IDX[c]
    body = n.to_bytes((n.bit_length() + 7) // 8, "big") if n else b""
    return b"\0" * (len(s) - len(s.lstrip("1"))) + body


_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _recover_x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decode_point(b):
    if len(b) != 32:
        return None
    n = int.from_bytes(b, "little")
    y, sign = n & ((1 << 255) - 1), n >> 255
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _encode(p):
    zi = pow(p[2], _P - 2, _P)
    x, y = p[0] * zi % _P, p[1] * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


_BY = 4 * pow(5, _P - 2, _P) % _P
_BASE = (_recover_x(_BY, 0), _BY, 1, _recover_x(_BY, 0) * _BY % _P)


def ed25519_verify(pub, msg, sig):
    """Cofactorless RFC 8032 verification; rejects S >= L and non-decodable points."""
    if len(pub) != 32 or len(sig) != 64:
        return False
    A, R = _decode_point(pub), _decode_point(sig[:32])
    s = int.from_bytes(sig[32:], "little")
    if A is None or R is None or s >= _L:
        return False
    k = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
    return _encode(_mul(s, _BASE)) == _encode(_add(R, _mul(k, A)))


# ---------------------------------------------------------------- canonical JSON / parsing
def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"))


def _no_dups(pairs):
    d = {}
    for k, v in pairs:
        if k in d:
            raise ValueError("duplicate key %r" % k)
        d[k] = v
    return d


def _reject_const(c):
    raise ValueError("non-finite number %s not allowed" % c)


def _parse_float(t):
    f = float(t)
    if f in (float("inf"), float("-inf")):
        raise ValueError("non-finite number %s not allowed" % t)
    return f


def parse_line(line):
    return json.loads(line, object_pairs_hook=_no_dups, parse_constant=_reject_const, parse_float=_parse_float)


GENESIS = "0" * 64
FIELDS = ("seq", "logged_at", "prev", "event", "hash", "sig", "signer")
_HEX = set("0123456789abcdef")


def _is_hex64(s):
    return isinstance(s, str) and len(s) == 64 and set(s) <= _HEX


def entry_hash(e):
    body = {k: e[k] for k in ("seq", "logged_at", "prev", "event")}
    return hashlib.sha256(canon(body).encode("ascii")).hexdigest()


# ---------------------------------------------------------------- chain verification
def verify_chain(text, pinned_signers=(), checkpoints=(), min_entries=0, allow_unsigned_fields=False):
    """Verify a receipt log given as str/bytes.

    pinned_signers: base58 pubkeys the verifier trusts (obtained out-of-band). Without a pin the result
                    proves internal consistency only, NOT who wrote the log.
    checkpoints:    iterable of (seq, hash_hex) the verifier saw earlier; the log must contain them (rollback/fork check).
    Returns dict: ok, authenticated, entries[], errors[], warnings[], head, count, signers.
    """
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as ex:
            return _fail("BAD_ENCODING", "file is not valid UTF-8: %s" % ex)
    pins = set(pinned_signers)
    errors, warnings, entries = [], [], []

    def err(i, code, msg):
        errors.append({"index": i, "code": code, "message": msg})

    lines = text.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    prev, prev_time, signer_seen, by_seq = GENESIS, None, [], {}
    for i, line in enumerate(lines):
        row = {"index": i, "ok": True, "problems": []}
        entries.append(row)

        def bad(code, msg):
            row["ok"] = False
            row["problems"].append(code)
            err(i, code, msg)
        if line.endswith("\r"):
            line = line[:-1]
        try:
            e = parse_line(line)
            if not isinstance(e, dict):
                raise ValueError("not a JSON object")
        except ValueError as ex:
            bad("BAD_JSON", "line %d: %s" % (i + 1, ex))
            continue
        row["entry"] = e
        missing = [f for f in FIELDS if f not in e]
        if missing:
            bad("MISSING_FIELD", "missing %s" % ",".join(missing))
            continue
        extra = [k for k in e if k not in FIELDS]
        if extra and not allow_unsigned_fields:
            bad("UNSIGNED_FIELD", "fields not covered by hash/signature: %s" % ",".join(extra))
        elif extra:
            warnings.append({"index": i, "code": "UNSIGNED_FIELD", "message": ",".join(extra)})
        types_ok = (isinstance(e["seq"], int) and not isinstance(e["seq"], bool) and isinstance(e["logged_at"], str)
                    and isinstance(e["prev"], str) and isinstance(e["hash"], str) and isinstance(e["sig"], str)
                    and isinstance(e["signer"], str))
        if not types_ok:
            bad("BAD_TYPE", "field has wrong JSON type")
            continue
        row["seq"] = e["seq"]
        if e["seq"] != i:
            bad("BAD_SEQ", "seq %s at position %d" % (e["seq"], i))
        if e["prev"] != prev:
            bad("BAD_PREV", "prev does not match hash of entry %d" % (i - 1) if i else "first entry prev is not all zeros")
        try:
            h = entry_hash(e)
        except (TypeError, ValueError) as ex:
            bad("BAD_JSON", "cannot canonicalise: %s" % ex)
            continue
        if not _is_hex64(e["hash"]) or h != e["hash"]:
            bad("BAD_HASH", "recomputed %s != stored %s" % (h[:16] + "…", str(e["hash"])[:16] + "…"))
        sig_ok = False
        try:
            pub, sig = b58decode(e["signer"]), b58decode(e["sig"])
            sig_ok = len(pub) == 32 and len(sig) == 64 and ed25519_verify(pub, bytes.fromhex(h), sig)
        except ValueError:
            pass
        # signature is checked over the RECOMPUTED hash, never the stored one
        if not sig_ok:
            bad("BAD_SIG", "ed25519 signature invalid for signer %s" % e["signer"])
        if pins and e["signer"] not in pins:
            bad("SIGNER_NOT_PINNED", "signer %s is not in the pinned set" % e["signer"])
        if e["signer"] not in signer_seen:
            signer_seen.append(e["signer"])
            if len(signer_seen) > 1:
                warnings.append({"index": i, "code": "SIGNER_CHANGED", "message": "signer changed to %s" % e["signer"]})
        if prev_time is not None and e["logged_at"] < prev_time:
            warnings.append({"index": i, "code": "TIME_REGRESSION", "message": "logged_at earlier than previous entry"})
        prev_time = e["logged_at"]
        by_seq[i] = e["hash"]
        prev = e["hash"]  # follow the stored hash so one bad entry is localised, not cascaded
    for seq, hx in checkpoints:
        if by_seq.get(seq) != hx:
            err(None, "CHECKPOINT_MISMATCH", "checkpoint %d:%s… not found in chain (truncated, rolled back, or forked)" % (seq, hx[:16]))
    if len(lines) < min_entries:
        err(None, "TOO_SHORT", "%d entries < required %d" % (len(lines), min_entries))
    if not lines:
        warnings.append({"index": None, "code": "EMPTY", "message": "no entries"})
    ok = not errors and bool(lines)
    return {"ok": ok, "authenticated": bool(ok and pins), "count": len(lines), "head": prev if lines else None,
            "head_seq": len(lines) - 1 if lines else None, "signers": signer_seen,
            "entries": entries, "errors": errors, "warnings": warnings}


def _fail(code, msg):
    return {"ok": False, "authenticated": False, "count": 0, "head": None, "head_seq": None, "signers": [],
            "entries": [], "errors": [{"index": None, "code": code, "message": msg}], "warnings": []}


def find_tx(report, tx_sha256):
    return [r["entry"] for r in report["entries"] if r.get("entry") and isinstance(r["entry"].get("event"), dict)
            and r["entry"]["event"].get("tx_sha256") == tx_sha256 and r["ok"]]


# ---------------------------------------------------------------- detached API receipt ({seq,hash,sig,signer,logged_at[,pq]})
def verify_detached(r, report, pinned_signers=(), pq_pubkey=None):
    """Check a receipt as returned by the verdict API against an independently verified chain.
    The API receipt omits `event`/`prev`, so we cannot recompute its hash alone: we require the hash to be
    present in the (verified) chain at the same seq, and re-check the signature ourselves."""
    out = {"ok": False, "problems": [], "pq": "absent"}
    try:
        pub, sig = b58decode(r["signer"]), b58decode(r["sig"])
        if not ed25519_verify(pub, bytes.fromhex(r["hash"]), sig):
            out["problems"].append("BAD_SIG")
    except (KeyError, ValueError, TypeError):
        out["problems"].append("MALFORMED")
        return out
    if pinned_signers and r["signer"] not in set(pinned_signers):
        out["problems"].append("SIGNER_NOT_PINNED")
    ent = next((x for x in report["entries"] if x.get("seq") == r.get("seq") and x["ok"]), None)
    if not ent or ent["entry"]["hash"] != r["hash"]:
        out["problems"].append("NOT_IN_CHAIN")
    pq = r.get("pq")
    if pq:
        out["pq"] = _verify_pq(pq, bytes.fromhex(r["hash"]), pq_pubkey)
        if out["pq"] == "invalid":
            out["problems"].append("BAD_PQ_SIG")
    out["ok"] = not out["problems"]
    return out


FALCON_SHIELD_SIGNER = "3HBA6GFnDU6Ez5KrNtWrjLTkWFRJgcmVneEPukRJ2ULW"  # production Falcon Shield receipt key


def verify_receipt(r, pinned_signers=(FALCON_SHIELD_SIGNER,), tx_b64=None):
    """Verify ONE receipt returned by the Shield API, with no chain and no network.
    Recomputes hash = sha256(canon({seq,logged_at,prev,event})), checks the ed25519 sig over it,
    and (optionally) that the receipt is about the exact transaction bytes you hold."""
    out = {"ok": False, "problems": [], "verdict": None, "tx_sha256": None}
    try:
        if not all(k in r for k in ("seq", "logged_at", "prev", "event", "hash", "sig", "signer")):
            out["problems"].append("MISSING_FIELDS")
            return out
        h = entry_hash(r)
        if h != r["hash"]:
            out["problems"].append("HASH_MISMATCH")
        if not ed25519_verify(b58decode(r["signer"]), bytes.fromhex(r["hash"]), b58decode(r["sig"])):
            out["problems"].append("BAD_SIG")
    except (KeyError, ValueError, TypeError):
        out["problems"].append("MALFORMED")
        return out
    if pinned_signers and r["signer"] not in set(pinned_signers):
        out["problems"].append("SIGNER_NOT_PINNED")
    ev = r.get("event") or {}
    out["verdict"], out["tx_sha256"] = ev.get("verdict"), ev.get("tx_sha256")
    if tx_b64 is not None:
        try:
            txh = hashlib.sha256(base64.b64decode("".join(tx_b64.split()), validate=True)).hexdigest()
        except Exception:
            out["problems"].append("BAD_TX")
            txh = None
        if txh and txh != ev.get("tx_sha256"):
            out["problems"].append("TX_MISMATCH")
    out["ok"] = not out["problems"]
    return out


def _verify_pq(pq, h, pq_pubkey):
    """ML-DSA-44 co-signature. Needs the PQ public key (pinned by pq.pk_sha256) and the optional `pqcrypto` package."""
    if pq_pubkey is None:
        return "not-checked (no --pq-pubkey)"
    if hashlib.sha256(pq_pubkey).hexdigest() != pq.get("pk_sha256"):
        return "invalid"
    try:
        from pqcrypto.sign import ml_dsa_44, slh_dsa_sha2_128s
        m = {"ML-DSA-44": ml_dsa_44, "SLH-DSA-SHA2-128s": slh_dsa_sha2_128s}[pq["alg"]]
    except Exception:
        return "not-checked (pqcrypto not installed)"
    try:
        res = m.verify(pq_pubkey, h, bytes.fromhex(pq["sig"]))
        return "invalid" if res is False else "valid"
    except Exception:
        return "invalid"


# ---------------------------------------------------------------- CLI
def _cp(s):
    seq, _, hx = s.partition(":")
    if not seq.isdigit() or not _is_hex64(hx):
        raise argparse.ArgumentTypeError("checkpoint must be SEQ:HASH64HEX")
    return int(seq), hx


def main(argv=None):
    ap = argparse.ArgumentParser(description="Verify a hash-chained, ed25519-signed receipt log offline.",
                                 epilog="Exit: 0 verified+authenticated, 1 verification FAILED, 2 usage/IO error, "
                                        "3 consistent but UNAUTHENTICATED (no --signer pin).")
    ap.add_argument("file", help="receipts.jsonl ('-' for stdin)")
    ap.add_argument("--signer", action="append", default=[], help="pinned base58 signer pubkey (repeatable). Get it out-of-band.")
    ap.add_argument("--checkpoint", action="append", default=[], type=_cp, metavar="SEQ:HASH",
                    help="entry you saw earlier; fail if absent (detects truncation/rollback/fork)")
    ap.add_argument("--min-entries", type=int, default=0)
    ap.add_argument("--allow-unsigned-fields", action="store_true")
    ap.add_argument("--allow-unpinned", action="store_true", help="exit 0 even without --signer (consistency only)")
    ap.add_argument("--tx", help="base64 tx (or file of it): show receipts whose tx_sha256 matches")
    ap.add_argument("--tx-sha256", help="hex sha256 of the tx bytes: show matching receipts")
    ap.add_argument("--receipt", help="API receipt JSON file to check against the chain")
    ap.add_argument("--pq-pubkey", help="file with raw ML-DSA-44 public key bytes (hex or binary) to check the receipt's pq co-signature")
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    a = ap.parse_args(argv)
    try:
        data = sys.stdin.buffer.read() if a.file == "-" else open(a.file, "rb").read()
    except OSError as ex:
        print("error:", ex, file=sys.stderr)
        return 2
    rep = verify_chain(data, a.signer, a.checkpoint, a.min_entries, a.allow_unsigned_fields)
    extra = {}
    txh = a.tx_sha256
    if a.tx:
        try:
            raw = open(a.tx).read().strip() if len(a.tx) < 4096 and __import__("os").path.exists(a.tx) else a.tx
            txh = hashlib.sha256(base64.b64decode(raw, validate=True)).hexdigest()
        except Exception as ex:
            print("error: bad --tx:", ex, file=sys.stderr)
            return 2
    if txh:
        extra["tx_matches"] = [{"seq": e["seq"], "verdict": e["event"].get("verdict"), "reasons": e["event"].get("reasons"),
                                "logged_at": e["logged_at"], "hash": e["hash"]} for e in find_tx(rep, txh.lower())]
        extra["tx_sha256"] = txh.lower()
    if a.receipt:
        try:
            pqk = None
            if a.pq_pubkey:
                raw = open(a.pq_pubkey, "rb").read().strip()
                try:
                    pqk = bytes.fromhex(raw.decode())
                except ValueError:
                    pqk = raw
            doc = json.load(open(a.receipt))
            rc = doc["receipt"] if isinstance(doc, dict) and "receipt" in doc else doc
            extra["receipt_check"] = verify_detached(rc, rep, a.signer, pqk)
        except (OSError, ValueError) as ex:
            print("error: bad --receipt:", ex, file=sys.stderr)
            return 2
    code = 1 if not rep["ok"] or (extra.get("receipt_check") and not extra["receipt_check"]["ok"]) else (0 if rep["authenticated"] or a.allow_unpinned else 3)
    if a.json:
        slim = {k: v for k, v in rep.items() if k != "entries"}
        slim["bad_entries"] = [r["index"] for r in rep["entries"] if not r["ok"]]
        print(json.dumps({**slim, **extra, "exit": code}, indent=1))
    else:
        print("entries: %d   head: seq %s  %s" % (rep["count"], rep["head_seq"], rep["head"]))
        print("signers: %s" % (", ".join(rep["signers"]) or "-"))
        for w in rep["warnings"]:
            print("  warn  %s %s" % (w["code"], ("#%s " % w["index"] if w["index"] is not None else "") + w["message"]))
        for x in rep["errors"][:50]:
            print("  FAIL  %s %s" % (x["code"], ("#%s " % x["index"] if x["index"] is not None else "") + x["message"]))
        if len(rep["errors"]) > 50:
            print("  ... %d more errors" % (len(rep["errors"]) - 50))
        if "tx_sha256" in extra:
            print("tx_sha256 %s: %d matching receipt(s)" % (extra["tx_sha256"], len(extra["tx_matches"])))
            for m in extra["tx_matches"]:
                print("  seq %d  %s  %s  %s" % (m["seq"], m["verdict"], m["logged_at"], "; ".join(m["reasons"] or [])))
        if "receipt_check" in extra:
            print("api receipt: %s %s  pq=%s" % ("OK" if extra["receipt_check"]["ok"] else "FAIL", ",".join(extra["receipt_check"]["problems"]), extra["receipt_check"]["pq"]))
        if not rep["ok"]:
            print("RESULT: FAILED")
        elif rep["authenticated"]:
            print("RESULT: VERIFIED — chain intact, every entry signed by a pinned signer")
        else:
            print("RESULT: CONSISTENT BUT UNAUTHENTICATED — chain is intact but no --signer pin given, so anyone could have written it")
    return code


if __name__ == "__main__":
    sys.exit(main())
