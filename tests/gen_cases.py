"""Generate tamper/edge-case chains + expected outcomes (hand-specified, NOT derived from the verifier).
Needs `cryptography` (dev-only) to sign synthetic chains. Output: tests/cases/*.jsonl and tests/cases/expected.json"""
import json, os, sys, hashlib, copy
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "cases")
os.makedirs(OUT, exist_ok=True)
sys.path.insert(0, os.path.join(HERE, "..", "python"))
import receipt_verify as rv

L = rv._L
ALPH = rv._B58


def b58(b):
    n = int.from_bytes(b, "big")
    s = ""
    while n:
        n, r = divmod(n, 58)
        s = ALPH[r] + s
    return "1" * (len(b) - len(b.lstrip(b"\0"))) + s


class Key:
    def __init__(s, seed):
        s.k = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(seed).digest())
        s.pub = b58(s.k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))

    def sign(s, h):
        return b58(s.k.sign(bytes.fromhex(h)))


CANON = rv.canon


def hash_of(e):
    return hashlib.sha256(CANON({k: e[k] for k in ("seq", "logged_at", "prev", "event")}).encode()).hexdigest()


def make_chain(key, events):
    out, prev = [], "0" * 64
    for i, ev in enumerate(events):
        body = {"seq": i, "logged_at": "2026-10-28T10:%02d:%02dZ" % (i // 60, i % 60), "prev": prev, "event": ev}
        h = hashlib.sha256(CANON(body).encode()).hexdigest()
        out.append({**body, "hash": h, "sig": key.sign(h), "signer": key.pub})
        prev = h
    return out


def rehash(e, key=None):
    e["hash"] = hash_of(e)
    if key:
        e["sig"] = key.sign(e["hash"])
        e["signer"] = key.pub


def dump(es):
    return "".join(CANON(e) + "\n" for e in es)


cases, exp = {}, {}


def add(name, text, ok, codes, pins=None, checkpoints=None, authenticated=None):
    cases[name] = text if isinstance(text, bytes) else text.encode("utf-8", "surrogatepass")
    exp[name] = {"ok": ok, "codes": sorted(set(codes), key=str), "pins": pins or [], "checkpoints": checkpoints or [], "authenticated": authenticated}


KEY, EVIL = Key(b"a22-test-key"), Key(b"a22-attacker")
FIX = os.path.join(HERE, "..", "fixtures", "real-44.jsonl")
real = [json.loads(l) for l in open(FIX)]
N = len(real)  # 44
PIN = real[0]["signer"]
H = N - 1
add("real_ok", open(FIX).read(), True, [], [PIN], authenticated=True)
add("real_unpinned", dump(real), True, [], [], authenticated=False)

# 1 edit event content (flip a BLOCK to ALLOW) without touching hash/sig
t = copy.deepcopy(real)
i = next(i for i, e in enumerate(t) if e["event"]["verdict"] == "BLOCK" and i < N - 2)
t[i]["event"]["verdict"] = "ALLOW"
add("edit_event", dump(t), False, [(i, "BAD_HASH"), (i, "BAD_SIG")], [PIN])

# 2 edit + recompute hash but attacker cannot sign
t = copy.deepcopy(real)
t[i]["event"]["verdict"] = "ALLOW"
t[i]["hash"] = hash_of(t[i])
add("edit_rehash", dump(t), False, [(i, "BAD_SIG"), (i + 1, "BAD_PREV")], [PIN])

# 3 edit + rehash + re-sign downstream with attacker key: internally consistent forgery
t = copy.deepcopy(real)
t[i]["event"]["verdict"] = "ALLOW"
for j in range(i, N):
    if j > i:
        t[j]["prev"] = t[j - 1]["hash"]
    rehash(t[j], EVIL)
add("forged_resign_unpinned", dump(t), True, [], [], authenticated=False)
add("forged_resign_pinned", dump(t), False, [(j, "SIGNER_NOT_PINNED") for j in range(i, N)], [PIN])

# 4 delete a middle entry
t = copy.deepcopy(real)
del t[10]
add("delete_middle", dump(t), False, [(10, "BAD_PREV")] + [(j, "BAD_SEQ") for j in range(10, N - 1)], [PIN])

# 5 swap two adjacent entries
t = copy.deepcopy(real)
t[7], t[8] = t[8], t[7]
add("swap_adjacent", dump(t), False, [(7, "BAD_SEQ"), (7, "BAD_PREV"), (8, "BAD_SEQ"), (8, "BAD_PREV"), (9, "BAD_PREV")], [PIN])

# 6 truncation: invisible without a checkpoint (documented limit), caught with one
t = real[:30]
add("truncate_no_checkpoint", dump(t), True, [], [PIN], authenticated=True)
add("truncate_with_checkpoint", dump(t), False, [(None, "CHECKPOINT_MISMATCH")], [PIN], [[H, real[H]["hash"]]])
add("checkpoint_ok", dump(real), True, [], [PIN], [[H, real[H]["hash"]], [0, real[0]["hash"]]], authenticated=True)

# 7 fork: same prefix, validly-signed (by attacker) different continuation
ev = {"seq": 20, "logged_at": "2026-10-28T11:00:00Z", "prev": real[19]["hash"], "event": {"x": 1}}
rehash(ev, EVIL)
add("fork_checkpoint", dump(real[:20] + [ev]), False, [(None, "CHECKPOINT_MISMATCH")], [], [[H, real[H]["hash"]]])

# 8 signature attacks
t = copy.deepcopy(real)
sb = bytearray(rv.b58decode(t[3]["sig"]))
sb[10] ^= 1
t[3]["sig"] = b58(bytes(sb))
add("sig_bitflip", dump(t), False, [(3, "BAD_SIG")], [PIN])
t = copy.deepcopy(real)
t[3]["signer"] = EVIL.pub
add("signer_swapped", dump(t), False, [(3, "BAD_SIG"), (3, "SIGNER_NOT_PINNED")], [PIN])
t = copy.deepcopy(real)
sb = rv.b58decode(t[3]["sig"])
t[3]["sig"] = b58(sb[:32] + (int.from_bytes(sb[32:], "little") + L).to_bytes(32, "little"))
add("sig_malleated_S_plus_L", dump(t), False, [(3, "BAD_SIG")], [PIN])
t = copy.deepcopy(real)
t[3]["sig"] = "0OIl-not-base58"
add("sig_garbage", dump(t), False, [(3, "BAD_SIG")], [PIN])
t = copy.deepcopy(real)
t[3]["hash"] = t[3]["hash"].upper()
add("hash_uppercase", dump(t), False, [(3, "BAD_HASH"), (4, "BAD_PREV")], [PIN])

# 9 structural
t = copy.deepcopy(real)
t[2]["note"] = "trust me"
add("unsigned_extra_field", dump(t), False, [(2, "UNSIGNED_FIELD")], [PIN])
t = copy.deepcopy(real)
del t[2]["sig"]
add("missing_field", dump(t), False, [(2, "MISSING_FIELD"), (3, "BAD_PREV")], [PIN])
t = copy.deepcopy(real)
t[2]["seq"] = 2.0
add("seq_float", dump(t), False, [(2, "BAD_TYPE"), (3, "BAD_PREV")], [PIN])
t = copy.deepcopy(real)
t[2]["seq"] = True
add("seq_bool", dump(t), False, [(2, "BAD_TYPE"), (3, "BAD_PREV")], [PIN])
ls = dump(real).split("\n")
ls[5] = '{"seq":5,"seq":5}'
add("duplicate_key", "\n".join(ls), False, [(5, "BAD_JSON"), (6, "BAD_PREV")], [PIN])
ls = dump(real).split("\n")
ls[5] = ls[5].replace('"seq":5', '"seq":NaN')
add("nan_literal", "\n".join(ls), False, [(5, "BAD_JSON"), (6, "BAD_PREV")], [PIN])
ls = dump(real).split("\n")
ls[5] = ls[5][:-3]
add("truncated_json_line", "\n".join(ls), False, [(5, "BAD_JSON"), (6, "BAD_PREV")], [PIN])
ls = dump(real).split("\n")
ls.insert(5, "")
add("blank_interior_line", "\n".join(ls), False, [(5, "BAD_JSON")] + [(j, "BAD_SEQ") for j in range(6, N + 1)], [PIN])
add("crlf_line_endings", dump(real).replace("\n", "\r\n"), True, [], [PIN], authenticated=True)
add("utf8_bom", b"\xef\xbb\xbf" + dump(real).encode(), False, [(0, "BAD_JSON"), (1, "BAD_PREV")], [PIN])
add("invalid_utf8", dump(real).encode() + b"\xff\xfe\n", False, [(None, "BAD_ENCODING")], [PIN])
add("empty_file", "", False, [], [PIN])
add("no_trailing_newline", dump(real).rstrip("\n"), True, [], [PIN], authenticated=True)

# 10 canonicalisation torture (synthetic chain signed by a test key)
torture = [
    {"kind": "unicode", "s": "sends 0.01 SOL to 8Lj… — \U0001F600 é中", "del": "\x7f", "ctl": "\x00\x01\x1f\b\f\n\r\t\"\\/"},
    {"kind": "lone_surrogates", "s": "\ud800 x \udfff"},
    {"order": {"\uffff": 1, "\U00010000": 2, "\ud7ff": 3, "": 4, "a": 5, "B": 6, "\ue000": 7, "ab": 8, "a ": 9}},
    {"floats": [0.1, 100.0, 1e-7, 1e16, 1e15, 123456789012345678.0, 5e-324, 1.7976931348623157e308, -0.0, 0.0, 1.5e-5, 0.0001, 2.5e22, 1e22, 12345.678, -1e-10, 4.35, 0.3]},
    {"ints": [0, -1, 2 ** 53 + 1, 2 ** 70, -(2 ** 100), 9007199254740993], "bools": [True, False, None], "nested": [[], {}, [[{"k": [1, 2, {"z": None}]}]]]},
]
tc = make_chain(KEY, torture)
add("canon_torture_ok", dump(tc), True, [], [KEY.pub], authenticated=True)
t = copy.deepcopy(tc)
t[3]["event"]["floats"][1] = 100  # int 100 vs float 100.0 must change the hash
add("canon_float_vs_int", dump(t), False, [(3, "BAD_HASH"), (3, "BAD_SIG")], [KEY.pub])

for n, b in cases.items():
    open(os.path.join(OUT, n + ".jsonl"), "wb").write(b)
json.dump(exp, open(os.path.join(OUT, "expected.json"), "w"), indent=1)
print(len(cases), "cases")
