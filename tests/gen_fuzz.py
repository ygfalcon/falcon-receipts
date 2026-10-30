"""Random JSON docs -> {raw JSON text, python canon}. JS must reproduce canon byte-for-byte from the raw text."""
import json, random, struct, sys, os
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "python"))
import receipt_verify as rv
random.seed(22)
POOL = ["a", "Z", " ", "é", "…", "中", "\U0001F600", "\U00010000", "￿", "", "퟿", "\x00", "\x1f", "\x7f", "\n", "\t", '"', "\\", "/", "\ud800", "\udc00", " "]
def rstr(): return "".join(random.choice(POOL) for _ in range(random.randint(0, 8)))
def rfloat():
    while True:
        f = struct.unpack("<d", struct.pack("<Q", random.getrandbits(64)))[0]
        if f == f and abs(f) != float("inf"): break
    return random.choice([f, round(f % 1000, random.randint(0, 6)), float(random.randint(-10**6, 10**6)), random.uniform(-1, 1) * 10 ** random.randint(-30, 30)])
def rval(d=0):
    k = random.randint(0, 8 if d < 4 else 5)
    if k == 0: return None
    if k == 1: return random.choice([True, False])
    if k in (2, 3): return random.choice([random.randint(-10**3, 10**3), random.randint(-10**30, 10**30), 0, -1, 2**63, 2**53 + 1])
    if k == 4: return rfloat()
    if k == 5: return rstr()
    if k in (6, 7): return [rval(d + 1) for _ in range(random.randint(0, 4))]
    return {rstr(): rval(d + 1) for _ in range(random.randint(0, 5))}
out = []
for _ in range(3000):
    v = rval()
    out.append({"raw": json.dumps(v, ensure_ascii=random.random() < 0.5, indent=random.choice([None, 1])), "canon": rv.canon(json.loads(json.dumps(v)))})
json.dump(out, open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases", "fuzz.json"), "w"))
print(len(out), "fuzz docs; distinct canon:", len({o["canon"] for o in out}))
