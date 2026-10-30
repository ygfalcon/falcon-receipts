import json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(HERE, "..", "python"))
import receipt_verify as rv
exp = json.load(open(os.path.join(HERE, "cases", "expected.json"))); bad = 0
for name, x in sorted(exp.items()):
    r = rv.verify_chain(open(os.path.join(HERE, "cases", name + ".jsonl"), "rb").read(), x["pins"], [tuple(c) for c in x["checkpoints"]])
    got = sorted({(e["index"], e["code"]) for e in r["errors"]}, key=str); want = sorted({(c[0], c[1]) for c in x["codes"]}, key=str)
    good = r["ok"] == x["ok"] and got == want and (x["authenticated"] is None or r["authenticated"] == x["authenticated"])
    bad += not good; print(("PASS " if good else "FAIL ") + name + ("" if good else "\n   got %s ok=%s auth=%s\n   want %s ok=%s auth=%s" % (got, r["ok"], r["authenticated"], want, x["ok"], x["authenticated"])))
print("python: %d/%d passed" % (len(exp) - bad, len(exp))); sys.exit(1 if bad else 0)
