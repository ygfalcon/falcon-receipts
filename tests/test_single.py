import sys, json, os
H = os.path.dirname(os.path.abspath(__file__)); sys.path.insert(0, os.path.join(H, "..", "python"))
import receipt_verify as R
D = os.path.join(H, "..", "fixtures", "single"); PIN = ["GgHie9LuzXPAU64iLsfA6jxbZoXv9RaSZk6rsMz44XpY"]  # test key, not production
n = ok = 0
def chk(c, msg):
    global n, ok; n += 1; ok += bool(c); print(("PASS " if c else "FAIL ") + msg)
for name in ("drainer_approve_plus_sweep", "jupiter_swap"):
    r = json.load(open(os.path.join(D, name + ".json")))["receipt"]; tx = open(os.path.join(D, name + ".tx")).read()
    chk(R.verify_receipt(r, PIN, tx)["ok"], name + " valid")
    chk("SIGNER_NOT_PINNED" in R.verify_receipt(r)["problems"], name + " rejected under production pin")
    t = json.loads(json.dumps(r)); t["event"]["verdict"] = "NO_MATCH" if t["event"]["verdict"] != "NO_MATCH" else "BLOCK"
    chk("HASH_MISMATCH" in R.verify_receipt(t, PIN)["problems"], name + " verdict tamper")
    t = dict(r); t["sig"] = r["sig"][:-2] + ("11" if not r["sig"].endswith("11") else "22")
    chk(not R.verify_receipt(t, PIN)["ok"], name + " sig tamper")
    other = "jupiter_swap" if name != "jupiter_swap" else "drainer_approve_plus_sweep"
    chk("TX_MISMATCH" in R.verify_receipt(r, PIN, open(os.path.join(D, other + ".tx")).read())["problems"], name + " wrong tx")
    t = {k: v for k, v in r.items() if k != "event"}
    chk("MISSING_FIELDS" in R.verify_receipt(t, PIN)["problems"], name + " legacy receipt without event")
print("single: %d/%d passed" % (ok, n)); sys.exit(0 if ok == n else 1)
