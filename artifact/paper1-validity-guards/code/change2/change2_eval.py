#!/usr/bin/env python3
"""change2_eval.py -- judge Change 2's locked predictions (CHANGE2_PREDICTIONS.md).

  control: every control run's riskScore equals the positive-control run's in
           every window (else STOP: the patched core with the flag unset is not
           the evaluated detector, and nothing else is read)
  C2-P1:   every window ending >= 60 min after its stream starts has a riskScore
           identical to the positive-control run (max |diff| = 0)
  C2-P2:   over benign windows with traffic ending < 60 min after stream start,
           1-min deployed runs: the 95% Fisher interval of r(DoS score, T)
           includes 0 on at least 4 of 5 scenarios (a constant DoS score counts
           as not tracking T)
  C2-P3:   reported: r(risk, botnet fraction) on admissible windows, before/after
Usage: python3 -I change2_eval.py <change2 runs dir> <poscontrol runs dir>
"""
import json, math, os, sys
from datetime import datetime
rd, pd = sys.argv[1:3]
S = [1, 2, 6, 8, 9]
def pt(s): return datetime.fromisoformat(s.replace("Z", "+00:00"))
def load(p):
    d = json.load(open(p)); t0 = pt(d["ingest_span"]["from"])
    return {w["windowEnd"]: dict(w, T=(pt(w["windowEnd"]) - t0).total_seconds() / 60) for w in d["windows"]}
def pearson(x, y):
    n = len(x)
    if n < 3: return None
    mx, my = sum(x) / n, sum(y) / n
    sx = math.sqrt(sum((a - mx) ** 2 for a in x)); sy = math.sqrt(sum((b - my) ** 2 for b in y))
    if sx == 0 or sy == 0: return None
    return sum((a - mx) * (b - my) for a, b in zip(x, y)) / (sx * sy)
def fisher(r, n):
    if r is None or n <= 3: return None
    z = math.atanh(max(min(r, .999999), -.999999)); h = 1.96 / math.sqrt(n - 3)
    return math.tanh(z - h), math.tanh(z + h)
f = lambda v: "undefined" if v is None else f"{v:+.3f}"
c = lambda v: "-" if v is None else f"[{v[0]:+.2f},{v[1]:+.2f}]"
L = []
# control
bad = []
for s in S:
    for arm in ("dep", "abl"):
        a = load(os.path.join(rd, f"ctrl_s{s}_{arm}_w1.json")); b = load(os.path.join(pd, f"s{s}_evt_{arm}_w1s1.json"))
        if set(a) != set(b): bad.append(f"s{s} {arm}: window sets differ"); continue
        m = max(abs(a[k]["riskScore"] - b[k]["riskScore"]) for k in a)
        if m > 0: bad.append(f"s{s} {arm}: max |risk diff| {m}")
L.append("CONTROL " + ("PASSED: flag unset reproduces the positive control in every window" if not bad else "FAILED: " + "; ".join(bad)))
if bad:
    print("\n".join(L)); sys.exit("STOP: control failed, predictions not judged")
# C2-P1
p1 = []
for s in S:
    for arm in ("dep", "abl"):
        for w in (1, 5):
            a = load(os.path.join(rd, f"c2_s{s}_{arm}_w{w}.json")); b = load(os.path.join(pd, f"s{s}_evt_{arm}_w{w}s1.json"))
            ks = [k for k in a if k in b and a[k]["T"] >= 60]
            m = max((abs(a[k]["riskScore"] - b[k]["riskScore"]) for k in ks), default=0)
            p1.append((s, arm, w, len(ks), m))
ok1 = all(m == 0 for *_, m in p1)
L.append(f"C2-P1 {'HELD' if ok1 else 'FAILED'}: " + "; ".join(f"s{s} {arm} w{w}: {n} windows, max |diff| {m:g}" for s, arm, w, n, m in p1))
if not ok1:
    L.append("  C2-P1 failed: the change is not the change described; C2-P2 and C2-P3 are not read.")
    print("\n".join(L)); open(os.path.join(rd, "CHANGE2_RESULT.txt"), "w").write("\n".join(L) + "\n"); sys.exit(1)
# C2-P2
k2, det = 0, []
for s in S:
    for tag, path in (("before", os.path.join(pd, f"s{s}_evt_dep_w1s1.json")), ("after", os.path.join(rd, f"c2_s{s}_dep_w1.json"))):
        W = [w for w in load(path).values() if w["botnet_fraction"] < 0.5 and w["T"] < 60 and w.get("labeled_flows", 1)]
        r = pearson([w["attackTypeScores"]["dos"] for w in W], [w["T"] for w in W]); ci = fisher(r, len(W))
        if tag == "after":
            held = r is None or (ci is not None and ci[0] <= 0 <= ci[1])
            k2 += held
        det.append(f"s{s} {tag}: n={len(W)} r={f(r)} {c(ci)}")
L.append(f"C2-P2 {'HELD' if k2 >= 4 else 'FAILED'}: DoS stops tracking T on {k2} of 5 (need 4) :: " + "; ".join(det))
# C2-P3
det3 = []
for s in S:
    for w in (1, 5):
        for tag, path in (("before", os.path.join(pd, f"s{s}_evt_dep_w{w}s1.json")), ("after", os.path.join(rd, f"c2_s{s}_dep_w{w}.json"))):
            W = [x for x in load(path).values() if x["T"] >= 60]
            r = pearson([x["riskScore"] for x in W], [x["botnet_fraction"] for x in W])
            det3.append(f"s{s} w{w} {tag} {f(r)}")
L.append("C2-P3 (reported): r(risk, botnet fraction), admissible windows :: " + "; ".join(det3))
print("\n".join(L)); open(os.path.join(rd, "CHANGE2_RESULT.txt"), "w").write("\n".join(L) + "\n")
