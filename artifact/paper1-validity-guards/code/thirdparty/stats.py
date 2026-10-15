#!/usr/bin/env python3
"""stats.py -- registered statistics and the verdict on each prediction (§7).

Usage: python3 -I stats.py <runs dir> <guards.tsv> <outdir>
Writes SUMMARY.tsv (every run) and PREDICTIONS.txt (P1-P6). Predictions are
judged on 1-minute windows (amendment C1); 5-minute rows are reported.
"""
import csv, glob, json, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import pearson, fisher
runs, gtsv, out = sys.argv[1:4]
G = {r["run"]: r for r in csv.DictReader(open(gtsv), delimiter="\t")}
def iv(r, neff):
    ci = fisher(r, neff)
    return ci
def has0(ci, r):
    return True if r is None else (ci is not None and ci[0] <= 0 <= ci[1])
S = []
for p in sorted(glob.glob(os.path.join(runs, "**", "*.json"), recursive=True)):
    d = json.load(open(p)); W = d["windows"]; w = d["config"]["window_minutes"]
    if not W:
        continue
    sc = [x["detector_score"] for x in W]; ben = [x for x in W if x["botnet_fraction"] < 0.5]
    r_gt = pearson(sc, [x["botnet_fraction"] for x in W]); ci_gt = iv(r_gt, len(W) / w)
    r_T = pearson([x["detector_score"] for x in ben], [x["T_min"] for x in ben]); ci_T = iv(r_T, len(ben) / w)
    r_tau = pearson([x["detector_score"] for x in ben], [x["T_min"] % 60 for x in ben]); ci_tau = iv(r_tau, len(ben) / w)
    pure = [x for x in ben if x["botnet_flows"] == 0]
    r_Tp = pearson([x["detector_score"] for x in pure], [x["T_min"] for x in pure]); ci_Tp = iv(r_Tp, len(pure) / w)
    # partial r(score, T | botnet fraction) over benign windows (exploratory, §8)
    r_sb = pearson([x["detector_score"] for x in ben], [x["botnet_fraction"] for x in ben])
    r_tb = pearson([x["T_min"] for x in ben], [x["botnet_fraction"] for x in ben])
    r_part = None
    if None not in (r_T, r_sb, r_tb) and abs(r_sb) < 1 and abs(r_tb) < 1:
        r_part = (r_T - r_sb * r_tb) / ((1 - r_sb ** 2) * (1 - r_tb ** 2)) ** 0.5
    g = G.get(p, {})
    S.append(dict(file=p, det=d["detector"], scen=d["pcap"], mode=d["mode"], w=w, n=len(W),
                  mal=len(W) - len(ben), ben=len(ben), r_gt=r_gt, ci_gt=ci_gt, r_T=r_T, ci_T=ci_T,
                  r_tau=r_tau, ci_tau=ci_tau, pure=len(pure), r_Tp=r_Tp, ci_Tp=ci_Tp, r_part=r_part, ben_all_T_lt60=all(x["T_min"] < 60 for x in ben) if ben else None,
                  withheld=g.get("withheld"), cond=g.get("conditions", "?")))
f = lambda v: "-" if v is None else f"{v:+.3f}"
c = lambda v: "-" if v is None else f"[{v[0]:+.2f},{v[1]:+.2f}]"
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "SUMMARY.tsv"), "w") as fh:
    fh.write("detector\tscenario\tmode\twindow\tn\tmal\tben\tr_gt\tci_gt\tr_T_benign\tci_T\tr_tau_benign\tci_tau\twithheld\tconditions\tEXPL_pure_benign_n\tEXPL_r_T_pure\tEXPL_ci_T_pure\tEXPL_partial_r_T_given_bf\n")
    for s in S:
        fh.write("\t".join(map(str, [s["det"], s["scen"], s["mode"], s["w"], s["n"], s["mal"], s["ben"], f(s["r_gt"]), c(s["ci_gt"]),
                 f(s["r_T"]), c(s["ci_T"]), f(s["r_tau"]), c(s["ci_tau"]), s["withheld"], s["cond"], s["pure"], f(s["r_Tp"]), c(s["ci_Tp"]), f(s["r_part"])])) + "\n")
one = [s for s in S if s["w"] == 1]
by = lambda det, mode=None: [s for s in one if s["det"] == det and (mode is None or s["mode"] == mode)]
L = []
# P1
app = [s for s in by("D1_slips", "ARRIVAL") if s["ben_all_T_lt60"]]
ok1 = all("INCOMPLETE_LOOKBACK" in s["cond"] for s in app)
L.append(f"P1 {'HELD' if app and ok1 else 'NOT TESTED' if not app else 'FAILED'}: {len(app)} D1 ARRIVAL scenarios with every benign window inside the first hour; INCOMPLETE_LOOKBACK fired on {sum('INCOMPLETE_LOOKBACK' in s['cond'] for s in app)}")
# P2
t = by("D1_slips", "TRUE"); k2 = sum(1 for s in t if s["ci_tau"] and s["ci_tau"][0] > 0)
L.append(f"P2 {'HELD' if k2 >= 3 else 'FAILED'}: r(score, tau) lower bound > 0 on {k2} of {len(t)} D1 TRUE scenarios (need 3) :: " +
         "; ".join(f"{s['scen']} {f(s['r_tau'])} {c(s['ci_tau'])}" for s in t))
# P3
k3, det3 = 0, []
for s in t:
    a = next((x for x in by("D1_slips", "ARRIVAL") if x["scen"] == s["scen"]), None)
    if not a or s["r_gt"] is None or a["r_gt"] is None:
        det3.append(f"{s['scen']} undefined"); continue
    sign = (s["r_gt"] > 0) != (a["r_gt"] > 0)
    disj = s["ci_gt"] and a["ci_gt"] and (s["ci_gt"][1] < a["ci_gt"][0] or a["ci_gt"][1] < s["ci_gt"][0])
    k3 += bool(sign or disj); det3.append(f"{s['scen']} TRUE {f(s['r_gt'])} ARRIVAL {f(a['r_gt'])} {'differs' if sign or disj else 'same'}")
L.append(f"P3 {'HELD' if k3 >= 3 else 'FAILED'}: r(score, truth) differs between modes on {k3} of {len(t)} (need 3) :: " + "; ".join(det3))
# P4
k = by("D2_kitsune", "TRUE")
ok4 = bool(k) and all(has0(s["ci_T"], s["r_T"]) and "LOOKBACK" not in s["cond"] for s in k)
L.append(f"P4 {'HELD' if ok4 else 'NOT RUN' if not k else 'FAILED'}: " + "; ".join(f"{s['scen']} r(score,T) {f(s['r_T'])} {c(s['ci_T'])} conditions {s['cond']}" for s in k))
# P5
r5 = by("D3_random_forest")
ok5 = bool(r5) and all(has0(s["ci_T"], s["r_T"]) for s in r5)
L.append(f"P5 {'HELD' if ok5 else 'FAILED'}: " + "; ".join(f"{s['scen']} {s['mode']} {f(s['r_T'])} {c(s['ci_T'])}" for s in r5) +
         " :: withheld by: " + "; ".join(f"{s['scen']} {s['mode']} {s['cond']}" for s in r5 if s["withheld"] == "True"))
held = lambda i: L[i].split()[1] == "HELD"
L.append(f"P6 {'HELD' if all(held(i) for i in (1, 2, 3, 4)) else 'FAILED'}: P2 {held(1)}, P3 {held(2)}, P4 {held(3)}, P5 {held(4)}")
L.append("EXPLORATORY (not a prediction): r(score, T) on benign windows with no botnet flow, and r(score, T | botnet fraction), separate replay age from drift in window content :: " +
         "; ".join(f"{s['det']} {s['scen']} {s['mode']} pure-benign {f(s['r_Tp'])} {c(s['ci_Tp'])} partial {f(s['r_part'])}" for s in one))
open(os.path.join(out, "PREDICTIONS.txt"), "w").write("\n".join(L) + "\n")
print("\n".join(L))
