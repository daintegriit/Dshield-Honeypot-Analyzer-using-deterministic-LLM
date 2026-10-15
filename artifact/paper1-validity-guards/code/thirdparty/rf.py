#!/usr/bin/env python3
"""rf.py -- D3, per-flow random forest, leave-one-scenario-out (registration §5).
Writes probs_sN.tsv (flow index, botnet probability). Per-flow scores do not
depend on either clock, so one file serves both modes.
Usage: python3 -I rf.py <inputs dir> <outdir> 1 2 6 8 9
"""
import csv, os, sys
import numpy as np
import sklearn
from sklearn.ensemble import RandomForestClassifier

inp, out = sys.argv[1], sys.argv[2]; scen = sys.argv[3:]
NUM = ["Dur", "sTos", "dTos", "TotPkts", "TotBytes", "SrcBytes"]
CAT = ["Proto", "Dir", "State"]
SEED = 20261015

def load(s):
    rows = list(csv.DictReader(open(os.path.join(inp, f"flows_s{s}.tsv")), delimiter="\t"))
    return rows

def num(v):
    try:
        return float(v)
    except (TypeError, ValueError):
        return 0.0

data = {s: load(s) for s in scen}
cats = {c: sorted({r[c].strip() for s in scen for r in data[s]}) for c in CAT}
def X(rows):
    m = np.zeros((len(rows), len(NUM) + sum(len(v) for v in cats.values())))
    for i, r in enumerate(rows):
        for j, c in enumerate(NUM):
            m[i, j] = num(r[c])
        k = len(NUM)
        for c in CAT:
            v = r[c].strip(); m[i, k + cats[c].index(v)] = 1.0; k += len(cats[c])
    return m
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, "VERSIONS_rf.txt"), "w") as f:
    f.write(f"scikit-learn {sklearn.__version__}\nnumpy {np.__version__}\nfeatures {NUM + CAT}\nseed {SEED}\n")
for s in scen:
    tr = [r for t in scen if t != s for r in data[t]]
    clf = RandomForestClassifier(n_estimators=300, class_weight="balanced", random_state=SEED, n_jobs=-1)
    clf.fit(X(tr), [1 if r["class"] == "botnet" else 0 for r in tr])
    p = clf.predict_proba(X(data[s]))[:, list(clf.classes_).index(1)]
    with open(os.path.join(out, f"probs_s{s}.tsv"), "w") as f:
        f.write("i\tp\n")
        for r, v in zip(data[s], p):
            f.write(f"{r['i']}\t{v:.6f}\n")
    print(f"s{s}: trained on {len(tr)} flows from {[t for t in scen if t != s]}, scored {len(p)}")
