#!/usr/bin/env python3
"""
planted.py -- positive and negative controls for the guard set.

Takes a CTU-13 run produced by analyze_ctu13.js (real windows, real labels,
real timing) and replaces the detector's score with a scorer of KNOWN quality,
so the guard audit can be checked against an answer known in advance:

  oracle     risk = 100 * botnet_fraction + N(0, 10)      should PASS every guard
  null       risk = Uniform(0, 100)                         should be WITHHELD
  replay_age risk = 150 * (5/T - 1/12), T = minutes since   should be WITHHELD
             the replay's first event (the Section V-B
             artifact, with no access to the traffic)

Usage: python3 -I planted.py <run.json> <outdir>
Writes <outdir>/<stem>__<scorer>.json in the format guard_audit.py reads.
"""
import json
import math
import os
import random
import sys
from datetime import datetime

SEED = 20261014
THRESHOLD = 60  # deployed operating point: state high at risk >= 60


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def state_of(r):
    return "critical" if r >= 85 else "high" if r >= 60 else "elevated" if r >= 45 else "stable"


def score(name, w, t_min, rng):
    if name == "oracle":
        return max(0.0, min(100.0, 100 * w["botnet_fraction"] + rng.gauss(0, 10)))
    if name == "null":
        return rng.uniform(0, 100)
    if name == "replay_age":
        return max(0.0, min(100.0, 150 * (5 / max(t_min, 1e-9) - 1 / 12)))
    raise ValueError(name)


def main():
    src, outdir = sys.argv[1], sys.argv[2]
    os.makedirs(outdir, exist_ok=True)
    doc = json.load(open(src))
    t0 = ts(doc["ingest_span"]["from"])
    stem = os.path.splitext(os.path.basename(src))[0]
    for name in ("oracle", "null", "replay_age"):
        rng = random.Random(f"{SEED}-{name}-{stem}")
        wins = []
        for w in doc["windows"]:
            t_min = (ts(w["windowEnd"]) - t0).total_seconds() / 60
            r = round(score(name, w, t_min, rng), 2)
            nw = {k: w[k] for k in ("idx", "windowStart", "windowEnd", "labeled_flows",
                                     "botnet_flows", "normal_flows", "botnet_fraction",
                                     "eventsInWindow") if k in w}
            nw.update(riskScore=r, state=state_of(r))
            wins.append(nw)
        mal = [w["riskScore"] for w in wins if w["botnet_fraction"] >= 0.5]
        ben = [w["riskScore"] for w in wins if w["botnet_fraction"] < 0.5]
        sep = {"malicious_n": len(mal), "benign_n": len(ben)}
        if mal and ben:
            sep["separation_margin"] = round(sum(mal) / len(mal) - sum(ben) / len(ben), 2)
        out = {
            "planted_scorer": name,
            "seed": SEED,
            "source_run": os.path.basename(src),
            "pcap": doc.get("pcap"),
            "config": doc.get("config"),
            "ingest_span": doc["ingest_span"],
            "separation": sep,
            "windows": wins,
        }
        json.dump(out, open(os.path.join(outdir, f"{stem}__{name}.json"), "w"), indent=1)


if __name__ == "__main__":
    main()
