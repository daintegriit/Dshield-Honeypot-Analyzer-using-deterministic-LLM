#!/usr/bin/env python3
"""
summarize.py -- metrics restricted to admissible windows, for every run given.

A window is admissible when it carries labeled traffic and ends at least
LOOKBACK_MIN after the run's first event (the INCOMPLETE_LOOKBACK rule). For each
run: window counts, then on admissible windows only Pearson r(risk, botnet
fraction) with a Fisher-z interval against n_eff = n * step / window, the
separation margin, and the operating point at risk >= 60.

Usage: python3 -I summarize.py <run.json> [...]
"""
import json
import math
import os
import sys
from datetime import datetime

LOOKBACK_MIN = 60.0
THRESHOLD = 60


def ts(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))


def pearson(x, y):
    n = len(x)
    if n < 3:
        return None
    mx, my = sum(x) / n, sum(y) / n
    sx = math.sqrt(sum((a - mx) ** 2 for a in x))
    sy = math.sqrt(sum((b - my) ** 2 for b in y))
    if sx == 0 or sy == 0:
        return None
    return sum((a - mx) * (b - my) for a, b in zip(x, y)) / (sx * sy)


def fisher(r, neff):
    if r is None or neff <= 3:
        return None
    z = math.atanh(max(min(r, 0.999999), -0.999999))
    h = 1.96 / math.sqrt(neff - 3)
    return math.tanh(z - h), math.tanh(z + h)


def fmt(v, nd=3):
    return "-" if v is None else f"{v:+.{nd}f}"


def main():
    print("run\tscorer\ttime_field\tscope\tspan_min\tn\tadm_mal\tadm_ben\tr_adm\tci_adm\tmargin_adm\tTP/FP/TN/FN_adm\tBA_adm\tF1_adm")
    for p in sys.argv[1:]:
        d = json.load(open(p))
        cfg = d.get("config") or {}
        win, step = cfg.get("window_minutes", 1), cfg.get("step_minutes", 1)
        t0 = ts(d["ingest_span"]["from"])
        W = d["windows"]
        adm = []
        for w in W:
            ev = w.get("eventsInWindow", w.get("labeled_flows"))
            if ev == 0:
                continue
            if (ts(w["windowEnd"]) - t0).total_seconds() / 60 >= LOOKBACK_MIN:
                adm.append(w)
        mal = [w for w in adm if w["botnet_fraction"] >= 0.5]
        ben = [w for w in adm if w["botnet_fraction"] < 0.5]
        r = pearson([w["riskScore"] for w in adm], [w["botnet_fraction"] for w in adm])
        ci = fisher(r, len(adm) * step / win)
        margin = (sum(w["riskScore"] for w in mal) / len(mal) - sum(w["riskScore"] for w in ben) / len(ben)) if mal and ben else None
        tp = sum(1 for w in mal if w["riskScore"] >= THRESHOLD)
        fn = len(mal) - tp
        fp = sum(1 for w in ben if w["riskScore"] >= THRESHOLD)
        tn = len(ben) - fp
        ba = ((tp / len(mal)) + (tn / len(ben))) / 2 if mal and ben else None
        f1 = (2 * tp / (2 * tp + fp + fn)) if (2 * tp + fp + fn) else None
        print("\t".join([
            os.path.basename(p), d.get("planted_scorer", "detector"),
            str(cfg.get("time_field", "timestamp")), str(cfg.get("scope_pcap")),
            f"{d['ingest_span'].get('minutes', 0):.0f}", str(len(W)), str(len(mal)), str(len(ben)),
            fmt(r), "-" if ci is None else f"[{ci[0]:+.2f},{ci[1]:+.2f}]",
            fmt(margin, 2), f"{tp}/{fp}/{tn}/{fn}", fmt(ba), fmt(f1),
        ]))


if __name__ == "__main__":
    main()
