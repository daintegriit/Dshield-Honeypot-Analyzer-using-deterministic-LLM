#!/usr/bin/env python3
"""make_rf_runs.py -- D3 window scores: mean flow probability; alert at >= 0.5.
Usage: python3 -I make_rf_runs.py <inputs dir> <rf dir> <runs dir> 1 2 6 8 9"""
import csv, os, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import pt, windows, write_run, to_risk, iso
inp, rfd, runs = sys.argv[1:4]
for s in sys.argv[4:]:
    rows = list(csv.DictReader(open(os.path.join(inp, f"flows_s{s}.tsv")), delimiter="\t"))
    p = {r["i"]: float(r["p"]) for r in csv.DictReader(open(os.path.join(rfd, f"probs_s{s}.tsv")), delimiter="\t")}
    for mode, col in (("TRUE", "event"), ("ARRIVAL", "arrival")):
        recs = sorted(((pt(r[col]), r["class"] == "botnet", p[r["i"]]) for r in rows if r[col]), key=lambda t: t[0])
        times = [t for t, _, _ in recs]; bot = [b for _, b, _ in recs]; pv = [v for _, _, v in recs]
        for wmin in (1, 5):
            wins, t0, t1 = windows(times, bot, wmin)
            sc = [sum(pv[w["lo"]:w["hi"]]) / (w["hi"] - w["lo"]) for w in wins]
            pr = [v >= 0.5 for v in sc]
            meta = dict(detector="D3_random_forest", pcap=f"ctu13-s{s}", mode=mode,
                        config=dict(window_minutes=wmin, step_minutes=1, time_field=col, lookback_min=0),
                        ingest_span=dict(**{"from": iso(t0), "to": iso(t1)}, minutes=(t1 - t0).total_seconds() / 60))
            write_run(os.path.join(runs, "D3", f"s{s}", mode, f"w{wmin}.json"), meta, wins, sc, pr,
                      [to_risk(v, 0.5, 1.0) for v in sc])
    print(f"s{s}: D3 runs written")
