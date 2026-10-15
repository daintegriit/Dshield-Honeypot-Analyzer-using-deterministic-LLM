#!/usr/bin/env python3
"""make_slips_runs.py -- D1 window scores (registration §5).
score = sum of threat x confidence over evidence timed inside the window;
alert = some evidence in the window belongs to a (profile, time window) Slips
alerted on. Evidence times are read on the clock the detector was fed, so they
are compared with the same mode's windows.
Usage: python3 -I make_slips_runs.py <inputs dir> <slips out dir> <runs dir> 1 2 6 8 9"""
import csv, os, sys
from datetime import datetime, timezone
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import pt, windows, write_run, to_risk, iso
inp, sd, runs = sys.argv[1:4]
for s in sys.argv[4:]:
    rows = list(csv.DictReader(open(os.path.join(inp, f"flows_s{s}.tsv")), delimiter="\t"))
    for mode, col in (("TRUE", "event"), ("ARRIVAL", "arrival")):
        ev = list(csv.DictReader(open(os.path.join(sd, f"evidence_s{s}_{mode}.tsv")), delimiter="\t"))
        recs = sorted(((pt(r[col]), r["class"] == "botnet") for r in rows if r[col]), key=lambda t: t[0])
        times = [t for t, _ in recs]; bot = [b for _, b in recs]
        alerted = {(e["ip"], e["twid"]) for e in ev if e["kind"] == "alert"}
        E = []
        for e in ev:
            if e["kind"] != "evidence" or e["ts_epoch"] in ("None", ""):
                continue
            try:
                v = float(e["threat"]) * float(e["confidence"])
            except ValueError:
                continue
            E.append((float(e["ts_epoch"]), v, (e["ip"], e["twid"]) in alerted))
        lo_t, hi_t = times[0].timestamp(), times[-1].timestamp()
        inside = sum(1 for t, _, _ in E if lo_t - 1 <= t <= hi_t + 3600)
        print(f"s{s} {mode}: {len(E)} evidence, {inside} timed within the fed stream, {len(alerted)} alerted profile-windows")
        for wmin in (1, 5):
            wins, t0, t1 = windows(times, bot, wmin)
            sc, pr = [], []
            for w in wins:
                a, b = pt(w["windowStart"]).timestamp(), pt(w["windowEnd"]).timestamp()
                vals = [(v, al) for t, v, al in E if a <= t <= b]
                sc.append(sum(v for v, _ in vals)); pr.append(any(al for _, al in vals))
            smax = max(sc) if sc else 0
            thr = min([v for v, p in zip(sc, pr) if p], default=smax + 1)
            meta = dict(detector="D1_slips", pcap=f"ctu13-s{s}", mode=mode,
                        config=dict(window_minutes=wmin, step_minutes=1, time_field=col, lookback_min=60),
                        ingest_span=dict(**{"from": iso(t0), "to": iso(t1)}, minutes=(t1 - t0).total_seconds() / 60))
            # riskScore: alerted windows are placed at or above 60, others below,
            # each ordered by score; the guards then read Slips' own decision.
            risks = [(60 + 40 * (v / smax if smax else 0)) if p else (59.9 * (v / smax if smax else 0)) for v, p in zip(sc, pr)]
            write_run(os.path.join(runs, "D1", f"s{s}", mode, f"w{wmin}.json"), meta, wins, sc, pr, risks)
