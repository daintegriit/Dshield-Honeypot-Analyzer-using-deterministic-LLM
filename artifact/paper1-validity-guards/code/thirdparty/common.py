"""common.py -- windows, statistics and run files shared by the three detectors.

Windows reproduce analyze_ctu13.js exactly: sliding windows [end-W, end] with both
ends inclusive, end = t0 + W, t0 + W + step, ... while end <= t1 + step, where t0
and t1 are the first and last record time in the mode's clock; windows with no
labeled record are skipped. A record is botnet when its class is botnet.
"""
import bisect, json, math, os
from datetime import datetime, timedelta, timezone

def pt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

def iso(dt):
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")

def windows(times, is_bot, win_min, step_min=1, start=None):
    """times: sorted datetimes; is_bot: parallel bools. Returns list of dicts with
    index range [lo, hi) into the sorted arrays."""
    t0, t1 = (start or times[0]), times[-1]
    W, S = timedelta(minutes=win_min), timedelta(minutes=step_min)
    cbot = [0]
    for b in is_bot:
        cbot.append(cbot[-1] + (1 if b else 0))
    out, end, idx = [], t0 + W, 0
    while end <= t1 + S:
        start = end - W
        lo = bisect.bisect_left(times, start)
        hi = bisect.bisect_right(times, end)
        n = hi - lo
        if n:
            nb = cbot[hi] - cbot[lo]
            out.append(dict(idx=idx, windowStart=iso(start), windowEnd=iso(end), lo=lo, hi=hi,
                            labeled_flows=n, botnet_flows=nb, normal_flows=n - nb,
                            botnet_fraction=round(nb / n, 4), eventsInWindow=n,
                            T_min=(end - t0).total_seconds() / 60))
        end += S
        idx += 1
    return out, t0, t1

def pearson(x, y):
    n = len(x)
    if n < 3:
        return None
    mx, my = sum(x) / n, sum(y) / n
    sx = math.sqrt(sum((a - mx) ** 2 for a in x)); sy = math.sqrt(sum((b - my) ** 2 for b in y))
    if sx == 0 or sy == 0:
        return None
    return sum((a - mx) * (b - my) for a, b in zip(x, y)) / (sx * sy)

def fisher(r, neff):
    if r is None or neff <= 3:
        return None
    z = math.atanh(max(min(r, 0.999999), -0.999999)); h = 1.96 / math.sqrt(neff - 3)
    return (math.tanh(z - h), math.tanh(z + h))

def to_risk(s, thr, smax):
    """Monotone map of a detector score onto 0..100 with the detector's own
    threshold at 60, so the guards' threshold-60 logic reads the detector's
    decision. Used only for the guard file; statistics use the raw score."""
    if s is None:
        return 0.0
    if s < thr:
        return 60.0 * max(s, 0) / thr if thr > 0 else 0.0
    top = smax if smax > thr else thr * 2 + 1e-9
    return min(100.0, 60.0 + 40.0 * (s - thr) / (top - thr))

def write_run(path, meta, wins, scores, preds, risks):
    """Write a run file guard_audit.py reads, plus the raw score per window."""
    rows = []
    for w, s, p, r in zip(wins, scores, preds, risks):
        x = {k: w[k] for k in ("idx", "windowStart", "windowEnd", "labeled_flows", "botnet_flows",
                               "normal_flows", "botnet_fraction", "eventsInWindow", "T_min")}
        x.update(detector_score=s, detectorPredicted=bool(p), riskScore=round(r, 3),
                 state="high" if p else "stable")
        rows.append(x)
    mal = [r["detector_score"] for r in rows if r["botnet_fraction"] >= 0.5]
    ben = [r["detector_score"] for r in rows if r["botnet_fraction"] < 0.5]
    sep = {"malicious_n": len(mal), "benign_n": len(ben)}
    if mal and ben:
        sep["separation_margin"] = round(sum(mal) / len(mal) - sum(ben) / len(ben), 6)
    sweep, vals = [], sorted({r["detector_score"] for r in rows})
    qs = [vals[min(len(vals) - 1, int(q * (len(vals) - 1) / 20))] for q in range(21)] if vals else []
    for th in sorted(set(qs)):
        tp = sum(1 for r in rows if r["botnet_fraction"] >= 0.5 and r["detector_score"] >= th)
        fn = len(mal) - tp
        fp = sum(1 for r in rows if r["botnet_fraction"] < 0.5 and r["detector_score"] >= th)
        f1 = 2 * tp / (2 * tp + fp + fn) if (2 * tp + fp + fn) else 0.0
        sweep.append(dict(truth_threshold=0.5, risk_threshold=th, f1=f1, fpr=(fp / len(ben)) if ben else 0.0))
    doc = dict(meta, windows=rows, separation=sep, threshold_sweep=sweep,
               guards={"version": "third-party", "ran": []})
    os.makedirs(os.path.dirname(path), exist_ok=True)
    json.dump(doc, open(path, "w"), indent=0)
