#!/usr/bin/env python3
"""envelope.py -- operating envelope of a corpus, computed from flows alone.

For each CTU-13 scenario and window width, recomputes from the flow records
(no detector output) every component of copilotCore-v4.3 that is a function of
the flows: the DoS, scan, brute-force, web-probe and C2 class scores, and the
entropy, concentration, behavior, signal-amplifier and C2-bonus risk
components. Formulas and constants are transcribed from copilotCore.js
(frozen backend, sha 91f4ad86...) and cited by line in comments. Severity and
impact depend on the severity the ingest path assigns, which the flow records
do not carry; they are reported as outside this envelope.

Two outputs:
  1. AGREEMENT: each recomputed value against the value the detector recorded
     in the positive-control run for the same window (true time, scoped).
     This checks the transcription; any disagreement is reported, not tuned.
  2. ENVELOPE: per component, the largest value it reaches on the corpus and
     the share of windows where it is non-zero; per C2 condition, the share of
     windows where it can be met; per class, windows admissible after a
     60-minute lookback. All from flows, labels and configuration.

Usage:
  python3 -I envelope.py <inputs dir> <poscontrol runs dir> <replay_ctu13.py dir> <outdir> 1 2 6 8 9
LOCAL_NETWORKS is read from the environment (same value the backend uses).
C2 gates use the deployed defaults unless C2_MIN_EVENTS, C2_MIN_FLOW_COUNT,
C2_MIN_SPAN_SEC are set (as the backend reads them).
"""
import bisect, csv, ipaddress, json, math, os, sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

inp, pcr, rdir, out = sys.argv[1:5]
scen = sys.argv[5:]
sys.path.insert(0, rdir)
import replay_ctu13 as R  # same port parser the replay used to build DPT=

# ---- constants (copilotCore.js L85-103, L706-708, L1054-1083, L1170-1240)
MIN_EVENTS = float(os.environ.get("C2_MIN_EVENTS", 30))
MIN_FLOW = float(os.environ.get("C2_MIN_FLOW_COUNT", 12))
MIN_SPAN = float(os.environ.get("C2_MIN_SPAN_SEC", 90))
BONUS_MIN = float(os.environ.get("C2_BONUS_MIN_SCORE", 40))
DOM_RATIO, LOW_BURST, MAX_PORTS, CV_MAX = 0.40, 0.40, 4, 0.65
RECENT_LIMIT = 20000
AUTH = {22, 23, 2222, 2223, 3389, 5900}
WEB = {80, 443, 8000, 8080, 8443, 8888, 9000, 9443}
NETS = [ipaddress.ip_network(n.strip(), strict=False)
        for n in os.environ.get("LOCAL_NETWORKS", "").split(",") if n.strip()]

def clamp(x, a, b):
    return max(a, min(b, x))

def is_local(ip):  # copilotCore.js L235-258
    if not ip:
        return False
    if ip.startswith(("10.", "192.168.", "127.")) or ip == "0.0.0.0":
        return True
    p = ip.split(".")
    if len(p) == 4 and p[0] == "172" and p[1].isdigit() and 16 <= int(p[1]) <= 31:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(a in n for n in NETS)

def H(counter):  # entropyFromCountsMap, L263
    t = sum(counter.values())
    return -sum((c / t) * math.log2(c / t) for c in counter.values() if c > 0) if t else 0.0

def cv(xs):  # coeffOfVariation, L378 (sample std / mean, >= 3 values)
    if len(xs) < 3:
        return None
    m = sum(xs) / len(xs)
    if m <= 0:
        return None
    s = math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))
    return s / m

def score(ev, c5, c60):
    """ev: list of (t_ms, src, dst, dpt) in the window, time-ascending, truncated
    to RECENT_LIMIT as the core's query is. c5, c60: counts in the trailing
    5 minutes and hour. Returns attack-type scores and risk components."""
    burst = c5 / c60 if c60 > 0 else 0.0
    dos = clamp(min(100, max(0, burst - 0.083) * 150), 0, 100)
    ports = Counter(d for _, _, _, d in ev if d)
    top10 = ports.most_common(10)
    tot_ports = sum(ports.values())
    Hp = H(ports)
    scan_c = sum(1 for _, c in top10 if c > 20)
    scan = 0 if c5 == 0 else clamp(min(60, scan_c * 15) + min(25, Hp * 8), 0, 100)
    auth = sum(c for p, c in top10 if p in AUTH)
    web = sum(c for p, c in top10 if p in WEB)
    brute = clamp(min(70, auth / 50), 0, 100)
    webp = clamp(min(70, web / 80), 0, 100)
    srcs, peers = Counter(), Counter()
    flows = defaultdict(lambda: [0, [], set()])
    wports = set()
    for t, s, d, p in ev:
        if s:
            srcs[s] += 1
        if not s or not d:
            continue
        sl, dl = is_local(s), is_local(d)
        if sl and not dl:
            peers[d] += 1
        elif not sl and dl:
            peers[s] += 1
        if sl != dl:
            if p:
                wports.add(p)
            f = flows[f"{s}->{d}"]
            f[0] += 1
            f[1].append(t)
            if p:
                f[2].add(p)
    top = None
    for k, f in flows.items():  # first maximum in insertion order, as the JS loop
        if top is None or f[0] > top[0]:
            top = f
    ftot = sum(f[0] for f in flows.values())
    dom = top[0] / ftot if top and ftot else 0.0
    pcv, span = None, 0.0
    if top and len(top[1]) >= 4:
        ts = sorted(top[1])
        span = (ts[-1] - ts[0]) / 1000
        deltas = [(b - a) / 1000 for a, b in zip(ts, ts[1:]) if b - a > 0]
        pcv = cv(deltas)
    cond = dict(events=len(ev) >= MIN_EVENTS, flow=bool(top) and top[0] >= MIN_FLOW,
                dominant=dom >= DOM_RATIO, low_burst=burst <= LOW_BURST,
                low_ports=0 < len(wports) <= MAX_PORTS,
                periodic=pcv is not None and pcv <= CV_MAX and span >= MIN_SPAN,
                span_reachable=span >= MIN_SPAN)
    c2 = 0
    if cond["events"] and top:
        c2 = clamp(25 * cond["flow"] + 25 * cond["dominant"] + 25 * cond["periodic"]
                   + 15 * cond["low_burst"] + 10 * cond["low_ports"], 0, 100)
    ent = clamp(clamp(Hp / math.log2(10), 0, 1) * 20, 0, 20)
    Hs = H(peers if peers else srcs)
    conc = clamp((1 - clamp(Hs / math.log2(50), 0, 1)) * 15, 0, 15) if (peers or srcs) else 0.0
    beh = clamp((auth / tot_ports if tot_ports else 0) * 20, 0, 20)
    strongest = max(c2, dos, scan, webp, brute)  # impact excluded: needs severity
    amp = 0.0
    if strongest >= 45:
        amp = clamp((strongest - 45) / 55 * 15, 0, 15)
    if strongest >= 60 and c5 >= 20:
        amp += clamp((strongest - 60) / 40 * 10, 0, 10)
    bonus = clamp(c2 / 4, 0, 20) if c2 >= BONUS_MIN else 0.0
    return (dict(dos=dos, scan=scan, brute_force=brute, web_probe=webp, c2=c2),
            dict(entropyComponent=ent, concentrationComponent=conc, behaviorComponent=beh,
                 signalAmplifier=amp, c2Bonus=bonus), cond)

def pt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

os.makedirs(out, exist_ok=True)
agree_rows, env_rows = [], []
for s in scen:
    rows = list(csv.DictReader(open(os.path.join(inp, f"flows_s{s}.tsv")), delimiter="\t"))
    recs = sorted(((pt(r["event"]), r["SrcAddr"].strip(), r["DstAddr"].strip(),
                    R.safe_port(r["Dport"]), r["class"] == "botnet") for r in rows if r["event"]),
                  key=lambda x: x[0])
    tms = [int(round(t.timestamp() * 1000)) for t, *_ in recs]  # Mongo stores milliseconds
    t0 = tms[0]
    for w in (1, 5):
        run = json.load(open(os.path.join(pcr, f"s{s}_evt_dep_w{w}s1.json")))
        n_by = Counter(); adm_by = Counter(); mx = Counter(); nz = Counter(); cond_ok = Counter()
        diffs = defaultdict(list)
        for rw in run["windows"]:
            end = int(round(pt(rw["windowEnd"]).timestamp() * 1000))
            lo = bisect.bisect_left(tms, end - w * 60000); hi = bisect.bisect_right(tms, end)
            ev = [(tms[i], recs[i][1], recs[i][2], recs[i][3]) for i in range(lo, min(hi, lo + RECENT_LIMIT))]
            c5 = hi - bisect.bisect_left(tms, end - 5 * 60000)
            c60 = hi - bisect.bisect_left(tms, end - 60 * 60000)
            ats, comp, cond = score(ev, c5, c60)
            for k, v in ats.items():
                diffs["ats." + k].append(abs(v - float(rw["attackTypeScores"].get(k, 0) or 0)))
            for k, v in comp.items():
                diffs["comp." + k].append(abs(v - float(rw["riskComponents"].get(k, 0) or 0)))
            cls = "mal" if rw["botnet_fraction"] >= 0.5 else "ben"
            n_by[cls] += 1
            if (end - t0) / 60000 >= 60:
                adm_by[cls] += 1
            for k, v in list(ats.items()) + list(comp.items()):
                mx[k] = max(mx[k], v); nz[k] += v > 1e-9
            for k, v in cond.items():
                cond_ok[k] += bool(v)
        n = len(run["windows"])
        for k, d in sorted(diffs.items()):
            agree_rows.append([f"s{s}", w, k, n, sum(x < 0.01 for x in d), f"{max(d):.4f}"])
        for k in mx:
            env_rows.append([f"s{s}", w, "component", k, f"{mx[k]:.2f}", f"{nz[k]}/{n}"])
        for k, v in cond_ok.items():
            env_rows.append([f"s{s}", w, "c2_condition", k, "", f"{v}/{n}"])
        for c in ("mal", "ben"):
            env_rows.append([f"s{s}", w, "admissible_windows", c, "", f"{adm_by[c]}/{n_by[c]}"])
        print(f"s{s} w{w}: {n} windows checked")
with open(os.path.join(out, "AGREEMENT.tsv"), "w") as f:
    f.write("scenario\twindow\tquantity\twindows\twithin_0.01\tmax_abs_diff\n")
    for r in agree_rows:
        f.write("\t".join(map(str, r)) + "\n")
with open(os.path.join(out, "ENVELOPE.tsv"), "w") as f:
    f.write("scenario\twindow\tkind\tname\tmax\tnonzero_or_met\n")
    for r in env_rows:
        f.write("\t".join(map(str, r)) + "\n")
bad = [r for r in agree_rows if r[4] != r[3]]
print(f"agreement: {len(agree_rows) - len(bad)} of {len(agree_rows)} quantity-runs exact to 0.01")
for r in bad:
    print("  DISAGREES", *r)
