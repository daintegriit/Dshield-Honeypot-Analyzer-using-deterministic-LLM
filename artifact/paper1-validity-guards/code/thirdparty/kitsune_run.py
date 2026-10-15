#!/usr/bin/env python3
"""kitsune_run.py -- D2, Kitsune on CTU-Mixed-Capture-1, true time (registration §3, §5).

Packet labels: before the infection boundary, benign; after it, malicious if the
packet is to or from a confirmed C2 destination, or from the infected host;
otherwise benign. FMgrace 5,000, ADgrace 50,000, threshold = 1-1e-3 quantile of a
log-normal fitted to the RMSE of the next 10,000 packets; all three are scaled by
one factor if the pre-boundary prefix is shorter than 65,000 packets. Training
and threshold packets are excluded from evaluation windows.

Usage: python3 -I kitsune_run.py <Kitsune-py dir> <capture.pcap> <boundary ISO>
          <infected IP> <c2 list file> <outdir>
"""
import csv, json, math, os, subprocess, sys
from datetime import datetime, timezone
kdir, pcap, boundary, infected, c2f, out = sys.argv[1:7]
sys.path.insert(0, kdir)
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from common import windows, write_run, to_risk, iso
os.makedirs(out, exist_ok=True)
B = datetime.fromisoformat(boundary.replace("Z", "+00:00")).timestamp()
C2 = {l.strip() for l in open(c2f) if l.strip() and not l.startswith("#")}
tsvp = os.path.join(out, os.path.basename(pcap) + ".tsv")
if not os.path.exists(tsvp):
    fields = ("frame.time_epoch frame.len eth.src eth.dst ip.src ip.dst tcp.srcport tcp.dstport udp.srcport "
              "udp.dstport icmp.type icmp.code arp.opcode arp.src.hw_mac arp.src.proto_ipv4 arp.dst.hw_mac "
              "arp.dst.proto_ipv4 ipv6.src ipv6.dst").split()
    cmd = ["tshark", "-r", pcap, "-T", "fields"] + sum([["-e", f] for f in fields], []) + ["-E", "header=y", "-E", "occurrence=f"]
    with open(tsvp, "w") as fh:
        subprocess.run(cmd, stdout=fh, check=True)
rows = []
with open(tsvp) as fh:
    rd = csv.reader(fh, delimiter="\t"); next(rd)
    for r in rd:
        t = float(r[0]); s, d = r[4] or r[17], r[5] or r[18]
        mal = t >= B and (s in C2 or d in C2 or s == infected)
        rows.append((t, mal))
n_pre = sum(1 for t, _ in rows if t < B)
FM, AD, TH = 5000, 50000, 10000
f = 1.0 if n_pre >= FM + AD + TH else n_pre / (FM + AD + TH)
FM, AD, TH = int(FM * f), int(AD * f), int(TH * f)
from Kitsune import Kitsune
K = Kitsune(tsvp, math.inf, 10, FM, AD)
rmse = []
while True:
    v = K.proc_next_packet()
    if v == -1:
        break
    rmse.append(v)
if len(rmse) != len(rows):
    sys.exit(f"STOP: Kitsune returned {len(rmse)} scores for {len(rows)} tsv rows; packet alignment is not exact")
tr = FM + AD
sample = [math.log(x) for x in rmse[tr:tr + TH] if x > 0]
mu = sum(sample) / len(sample); sd = math.sqrt(sum((x - mu) ** 2 for x in sample) / (len(sample) - 1))
thr = math.exp(mu + 3.090232306 * sd)  # z for 1 - 1e-3
ev = list(range(tr + TH, len(rows)))
times = [datetime.fromtimestamp(rows[i][0], timezone.utc) for i in ev]
bot = [rows[i][1] for i in ev]
sc_p = [rmse[i] for i in ev]
json.dump(dict(n_packets=len(rows), n_pre_boundary=n_pre, scale=f, FMgrace=FM, ADgrace=AD, threshold_sample=TH,
               lognormal_mu=mu, lognormal_sd=sd, threshold=thr, eval_packets=len(ev),
               eval_malicious=sum(bot)), open(os.path.join(out, "kitsune_params.json"), "w"), indent=1)
smax = max(sc_p) if sc_p else thr
for wmin in (1, 5):
    # The stream starts at the capture's first packet: that is the detector's t0.
    t0 = datetime.fromtimestamp(rows[0][0], timezone.utc)
    wins, _, t1 = windows(times, bot, wmin, start=t0)
    sc = [max(sc_p[w["lo"]:w["hi"]]) for w in wins]
    pr = [v >= thr for v in sc]
    meta = dict(detector="D2_kitsune", pcap=os.path.basename(pcap), mode="TRUE",
                config=dict(window_minutes=wmin, step_minutes=1, time_field="frame.time_epoch", lookback_min=10),
                ingest_span=dict(**{"from": iso(t0), "to": iso(t1)}, minutes=(t1 - t0).total_seconds() / 60))
    write_run(os.path.join(out, "runs", f"w{wmin}.json"), meta, wins, sc, pr, [to_risk(v, thr, smax) for v in sc])
print(open(os.path.join(out, "kitsune_params.json")).read())
