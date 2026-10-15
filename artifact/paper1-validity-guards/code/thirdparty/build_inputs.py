#!/usr/bin/env python3
"""build_inputs.py -- join the CTU-13 .binetflow rows to the replayed documents.

Each labeled row is rebuilt into the exact raw line replay_ctu13.py sent, then
matched to a Mongo document with the same raw line (k-th row to k-th document
in arrival order), which gives every flow its arrival time and its true time.
Writes, per scenario:
  flows_sN.tsv           every matched flow: index, arrival, event, class, subclass, binetflow fields
  sN_TRUE.binetflow      labeled flows, StartTime = recorded time
  sN_ARRIVAL.binetflow   labeled flows, StartTime = Chiron arrival time
Rows the replay sent that Chiron never stored are listed and excluded, so every
detector sees exactly the flows Chiron scored; a stored document with no row stops
the run. Labels in the two .binetflow files are replaced by 'flow=Unknown' so no detector
can read ground truth. Usage:
  python3 -I build_inputs.py <replay_ctu13.py dir> <CTU-13-Dataset dir> <export dir> <outdir> 1 2 6 8 9
"""
import collections, csv, json, os, sys
from datetime import datetime, timezone

rdir, ctu, exp, out = sys.argv[1:5]
scen = sys.argv[5:]
sys.path.insert(0, rdir)
import replay_ctu13 as R  # the replay's own parser, so the raw lines match byte for byte

def pt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00"))

def argus(dt):
    return dt.astimezone(timezone.utc).strftime("%Y/%m/%d %H:%M:%S.%f")

os.makedirs(out, exist_ok=True)
for s in scen:
    sd = os.path.join(ctu, s)
    path = os.path.join(sd, [f for f in os.listdir(sd) if f.endswith(".binetflow")][0])
    docs = collections.defaultdict(collections.deque)
    nd = 0
    for line in open(os.path.join(exp, f"mongo_s{s}.jsonl")):
        d = json.loads(line); nd += 1
        docs[d["raw"]].append(d)
    rows, header = [], None
    with open(path, encoding="utf-8", errors="replace") as fh:
        rd = csv.reader(fh); header = next(rd)
        for row in rd:
            if len(row) <= R.COL_LABEL:
                continue
            cls, sub = R.classify_label(row[R.COL_LABEL].strip())
            if cls is None:
                continue
            raw = R.build_raw(row)
            if raw is None:
                continue
            rows.append((row[R.COL_START].strip(), raw, row, cls, sub))
    rows.sort(key=lambda t: t[0])  # the replay's send order
    matched, miss, missed = [], 0, []
    for st, raw, row, cls, sub in rows:
        q = docs.get(raw)
        if not q:
            miss += 1; missed.append(f"  row not ingested: {st} {cls} {row[R.COL_LABEL].strip()} {raw}"); continue
        d = q.popleft()
        matched.append((pt(d["timestamp"]), pt(d["event_time"]) if d.get("event_time") else None, row, cls, sub))
    left = sum(len(q) for q in docs.values())
    print(f"s{s}: binetflow labeled {len(rows)}  mongo {nd}  matched {len(matched)}  rows unmatched {miss}  docs unmatched {left}")
    for m in missed:
        print(m)
    if left:
        # A flow Chiron scored that no detector would see: the comparison would not be like for like.
        print(f"  WARNING s{s}: {left} replayed documents have no .binetflow row; stop")
    elif miss:
        # Rows the replay sent but Chiron never stored are excluded from every detector's input,
        # so all detectors still see exactly the flows Chiron scored.
        print(f"  NOTE s{s}: {miss} .binetflow rows were never ingested by Chiron and are excluded from every input")
    with open(os.path.join(out, f"flows_s{s}.tsv"), "w") as f:
        f.write("i\tarrival\tevent\tclass\tsubclass\t" + "\t".join(header) + "\n")
        for i, (a, e, row, cls, sub) in enumerate(matched):
            f.write(f"{i}\t{a.isoformat()}\t{e.isoformat() if e else ''}\t{cls}\t{sub}\t" + "\t".join(row) + "\n")
    for mode in ("TRUE", "ARRIVAL"):
        recs = []
        for i, (a, e, row, cls, sub) in enumerate(matched):
            r = list(row)
            r[R.COL_START] = argus(a) if mode == "ARRIVAL" else row[R.COL_START].strip()
            r[R.COL_LABEL] = "flow=Unknown"
            recs.append((r[R.COL_START], r))
        recs.sort(key=lambda t: t[0])
        with open(os.path.join(out, f"s{s}_{mode}.binetflow"), "w", newline="") as f:
            w = csv.writer(f); w.writerow(header)
            for _, r in recs:
                w.writerow(r)
