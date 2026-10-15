#!/usr/bin/env python3
"""slips_parse.py -- read a Slips output folder into evidence and alert records.

Slips writes alerts.json as one JSON object per line (IDEA0 format). Field
names have changed across releases, so every field is looked up under several
names, and --inspect prints what a folder actually contains so the mapping can
be checked on the pilot before any registered input is read.

  python3 -I slips_parse.py --inspect <slips out dir>
  python3 -I slips_parse.py <slips out dir> <threat map json> > evidence.tsv
Output columns: kind (evidence|alert), ts_epoch, ip, twid, threat, confidence, id
"""
import json, os, sys
from datetime import datetime, timezone

def tsv(v):
    if v is None:
        return None
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    for f in ("%Y/%m/%d %H:%M:%S.%f", "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(s, f).replace(tzinfo=timezone.utc).timestamp()
        except ValueError:
            pass
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()
    except ValueError:
        try:
            return float(s)
        except ValueError:
            return None

def note(o):
    n = o.get("Note")
    if isinstance(n, str):
        try:
            return json.loads(n)
        except ValueError:
            return {}
    return n if isinstance(n, dict) else {}

def first(*vals):
    for v in vals:
        if v not in (None, "", [], {}):
            return v
    return None

def ip_of(o, n):
    src = o.get("Source")
    if isinstance(src, list) and src and isinstance(src[0], dict):
        for k in ("IP4", "IP6"):
            v = src[0].get(k)
            if v:
                return v[0] if isinstance(v, list) else v
    return first(n.get("profile_ip"), n.get("profileid"), o.get("profileid"), o.get("profile"), n.get("srcip"))

def kind_of(o, n):
    cat = " ".join(str(c) for c in (o.get("Category") or [])) if isinstance(o.get("Category"), list) else str(o.get("Category", ""))
    blob = (cat + " " + str(n.get("type", "")) + " " + str(o.get("type", ""))).lower()
    return "alert" if "alert" in blob else "evidence"

def records(d):
    p = os.path.join(d, "alerts.json")
    for line in open(p, errors="replace"):
        line = line.strip()
        if line.startswith("{"):
            try:
                yield json.loads(line)
            except ValueError:
                pass

def main():
    if sys.argv[1] == "--inspect":
        d = sys.argv[2]; seen = {}
        for o in records(d):
            k = kind_of(o, note(o)); seen.setdefault(k, []).append(o)
        for k, v in seen.items():
            print(f"== {k}: {len(v)} records; first two:")
            for o in v[:2]:
                print(json.dumps(o, indent=1)[:2500])
        print("== parsed view of the first five records:")
        for o in list(records(d))[:5]:
            n = note(o)
            print(kind_of(o, n), first(o.get("StartTime"), o.get("EventTime"), n.get("timestamp"), o.get("DetectTime")),
                  ip_of(o, n), first(n.get("timewindow"), n.get("twid"), o.get("twid")),
                  first(n.get("threat_level"), o.get("threat_level")), first(o.get("Confidence"), n.get("confidence")))
        return
    d, tmap = sys.argv[1], json.load(open(sys.argv[2]))
    print("kind\tts_epoch\tip\ttwid\tthreat\tconfidence\tid")
    for o in records(d):
        n = note(o)
        t = tsv(first(o.get("StartTime"), o.get("EventTime"), n.get("timestamp"), o.get("DetectTime")))
        tl = first(n.get("threat_level"), o.get("threat_level"))
        if isinstance(tl, str):
            tl = tmap.get(tl.strip().lower())
        conf = first(o.get("Confidence"), n.get("confidence"))
        print("\t".join(str(x) for x in (kind_of(o, n), t, ip_of(o, n),
              first(n.get("timewindow"), n.get("twid"), o.get("twid")), tl, conf, o.get("ID"))))

if __name__ == "__main__":
    main()
