#!/usr/bin/env python3
"""guard_param.py -- run guard_audit.py unmodified, with the lookback as a parameter.

Registration §6: the only change is that the lookback used by INCOMPLETE_LOOKBACK
and FOREIGN_LOOKBACK is set per detector (default 60 reproduces every published
audit). A lookback of 0 means the detector has none: both conditions are NA and
are dropped from the verdict.
Usage: python3 -I guard_param.py <guard_audit.py> <out.tsv> <run.json> [...]
Each run's lookback is read from its config.lookback_min.
"""
import importlib.util, json, os, sys
ga, out = sys.argv[1], sys.argv[2]
spec = importlib.util.spec_from_file_location("guard_audit", ga)
G = importlib.util.module_from_spec(spec); spec.loader.exec_module(G)
WITHHOLD = ("UNREACHABLE_THRESHOLD", "EMPTY_CLASS", "TRIVIAL_NEGATIVE_CLASS", "UNDERPOWERED_CLASS",
            "INVERTED_SEPARATION", "NEAR_CHANCE_SEPARATION", "UNDERIVED_GROUND_TRUTH",
            "INCOMPLETE_LOOKBACK", "FOREIGN_LOOKBACK")
with open(out, "w") as f:
    f.write("run\tlookback_min\twindows\twithheld\tconditions\tdetail\n")
    for p in sys.argv[3:]:
        lb = float(json.load(open(p)).get("config", {}).get("lookback_min", 60))
        G.LOOKBACK_MIN = lb if lb > 0 else 60.0
        r = G.audit(p)
        fs = r.get("findings", [])
        if lb == 0:
            fs = [x for x in fs if x["guard"] not in ("INCOMPLETE_LOOKBACK", "FOREIGN_LOOKBACK")]
        wh = any(x["guard"] in WITHHOLD for x in fs)
        f.write("\t".join([p, f"{lb:g}", str(r.get("windows")), str(wh),
                           ";".join(sorted({x["guard"] for x in fs})) or "none",
                           " | ".join(x["detail"] for x in fs)]) + "\n")
print(open(out).read())
