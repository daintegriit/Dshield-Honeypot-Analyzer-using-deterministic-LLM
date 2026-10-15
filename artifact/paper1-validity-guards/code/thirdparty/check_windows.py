#!/usr/bin/env python3
"""check_windows.py -- the third-party windows must be Chiron's windows.
Compares windowEnd, labeled_flows and botnet_flows window by window between a
kit run and the matching Chiron run. Any mismatch stops the analysis.
Usage: python3 -I check_windows.py <kit run.json> <chiron run.json>"""
import json, sys
a, b = (json.load(open(p))["windows"] for p in sys.argv[1:3])
ka = {w["windowEnd"][:19]: (w["labeled_flows"], w["botnet_flows"]) for w in a}
kb = {w["windowEnd"][:19]: (w["labeled_flows"], w["botnet_flows"]) for w in b}
only_a, only_b = set(ka) - set(kb), set(kb) - set(ka)
diff = [k for k in set(ka) & set(kb) if ka[k] != kb[k]]
print(f"{sys.argv[1]}: kit {len(ka)} windows, chiron {len(kb)}; only kit {len(only_a)}, only chiron {len(only_b)}, count mismatches {len(diff)}")
for k in sorted(diff)[:5]:
    print("  ", k, "kit", ka[k], "chiron", kb[k])
sys.exit(1 if (only_a or only_b or diff) else 0)
