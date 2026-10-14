#!/usr/bin/env python3
"""
reachability.py — measured component reachability for a scored evaluation run.

WHY THIS EXISTS
---------------
A multi-component detector evaluated on a borrowed corpus may be structurally
unable to exercise most of its scoring. On CTU-13 scenario 9 (100 windows,
1-minute):

    entropy         100/100 windows non-zero, observed max 13.53 of 20
    amplifier       100/100                              25.00 of 25
    c2Bonus          93/100                              16.25 of 20
    concentration      4/100                               4.28 of 15
    severity           0/100                               0    of 25
    behaviour          0/100                               0    of 20
    impact             0/100                               0    of 12
    coupling           0/100                               0    of  5

Attainable ceiling = sum of observed maxima = 59.06, against an alerting
threshold of 60. Zero recall on that corpus was therefore determined before any
traffic was replayed, and the resulting TP/FP/TN/FN table measures the
evaluation rather than the detector.

Declared reachability (a per-deployment profile asserting which components have
inputs) is a prediction. This script measures it instead: a component that never
moved across the run was not exercised, whatever the profile claims.

REPORTING RULE
--------------
Report, per component, the fraction of scored windows in which it was non-zero
and its observed maximum. The sum of observed maxima is the attainable ceiling.
A state threshold above that ceiling makes the result uninterpretable, and the
run should say so rather than emitting a confusion matrix.

USAGE
    python3 reachability.py <eval.json> [<eval.json> ...]
    python3 reachability.py ~/research/results/normsweep_*/eval/*.json

Reads the per-window records written by analyze_ctu13.js (key: "windows") or by
run_full_experiment.js (key: "results"). Does not modify anything.
"""

import json
import os
import sys

# Nominal point budgets, from copilotCore.js RISK_BUDGET.
BUDGETS = {
    "severityComponent": 25,
    "behaviorComponent": 20,
    "entropyComponent": 20,
    "concentrationComponent": 15,
    "signalAmplifier": 25,
    "c2Bonus": 20,
    "impactBonus": 12,
    "couplingBonus": 5,
    # Retired in v4.0: volume cannot separate malicious from benign traffic
    # arriving at comparable rates. Reported as context, contributes 0.
    "volumeComponent": 0,
}

# From copilotCore.js. Reported alongside the ceiling so the comparison is
# explicit rather than left to the reader.
STATE_THRESHOLDS = [("elevated", 45), ("high", 60), ("critical", 85)]


def extract_windows(doc):
    """Per-window records, from either harness's output shape."""
    for key in ("windows", "results"):
        v = doc.get(key)
        if isinstance(v, list) and v:
            return v, key
    return [], None


def components_of(rec):
    """Component map from a window record, whatever nesting the harness used."""
    for path in (
        ("riskComponents",),
        ("core", "riskComponents"),
        ("coreSummary", "riskComponents"),
    ):
        cur = rec
        for p in path:
            cur = cur.get(p) if isinstance(cur, dict) else None
            if cur is None:
                break
        if isinstance(cur, dict) and cur:
            return cur
    return {}


def analyse(path):
    with open(path) as fh:
        doc = json.load(fh)

    windows, key = extract_windows(doc)
    if not windows:
        return {"file": path, "error": "no per-window records"}

    stats = {}
    for rec in windows:
        comps = components_of(rec)
        for name, raw in comps.items():
            try:
                val = float(raw or 0)
            except (TypeError, ValueError):
                continue
            s = stats.setdefault(name, {"n": 0, "nonzero": 0, "max": 0.0})
            s["n"] += 1
            if val > 0:
                s["nonzero"] += 1
            if val > s["max"]:
                s["max"] = val

    if not stats:
        return {"file": path, "error": "records carry no riskComponents"}

    ceiling = sum(s["max"] for s in stats.values())
    dead = sorted(n for n, s in stats.items()
                  if s["nonzero"] == 0 and BUDGETS.get(n, 0) > 0)

    return {
        "file": path,
        "recordKey": key,
        "windows": len(windows),
        "stats": stats,
        "ceiling": ceiling,
        "nominal": sum(BUDGETS.values()),
        "dead": dead,
    }


def report(r):
    print("=" * 74)
    print("  " + os.path.basename(r["file"]))
    print("=" * 74)

    if "error" in r:
        print("  " + r["error"])
        print()
        return

    print(f"  windows scored : {r['windows']}  (from '{r['recordKey']}')")
    print()
    print(f"  {'component':24s} {'non-zero':>12s} {'obs. max':>9s} {'budget':>7s}"
          f"  {'used':>6s}")
    print("  " + "-" * 66)

    for name in sorted(r["stats"], key=lambda n: -r["stats"][n]["max"]):
        s = r["stats"][name]
        budget = BUDGETS.get(name, 0)
        frac = f"{s['nonzero']}/{s['n']}"
        used = f"{100.0 * s['max'] / budget:.0f}%" if budget else "n/a"
        flag = "  <- never exercised" if (s["nonzero"] == 0 and budget > 0) else ""
        print(f"  {name:24s} {frac:>12s} {s['max']:9.2f} {budget:7d}  {used:>6s}{flag}")

    print("  " + "-" * 66)
    print(f"  {'attainable ceiling':24s} {'':>12s} {r['ceiling']:9.2f} "
          f"{r['nominal']:7d}")
    print()

    for name, thr in STATE_THRESHOLDS:
        if r["ceiling"] < thr:
            print(f"  UNREACHABLE: state '{name}' begins at {thr}; the observed "
                  f"ceiling is {r['ceiling']:.2f}.")
            print(f"               No window in this run could enter that state. A "
                  f"confusion")
            print(f"               matrix computed against it measures the "
                  f"evaluation, not the")
            print(f"               detector.")
            break
    else:
        print(f"  All state thresholds are within the observed ceiling "
              f"({r['ceiling']:.2f}).")

    if r["dead"]:
        print()
        print(f"  {len(r['dead'])} component(s) never moved across "
              f"{r['windows']} windows:")
        for n in r["dead"]:
            print(f"    - {n} (budget {BUDGETS.get(n, 0)})")
        print("  These contribute nothing on this corpus. Whether that reflects "
              "the traffic")
        print("  or a structural inability to supply their inputs should be "
              "stated explicitly.")
    print()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    results = [analyse(p) for p in sys.argv[1:]]
    for r in results:
        report(r)

    ok = [r for r in results if "error" not in r]
    if len(ok) > 1:
        print("=" * 74)
        print("  SUMMARY")
        print("=" * 74)
        print(f"  {'run':44s} {'windows':>8s} {'ceiling':>9s} {'dead':>6s}")
        print("  " + "-" * 70)
        for r in ok:
            name = os.path.basename(r["file"])[:44]
            print(f"  {name:44s} {r['windows']:8d} {r['ceiling']:9.2f} "
                  f"{len(r['dead']):6d}")
        print()


if __name__ == "__main__":
    main()

