#!/usr/bin/env python3
"""
inert_components.py — detect components that carry no discriminative information.

A component taking the same value in every window contributes a constant offset
and cannot affect the ranking between windows. It appears in the score
decomposition as a contributing signal and carries none.

Two conditions, reported separately:

    SATURATED   at or near its cap in nearly every window. The cap is too low
                for the traffic; variation above it is discarded.
    INVARIANT   constant at any value across windows. Same consequence for
                discrimination, different cause.
    DEAD        constant at zero. Reported separately because "never fired" and
                "fired identically every time" are different problems.

MOTIVATION

    entropyComponent, live honeypot, 60 windows sampled over 5 days:
        at its 20-point cap in 59 of 60. Its ceiling is log2(10) = 3.32 bits,
        which any window touching ten ports exceeds. A honeypot receiving
        internet background radiation exceeds it constantly.

    dosScore, earlier version, CTU-13 scenario 1:
        a 20*log10(events+1) term reaching its 60-point cap at ~1,000 events per
        window, saturated in 100% of windows at every window size, so pickTop()
        returned "dos" for every single window and the attack-type table was
        uninformative by construction.

Neither produced an error. Both looked like contributing signals.

USAGE
    python3 inert_components.py <run.json> [<run.json> ...]

Accepts any JSON carrying per-window risk components, in any of these shapes:
    {"windows":  [ {... "riskComponents": {...}} ]}      analyze_ctu13.js
    {"results":  [ {... "riskComponents": {...}} ]}      run_full_experiment.js
    [ {... "entropy": n, "amp": n, ...} ]                 honeypot sweep
"""

import json
import os
import sys

BUDGETS = {
    "severityComponent": 25,
    "behaviorComponent": 20,
    "entropyComponent": 20,
    "concentrationComponent": 15,
    "signalAmplifier": 25,
    "c2Bonus": 20,
    "impactBonus": 12,
    "couplingBonus": 5,
    "volumeComponent": 0,  # retired v4.0
}

# Short keys used by the ad-hoc honeypot sweep script.
ALIASES = {
    "entropy": "entropyComponent",
    "amp": "signalAmplifier",
    "c2": "c2Bonus",
    "sev": "severityComponent",
    "beh": "behaviorComponent",
    "vol": "volumeComponent",
    "impB": "impactBonus",
    "cplB": "couplingBonus",
}

SATURATION_VALUE_FRAC = 0.95
SATURATION_WINDOW_FRAC = 0.95
INVARIANCE_CV = 0.01


def records(doc):
    """Per-window records from whichever shape this file uses."""
    if isinstance(doc, list):
        return doc
    for key in ("windows", "results"):
        v = doc.get(key)
        if isinstance(v, list) and v:
            return v
    return []


def components(rec):
    """Component map, normalising short keys and nested placements."""
    for path in (("riskComponents",), ("core", "riskComponents"),
                 ("coreSummary", "riskComponents")):
        cur = rec
        for p in path:
            cur = cur.get(p) if isinstance(cur, dict) else None
            if cur is None:
                break
        if isinstance(cur, dict) and cur:
            return cur

    # Flat record with short keys, as written by the honeypot sweep.
    flat = {ALIASES[k]: rec[k] for k in ALIASES if k in rec}
    return flat


def analyse(path):
    with open(path) as fh:
        doc = json.load(fh)

    recs = records(doc)
    if not recs:
        return {"file": path, "error": "no per-window records"}

    series = {}
    for r in recs:
        for k, raw in components(r).items():
            try:
                series.setdefault(k, []).append(float(raw or 0))
            except (TypeError, ValueError):
                pass

    if not series:
        return {"file": path, "error": "records carry no risk components"}

    stats, flags = {}, []
    for name, vals in series.items():
        n = len(vals)
        budget = BUDGETS.get(name, 0)
        mu = sum(vals) / n
        var = sum((v - mu) ** 2 for v in vals) / n
        sd = var ** 0.5
        cv = sd / mu if mu > 0 else 0.0
        at_cap = sum(1 for v in vals if budget > 0 and v >= budget * SATURATION_VALUE_FRAC)

        stats[name] = {
            "budget": budget, "n": n, "mean": mu, "sd": sd, "cv": cv,
            "min": min(vals), "max": max(vals), "at_cap": at_cap,
        }

        if budget <= 0:
            continue
        if at_cap >= n * SATURATION_WINDOW_FRAC:
            flags.append((name, "SATURATED",
                          f"at >={int(SATURATION_VALUE_FRAC*100)}% of its {budget}-point "
                          f"budget in {at_cap} of {n} windows; variation above the cap "
                          f"is discarded"))
        elif mu == 0:
            flags.append((name, "DEAD",
                          f"zero in all {n} windows; never fired"))
        elif cv < INVARIANCE_CV:
            flags.append((name, "INVARIANT",
                          f"constant at {mu:.2f} across all {n} windows "
                          f"(cv={cv:.4f}); fixed offset, no discrimination"))

    return {"file": path, "n": len(recs), "stats": stats, "flags": flags}


def report(r):
    print("=" * 78)
    print("  " + os.path.basename(r["file"]))
    print("=" * 78)

    if "error" in r:
        print("  " + r["error"] + "\n")
        return

    print(f"  windows: {r['n']}\n")
    print(f"  {'component':24s} {'mean':>8s} {'sd':>8s} {'cv':>8s} "
          f"{'range':>16s} {'at cap':>9s}")
    print("  " + "-" * 76)

    for name in sorted(r["stats"], key=lambda k: -r["stats"][k]["mean"]):
        s = r["stats"][name]
        rng = f"{s['min']:.2f}..{s['max']:.2f}"
        cap = f"{s['at_cap']}/{s['n']}" if s["budget"] else "n/a"
        print(f"  {name:24s} {s['mean']:8.2f} {s['sd']:8.3f} {s['cv']:8.4f} "
              f"{rng:>16s} {cap:>9s}")

    print()
    if not r["flags"]:
        print("  No inert components detected.\n")
        return

    print("  " + "~" * 76)
    print("  VALIDITY WARNING — components carrying no discriminative information")
    print("  " + "~" * 76)
    for name, cond, detail in r["flags"]:
        print(f"     [{cond}] {name}")
        print(f"     {detail}")
    print()
    print("  These contribute to the score without separating windows. Claims that")
    print("  the score fuses these signals are not supported for this corpus.")
    print()


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)
    for p in sys.argv[1:]:
        report(analyse(p))


if __name__ == "__main__":
    main()
