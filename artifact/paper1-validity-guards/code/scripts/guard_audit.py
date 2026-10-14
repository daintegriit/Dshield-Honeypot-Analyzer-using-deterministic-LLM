#!/usr/bin/env python3
"""
guard_audit.py — apply current guards to previously archived results.

WHY THIS EXISTS
---------------
Guards were added to the evaluation harness on 2026-08-08. Every result
archived before that date was produced without them, and nothing in those files
says so. Whether a given archived number would survive today's validity checks
is currently a matter of remembering which guard postdates which run.

This makes it a query. It applies the current guard set to any archived run that
carries per-window records, and reports which results would be withheld today.

The point is not to invalidate old work. It is that "this number predates the
check that would have caught it" should be recoverable from the artifact rather
than from memory.

GUARDS APPLIED
    UNREACHABLE_THRESHOLD  no window could reach the alerting threshold, so TP
                           and FP are structurally zero
    EMPTY_CLASS            one class has no windows, so recall or specificity is
                           undefined
    SATURATED_COMPONENT    a component is at its cap in nearly every window and
                           carries no discriminative information
    DEGENERATE_SWEEP       the best F1 in a threshold sweep comes with FPR close
                           to 1, i.e. the constant-attack detector signature
    TRIVIAL_NEGATIVE_CLASS every negative window has zero events, so the
                           comparison is traffic-present vs traffic-absent
    UNDERPOWERED_CLASS     a class has too few windows to support a rate
    INVERTED_SEPARATION    the score ranks benign windows above malicious ones,
                           so the detector is anti-correlated with ground truth
    INCOMPLETE_LOOKBACK    too few windows in a class have a full lookback, so
                           the classes differ in replay age, not content
    FOREIGN_LOOKBACK       another run's traffic sits in this run's lookback

USAGE
    python3 guard_audit.py <run.json> [<run.json> ...]
    python3 guard_audit.py ~/research/results/*/eval/*.json
    python3 guard_audit.py --csv ~/research/outputs/full_experiment/*.json
"""

import json
import math
import os
import sys

GUARD_SET_VERSION = "2026-10-14a"

BUDGETS = {
    "severityComponent": 25, "behaviorComponent": 20, "entropyComponent": 20,
    "concentrationComponent": 15, "signalAmplifier": 25, "c2Bonus": 20,
    "impactBonus": 12, "couplingBonus": 5, "volumeComponent": 0,
}

DEPLOYED_STATE_THRESHOLD = 60
SATURATION_VALUE_FRAC = 0.95
SATURATION_WINDOW_FRAC = 0.95
DEGENERATE_FPR = 0.95
MIN_CLASS_N = 5
NEAR_CHANCE_Z = 1.96
# truthMode values that define the boundary from the harness rather than
# from the capture. Absent is not a violation: CTU-13 runs label per flow.
UNDERIVED_TRUTH_MODES = ("replay_start",)
# Longest lookback of any component with a non-zero budget: the burst ratio
# divides the last 5 min by the trailing HOUR. A window whose end lies less
# than this far after the first replayed event scores a lookback that the
# replay never filled: under uniform traffic dos = 150*(5/T - 1/12) whatever
# the traffic is (T = minutes since data start). Measured fit: MAE <= 0.2 pts
# on CTU-13 s1, s2, s8, s9 at 1-min windows.
LOOKBACK_MIN = 60.0


def windows_of(doc):
    for key in ("windows", "results"):
        v = doc.get(key)
        if isinstance(v, list) and v:
            return v, key
    return [], None


def components_of(rec):
    for pathspec in (("riskComponents",), ("core", "riskComponents"),
                     ("coreSummary", "riskComponents")):
        cur = rec
        for p in pathspec:
            cur = cur.get(p) if isinstance(cur, dict) else None
            if cur is None:
                break
        if isinstance(cur, dict) and cur:
            return cur
    return {}


def risk_of(rec):
    for k in ("riskScore", "riskScore0to100", "risk"):
        if k in rec:
            try:
                return float(rec[k])
            except (TypeError, ValueError):
                pass
    core = rec.get("core") or rec.get("coreSummary") or {}
    for k in ("riskScore0to100", "riskScore"):
        if k in core:
            try:
                return float(core[k])
            except (TypeError, ValueError):
                pass
    return None


def truth_of(rec):
    """Whether this window is labelled malicious, in either harness's shape."""
    if "botnet_fraction" in rec:
        try:
            return float(rec["botnet_fraction"]) >= 0.5
        except (TypeError, ValueError):
            return None
    for k in ("truth", "truthLabel", "groundTruth"):
        v = rec.get(k)
        if isinstance(v, str):
            return v.lower() in ("attack", "malicious", "true")
        if isinstance(v, bool):
            return v
    return None


def events_of(rec):
    """Windowed event count, in whichever shape this harness used."""
    for pathspec in (("attackMetrics",), ("core", "attackMetrics"),
                     ("coreSummary", "attackMetrics")):
        cur = rec
        for p in pathspec:
            cur = cur.get(p) if isinstance(cur, dict) else None
            if cur is None:
                break
        if isinstance(cur, dict):
            for k in ("attacksLast1Min", "attacksLast5Min"):
                if k in cur:
                    try:
                        return float(cur[k])
                    except (TypeError, ValueError):
                        pass
    for k in ("labeled_flows", "events", "flows"):
        if k in rec:
            try:
                return float(rec[k])
            except (TypeError, ValueError):
                pass
    return None


def predicted_of(rec):
    v = rec.get("detectorPredicted")
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() not in ("normal", "benign", "false", "")
    st = rec.get("state")
    if isinstance(st, str):
        return st.strip().lower() in ("high", "critical")
    return None


def _ts(s):
    from datetime import datetime
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None


def data_start_of(doc):
    """First instant this run's own traffic can appear in the store."""
    span = doc.get("ingest_span")
    if isinstance(span, dict) and span.get("from"):
        return _ts(span["from"])
    if doc.get("injectionStart"):
        return _ts(doc["injectionStart"])
    return None


def window_end_of(rec):
    for k in ("windowEnd", "timestamp"):
        if rec.get(k):
            return _ts(rec[k])
    return None


def hour_count_of(rec):
    am = rec.get("attackMetrics") if isinstance(rec.get("attackMetrics"), dict) else None
    if am and "attacksLastHour" in am:
        try:
            return float(am["attacksLastHour"])
        except (TypeError, ValueError):
            return None
    return None


def audit(path):
    try:
        with open(path) as fh:
            doc = json.load(fh)
    except Exception as e:
        return {"file": path, "error": str(e)}

    if isinstance(doc, list):
        doc = {"windows": doc}

    recs, key = windows_of(doc)
    if not recs:
        return {"file": path, "error": "no per-window records"}

    # Did this run carry guards when it was produced?
    had_guards = ("guard_failures" in doc) or ("guards" in doc)

    findings = []

    # --- UNREACHABLE_THRESHOLD ---
    risks = [r for r in (risk_of(w) for w in recs) if r is not None]
    ceiling = max(risks) if risks else None
    if ceiling is not None and ceiling < DEPLOYED_STATE_THRESHOLD:
        findings.append({
            "guard": "UNREACHABLE_THRESHOLD",
            "detail": f"highest risk score {ceiling:.2f} < alerting threshold "
                      f"{DEPLOYED_STATE_THRESHOLD} over {len(risks)} windows",
        })

    # --- EMPTY_CLASS ---
    truths = [t for t in (truth_of(w) for w in recs) if t is not None]
    if truths:
        n_mal = sum(1 for t in truths if t)
        n_ben = len(truths) - n_mal
        if n_mal == 0 or n_ben == 0:
            findings.append({
                "guard": "EMPTY_CLASS",
                "detail": f"malicious {n_mal}, benign {n_ben} of {len(truths)} "
                          f"labelled windows",
            })

    # --- TRIVIAL_NEGATIVE_CLASS / UNDERPOWERED_CLASS ---
    labelled = [(w, truth_of(w)) for w in recs]
    labelled = [(w, t) for w, t in labelled if t is not None]
    if labelled:
        neg = [w for w, t in labelled if not t]
        pos = [w for w, t in labelled if t]

        neg_events = [e for e in (events_of(w) for w in neg) if e is not None]
        if neg and neg_events and max(neg_events) == 0:
            findings.append({
                "guard": "TRIVIAL_NEGATIVE_CLASS",
                "detail": f"all {len(neg)} negative windows contain zero events; "
                          f"the comparison separates traffic-present from "
                          f"traffic-absent, not malicious from benign",
            })

        for label, group in (("negative", neg), ("positive", pos)):
            if 0 < len(group) < MIN_CLASS_N:
                findings.append({
                    "guard": "UNDERPOWERED_CLASS",
                    "detail": f"{len(group)} {label} window(s), below the minimum "
                              f"of {MIN_CLASS_N}; a rate computed over this class "
                              f"is not meaningful",
                })

    # --- UNDERIVED_GROUND_TRUTH ---
    # Every other guard is a function of the confusion matrix. This one is not:
    # a matrix produced from a boundary the harness chose is indistinguishable
    # from one produced by a detector on correct labels. Withhold when the
    # artifact records a boundary that was not derived from the capture.
    tm = doc.get("truthMode")
    if isinstance(tm, str) and tm in UNDERIVED_TRUTH_MODES:
        findings.append({
            "guard": "UNDERIVED_GROUND_TRUTH",
            "detail": f"truthMode = {tm!r}: the boundary is the start of replay, "
                      f"so labels separate traffic-present from traffic-absent "
                      f"rather than malicious from benign",
        })

    # --- NEAR_CHANCE_SEPARATION ---
    # A matrix can report a non-zero F1 while the detector is not
    # distinguishable from chance: alerting on most windows produces true
    # positives as an arithmetic consequence of alerting often. Balanced
    # accuracy under the null is 0.5, SE = 0.5*sqrt(0.25/n_pos + 0.25/n_neg).
    # The bar is a function of class sizes, not of any observed result.
    if labelled:
        preds = [(t, predicted_of(w)) for w, t in labelled]
        preds = [(t, p) for t, p in preds if p is not None]
        if preds:
            tp = sum(1 for t, p in preds if t and p)
            fn = sum(1 for t, p in preds if t and not p)
            fp = sum(1 for t, p in preds if not t and p)
            tn = sum(1 for t, p in preds if not t and not p)
            n_pos, n_neg = tp + fn, tn + fp
            if n_pos and n_neg:
                bal = ((tp / n_pos) + (tn / n_neg)) / 2.0
                den = 2 * tp + fp + fn
                f1 = (2 * tp / den) if den else 0.0
                se = 0.5 * math.sqrt(0.25 / n_pos + 0.25 / n_neg)
                bar = 0.5 + NEAR_CHANCE_Z * se
                if f1 > 0 and bal < bar:
                    findings.append({
                        "guard": "NEAR_CHANCE_SEPARATION",
                        "detail": f"balanced accuracy {bal:.3f} within "
                                  f"{NEAR_CHANCE_Z} SE of chance for "
                                  f"{n_pos}/{n_neg} windows (bar {bar:.3f}), "
                                  f"while F1 = {f1:.3f}, FPR = {fp/n_neg:.3f}",
                    })

    # --- INCOMPLETE_LOOKBACK ---
    # Not a function of the confusion matrix. A window is admissible only if
    # the replay has supplied its full lookback. Withhold when, restricted to
    # admissible windows, either class has fewer than MIN_CLASS_N windows
    # carrying traffic: the reported comparison is then between windows that
    # differ in how long the replay had been running, not in what they contain.
    t0 = data_start_of(doc)
    if t0 is not None and labelled:
        adm = {True: 0, False: 0}
        tot = {True: 0, False: 0}
        for w, t in labelled:
            te = window_end_of(w)
            ev = events_of(w)
            # A missing count is unknown, not zero: keep the window. Only a
            # recorded zero marks it empty.
            if te is None or ev == 0:
                continue
            tot[t] += 1
            if (te - t0).total_seconds() / 60.0 >= LOOKBACK_MIN:
                adm[t] += 1
        if min(adm.values()) < MIN_CLASS_N:
            findings.append({
                "guard": "INCOMPLETE_LOOKBACK",
                "detail": f"windows with traffic and a full {LOOKBACK_MIN:.0f}-min "
                          f"lookback: malicious {adm[True]}/{tot[True]}, benign "
                          f"{adm[False]}/{tot[False]}",
            })

    # --- FOREIGN_LOOKBACK ---
    # The lookback is scoped by source, not by run: traffic left by an earlier
    # run or scenario inside the trailing hour is scored as this run's history.
    # Detectable where windows record the hour count: any record before this
    # run's traffic starts with a non-zero hour count.
    if t0 is not None:
        for w in recs:
            te = window_end_of(w)
            hc = hour_count_of(w)
            if te is not None and hc and te <= t0:
                findings.append({
                    "guard": "FOREIGN_LOOKBACK",
                    "detail": f"{hc:.0f} events in the trailing hour at "
                              f"{te.isoformat()}, before this run's first "
                              f"replayed event",
                })
                break

    # --- INVERTED_SEPARATION ---
    sep = doc.get("risk_separation") or doc.get("separation") or {}
    margin = sep.get("separation_margin")
    try:
        if margin is not None and float(margin) < 0:
            findings.append({
                "guard": "INVERTED_SEPARATION",
                "detail": f"separation margin {float(margin):.2f}: mean risk is "
                          f"HIGHER on benign windows than malicious ones. Any "
                          f"threshold applied to this score selects benign "
                          f"traffic preferentially.",
            })
    except (TypeError, ValueError):
        pass

    # --- SATURATED_COMPONENT ---
    series = {}
    for w in recs:
        for k, v in components_of(w).items():
            try:
                series.setdefault(k, []).append(float(v or 0))
            except (TypeError, ValueError):
                pass
    for name, vals in series.items():
        budget = BUDGETS.get(name, 0)
        if budget <= 0 or not vals:
            continue
        at_cap = sum(1 for v in vals if v >= budget * SATURATION_VALUE_FRAC)
        if at_cap >= len(vals) * SATURATION_WINDOW_FRAC:
            findings.append({
                "guard": "SATURATED_COMPONENT",
                "detail": f"{name} at >={int(SATURATION_VALUE_FRAC*100)}% of its "
                          f"{budget}-point budget in {at_cap}/{len(vals)} windows",
            })

    # --- DEGENERATE_SWEEP ---
    # Fires when the sweep's BEST F1 sits at FPR >= DEGENERATE_FPR. The earlier
    # form fired on the first row with FPR >= 0.95 and a truthy F1, which every
    # sweep starting at a low threshold has, so it measured the sweep's range
    # rather than its optimum (47 of 49 CTU-13 runs, against 20 by this rule).
    sweep = doc.get("threshold_sweep")
    if isinstance(sweep, list):
        rows = []
        for row in sweep:
            if not isinstance(row, dict):
                continue
            f1 = row.get("f1", row.get("best_f1"))
            try:
                rows.append((float(f1), float(row.get("fpr")), row))
            except (TypeError, ValueError):
                pass
        if rows:
            f1, fpr, row = max(rows, key=lambda t: t[0])
            if fpr >= DEGENERATE_FPR:
                findings.append({
                    "guard": "DEGENERATE_SWEEP",
                    "detail": f"best F1 {f1:.3f} at FPR {fpr:.3f} "
                              f"(truth>={row.get('truth_threshold', '?')}); "
                              f"constant-attack signature",
                })

    return {
        "file": path,
        "windows": len(recs),
        "record_key": key,
        "had_guards_when_produced": had_guards,
        "ceiling": ceiling,
        "findings": findings,
        "would_be_withheld": any(
            f["guard"] in (
                "UNREACHABLE_THRESHOLD",
                "EMPTY_CLASS",
                "TRIVIAL_NEGATIVE_CLASS",
                "UNDERPOWERED_CLASS",
                "INVERTED_SEPARATION",
                "NEAR_CHANCE_SEPARATION",
                "UNDERIVED_GROUND_TRUTH",
                "INCOMPLETE_LOOKBACK",
                "FOREIGN_LOOKBACK",
            )
            for f in findings
        ),
    }


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    as_csv = "--csv" in sys.argv
    if not args:
        print(__doc__)
        sys.exit(1)

    results = [audit(p) for p in args]
    ok = [r for r in results if "error" not in r]

    if as_csv:
        print("file,windows,had_guards,ceiling,would_be_withheld,guards_tripped")
        for r in ok:
            print(",".join([
                os.path.basename(r["file"]),
                str(r["windows"]),
                str(r["had_guards_when_produced"]),
                f"{r['ceiling']:.2f}" if r["ceiling"] is not None else "",
                str(r["would_be_withheld"]),
                ";".join(sorted({f["guard"] for f in r["findings"]})) or "none",
            ]))
        return

    print("=" * 78)
    print(f"  RETROACTIVE GUARD AUDIT  (guard set {GUARD_SET_VERSION})")
    print("=" * 78)
    print(f"  {len(results)} file(s), {len(ok)} readable\n")

    for r in results:
        if "error" in r:
            print(f"  {os.path.basename(r['file'])[:60]}")
            print(f"     skipped: {r['error']}\n")
            continue

        mark = "WITHHELD" if r["would_be_withheld"] else "ok      "
        prod = "with guards" if r["had_guards_when_produced"] else "pre-guard "
        print(f"  [{mark}] {os.path.basename(r['file'])[:52]}")
        print(f"             {r['windows']:4d} windows | produced {prod} | "
              f"ceiling {r['ceiling'] if r['ceiling'] is not None else 'n/a'}")
        for f in r["findings"]:
            print(f"             - {f['guard']}: {f['detail']}")
        print()

    withheld = [r for r in ok if r["would_be_withheld"]]
    preguard = [r for r in ok if not r["had_guards_when_produced"]]
    preguard_withheld = [r for r in preguard if r["would_be_withheld"]]

    print("=" * 78)
    print("  SUMMARY")
    print("=" * 78)
    print(f"  produced before guards existed : {len(preguard)} of {len(ok)}")
    print(f"  would be withheld today        : {len(withheld)} of {len(ok)}")
    print(f"  both                           : {len(preguard_withheld)}")
    print()
    if preguard_withheld:
        print("  These results were archived without the checks that would now")
        print("  suppress their confusion matrices. They remain valid records of")
        print("  what the system produced; they are not valid evidence of detection")
        print("  performance, and nothing in the files themselves said so.")
        print()


if __name__ == "__main__":
    main()
