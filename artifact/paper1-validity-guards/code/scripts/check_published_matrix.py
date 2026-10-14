#!/usr/bin/env python3
"""
Apply the architecture-independent validity conditions to a published
evaluation, given only what a paper typically reports.

Six of the eight conditions in the Chiron guard set need no access to the
detector: they are computable from class counts, a confusion matrix, per-class
score means, or a threshold sweep. This script implements those six so the
conditions can be checked against any published result.

The two omitted conditions (UNREACHABLE_THRESHOLD, SATURATED_COMPONENT)
require a component-decomposed score and are not applicable here.
"""

import math
from dataclasses import dataclass, field
from typing import Optional, List, Dict


@dataclass
class Evaluation:
    """What a paper reports. Every field is optional; conditions that lack
    their inputs are returned as 'not assessable' rather than silently passing."""
    name: str
    class_counts: Dict[str, int] = field(default_factory=dict)   # class -> n
    tp: Optional[int] = None
    fp: Optional[int] = None
    tn: Optional[int] = None
    fn: Optional[int] = None
    events_per_negative: Optional[List[int]] = None   # events in each negative unit
    class_score_means: Optional[Dict[str, float]] = None  # class -> mean score
    sweep: Optional[List[Dict[str, float]]] = None    # [{'f1':..,'fpr':..}, ...]
    window_width: Optional[float] = None              # seconds
    capture_span: Optional[float] = None              # seconds
    window_stride: Optional[float] = None             # seconds


UNDERPOWERED_MAX = 2   # a class this small cannot support a rate
NEAR_CHANCE_Z = 1.96   # balanced accuracy within this many SE of chance


def check(ev: Evaluation):
    fired, passed, skipped = [], [], []

    # --- UNDERPOWERED CLASS -------------------------------------------------
    if ev.class_counts:
        small = {k: v for k, v in ev.class_counts.items() if v <= UNDERPOWERED_MAX}
        if small:
            fired.append(("UNDERPOWERED_CLASS",
                          f"class(es) with n <= {UNDERPOWERED_MAX}: " +
                          ", ".join(f"{k}={v}" for k, v in small.items())))
        else:
            passed.append("UNDERPOWERED_CLASS")
    else:
        skipped.append(("UNDERPOWERED_CLASS", "no per-class counts reported"))

    # --- EMPTY CLASS --------------------------------------------------------
    if ev.class_counts:
        empty = [k for k, v in ev.class_counts.items() if v == 0]
        if empty:
            fired.append(("EMPTY_CLASS", f"class(es) with no members: {empty}"))
        else:
            passed.append("EMPTY_CLASS")
    elif ev.fn is not None and ev.tp is not None:
        if ev.tp + ev.fn == 0:
            fired.append(("EMPTY_CLASS", "positive class is empty; recall undefined"))
        else:
            passed.append("EMPTY_CLASS")
    else:
        skipped.append(("EMPTY_CLASS", "no class counts or matrix reported"))

    # --- TRIVIAL NEGATIVE CLASS --------------------------------------------
    if ev.events_per_negative is not None:
        empty_neg = sum(1 for e in ev.events_per_negative if e == 0)
        n = len(ev.events_per_negative)
        if n and empty_neg == n:
            fired.append(("TRIVIAL_NEGATIVE_CLASS",
                          f"all {n} negative units contain zero events; the "
                          "comparison separates traffic-present from traffic-absent"))
        else:
            passed.append("TRIVIAL_NEGATIVE_CLASS")
    else:
        skipped.append(("TRIVIAL_NEGATIVE_CLASS",
                        "per-unit event counts for the negative class not reported"))

    # --- NEAR CHANCE SEPARATION ---
    if None not in (ev.tp, ev.fp, ev.tn, ev.fn):
        n_pos, n_neg = ev.tp + ev.fn, ev.tn + ev.fp
        if n_pos and n_neg:
            bal = ((ev.tp / n_pos) + (ev.tn / n_neg)) / 2.0
            den = 2 * ev.tp + ev.fp + ev.fn
            f1 = (2 * ev.tp / den) if den else 0.0
            se = 0.5 * math.sqrt(0.25 / n_pos + 0.25 / n_neg)
            bar = 0.5 + NEAR_CHANCE_Z * se
            if f1 > 0 and bal < bar:
                fired.append(("NEAR_CHANCE_SEPARATION",
                              f"balanced accuracy {bal:.3f} within {NEAR_CHANCE_Z} SE "
                              f"of chance for {n_pos}/{n_neg} (bar {bar:.3f}), "
                              f"F1 = {f1:.3f}"))
            else:
                passed.append(f"NEAR_CHANCE_SEPARATION (bal {bal:.3f}, bar {bar:.3f})")
        else:
            skipped.append(("NEAR_CHANCE_SEPARATION", "one class empty"))
    else:
        skipped.append(("NEAR_CHANCE_SEPARATION", "confusion matrix not reported"))

    # --- INVERTED SEPARATION ------------------------------------------------
    if ev.class_score_means and len(ev.class_score_means) >= 2:
        items = sorted(ev.class_score_means.items(), key=lambda kv: kv[1])
        lowest, highest = items[0][0], items[-1][0]
        if "benign" in highest.lower() or "normal" in highest.lower():
            fired.append(("INVERTED_SEPARATION",
                          f"'{highest}' scores above '{lowest}'; a threshold would "
                          "select benign traffic preferentially"))
        else:
            passed.append("INVERTED_SEPARATION")
    else:
        skipped.append(("INVERTED_SEPARATION", "per-class score means not reported"))

    # --- DEGENERATE SWEEP ---------------------------------------------------
    if ev.sweep:
        best = max(ev.sweep, key=lambda p: p.get("f1", 0))
        if best.get("fpr", 0) >= 0.95:
            fired.append(("DEGENERATE_SWEEP",
                          f"best F1={best['f1']:.3f} occurs at FPR={best['fpr']:.2f}: "
                          "the constant-alert signature"))
        else:
            passed.append("DEGENERATE_SWEEP")
    else:
        skipped.append(("DEGENERATE_SWEEP", "no threshold sweep reported"))

    # --- WINDOW SPAN --------------------------------------------------------
    if ev.window_width and ev.capture_span:
        n_windows = ev.capture_span / ev.window_width
        if n_windows < 2:
            fired.append(("WINDOW_SPAN",
                          f"capture span {ev.capture_span}s at window {ev.window_width}s "
                          f"yields {n_windows:.1f} windows"))
        else:
            passed.append("WINDOW_SPAN")
    else:
        skipped.append(("WINDOW_SPAN", "capture span or window width not reported"))

    return fired, passed, skipped


def overlap_note(ev: Evaluation, n_reported: Optional[int] = None):
    """Not a guard. Reports the effective sample size when windows overlap,
    which is an upper bound: it treats windows one width apart as independent."""
    if ev.window_width and ev.window_stride and ev.window_stride < ev.window_width:
        frac = ev.window_stride / ev.window_width
        msg = (f"windows overlap: stride/width = {frac:.2f}, so adjacent windows "
               f"share {100*(1-frac):.0f}% of their samples")
        if n_reported:
            msg += f"; n_eff <= {n_reported * frac:.0f} against {n_reported} reported"
        return msg
    return None


def report(ev: Evaluation, n_reported=None):
    print("=" * 72)
    print(ev.name)
    print("=" * 72)
    fired, passed, skipped = check(ev)
    if fired:
        print("\nWITHHELD — conditions met:")
        for name, why in fired:
            print(f"  [{name}]\n      {why}")
    else:
        print("\nNo withholding condition met.")
    if passed:
        print("\nChecked and passed: " + ", ".join(passed))
    if skipped:
        print("\nNot assessable from what the paper reports:")
        for name, why in skipped:
            print(f"  {name}: {why}")
    note = overlap_note(ev, n_reported)
    if note:
        print(f"\nAdditional note (not a guard):\n  {note}")
    print()


if __name__ == "__main__":

    # ---------------------------------------------------------------- case 1
    # Hybrid TDA + LSTM, CIC-IDS2017 (arXiv 2606.31619), Table II.
    # All five classes reported at precision = recall = F1 = 1.000.
    tda = Evaluation(
        name="TDA+LSTM on CIC-IDS2017 (arXiv 2606.31619), Table II",
        class_counts={
            "Benign": 642, "DoS/DDoS": 91, "PortScan": 58,
            "Brute Force": 6, "Bot/Infiltration": 1,
        },
        window_width=50.0,     # 50 samples
        window_stride=25.0,    # step 25 samples
        tp=156, fp=0, tn=642, fn=0,   # Figure 3, binary confusion matrix
    )
    report(tda, n_reported=798)

    # ---------------------------------------------------------------- case 2
    # MCC paper (arXiv 2512.19203), Heartbleed subset of CSE-CIC-IDS2017.
    # ZeroR reaches 99.978% accuracy at 0% attack recall; recall of 90.9%
    # elsewhere implies 11 attack instances (10/11).
    mcc = Evaluation(
        name="MCC study, Heartbleed subset (arXiv 2512.19203), Table 4",
        class_counts={"Benign": 49989, "Heartbleed": 11},
    )
    report(mcc)
