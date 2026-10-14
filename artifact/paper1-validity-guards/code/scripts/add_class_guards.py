#!/usr/bin/env python3
"""
add_class_guards.py — adds two guards to guard_audit.py.

TRIVIAL_NEGATIVE_CLASS
    Every window in the negative class contains zero events. The classes are
    populated, so EMPTY_CLASS does not fire, but the comparison is between
    traffic-present and traffic-absent rather than malicious and benign. Any
    monotonic function of volume separates them perfectly.

    Measured: the 2026-05-25 Emotet run reported precision 1.0, recall 1.0,
    F1 1.0 over 144 samples with 59 all-zero negative windows. Three further
    runs have an all-zero negative class of size 1, which is the next guard's
    problem rather than this one's.

UNDERPOWERED_CLASS
    A class has fewer than MIN_CLASS_N windows. A specificity of 1.0 computed
    over a single negative window is not a false-positive rate. This is the
    same failure as the existing window-to-span rule one level down: enough
    windows overall, too few in one class.

    Measured: three archived pcap runs have exactly one negative window.

Run from ~/research/scripts:  python3 add_class_guards.py
"""

import io
import sys

P = "guard_audit.py"

s = io.open(P, encoding="utf-8").read()


def sub(name, old, new):
    global s
    n = s.count(old)
    if n != 1:
        print(f"FAIL [{name}]: anchor matched {n} times, expected 1")
        sys.exit(1)
    s = s.replace(old, new)
    print(f"ok   [{name}]")


# --- constants ---------------------------------------------------------
sub(
    "constants",
    "DEGENERATE_FPR = 0.95",
    """DEGENERATE_FPR = 0.95
MIN_CLASS_N = 5""",
)


# --- docstring ---------------------------------------------------------
sub(
    "doc",
    """    DEGENERATE_SWEEP       the best F1 in a threshold sweep comes with FPR close
                           to 1, i.e. the constant-attack detector signature""",
    """    DEGENERATE_SWEEP       the best F1 in a threshold sweep comes with FPR close
                           to 1, i.e. the constant-attack detector signature
    TRIVIAL_NEGATIVE_CLASS every negative window has zero events, so the
                           comparison is traffic-present vs traffic-absent
    UNDERPOWERED_CLASS     a class has too few windows to support a rate""",
)


# --- helper to read event counts --------------------------------------
sub(
    "helper",
    """def audit(path):""",
    '''def events_of(rec):
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


def audit(path):''',
)


# --- the two new checks ------------------------------------------------
sub(
    "checks",
    """    # --- SATURATED_COMPONENT ---""",
    """    # --- TRIVIAL_NEGATIVE_CLASS / UNDERPOWERED_CLASS ---
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

    # --- SATURATED_COMPONENT ---""",
)


# --- treat both as withholding conditions ------------------------------
sub(
    "withhold",
    """        "would_be_withheld": any(
            f["guard"] in ("UNREACHABLE_THRESHOLD", "EMPTY_CLASS")
            for f in findings
        ),""",
    """        "would_be_withheld": any(
            f["guard"] in (
                "UNREACHABLE_THRESHOLD",
                "EMPTY_CLASS",
                "TRIVIAL_NEGATIVE_CLASS",
                "UNDERPOWERED_CLASS",
            )
            for f in findings
        ),""",
)


io.open(P + ".bak_preclass", "w", encoding="utf-8").write(
    io.open(P, encoding="utf-8").read()
)
io.open(P, "w", encoding="utf-8").write(s)
print(f"\nwrote {P}  (backup: {P}.bak_preclass)")
