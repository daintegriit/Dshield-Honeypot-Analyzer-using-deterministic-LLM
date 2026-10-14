#!/usr/bin/env python3
"""
add_source_window.py — adds infection-centred source-window truncation to
replay_pcap_events.py.

WHY
---
The Stratosphere captures run for days to months, because the infected machines
were left recording. The transition the ground truth marks occurs within the
first few hundred seconds. Replaying a full capture in natural timing is
infeasible for the longer traces (Sality and CCleaner exceed three months), and
compressing it into a fixed target duration reduces a several-hundred-second
pre-infection period to under two seconds:

    Emotet 271-1  source span 1,389,673 s, target 5,400 s -> scale 0.0039
                  infection offset 459 s -> 1.8 s in replay time

Both failure modes were measured. This adds a third option: replay only a window
spanning the infection boundary, at natural timing.

    SOURCE_WINDOW_PRE=300 SOURCE_WINDOW_POST=900 REPLAY_MODE=natural

gives five minutes of pre-infection baseline and fifteen minutes after, at real
inter-arrival timing, for any capture regardless of its total span.

THE PART THAT MATTERS
---------------------
After truncation the infection is no longer INFECTION_OFFSET_SECONDS from the
first event, because the head of the capture has been cut. The offset must be
rebased against the new first event before it is emitted for the harness.
Failing to rebase reproduces the labelling error this corpus already suffered
once, in a form that would be harder to notice: the offset would be plausible
rather than absent.

Run from ~/research/scripts:  python3 add_source_window.py
"""

import io
import sys

P = "replay_pcap_events.py"
s = io.open(P, encoding="utf-8").read()


def sub(name, old, new):
    global s
    n = s.count(old)
    if n != 1:
        print(f"FAIL [{name}]: anchor matched {n} times, expected 1")
        sys.exit(1)
    s = s.replace(old, new)
    print(f"ok   [{name}]")


# --- config ------------------------------------------------------------
sub(
    "config",
    'INFECTION_OFFSET_SECONDS = float(os.environ.get("INFECTION_OFFSET_SECONDS", "0"))',
    '''INFECTION_OFFSET_SECONDS = float(os.environ.get("INFECTION_OFFSET_SECONDS", "0"))

# Source-window truncation, in SOURCE seconds either side of the infection
# boundary. 0/0 disables it and the whole capture is replayed.
#
# Applied to the source timeline before scheduling, so independent of
# REPLAY_MODE. With REPLAY_MODE=natural the replay lasts PRE+POST seconds
# regardless of how long the capture ran.
SOURCE_WINDOW_PRE = float(os.environ.get("SOURCE_WINDOW_PRE", "0"))
SOURCE_WINDOW_POST = float(os.environ.get("SOURCE_WINDOW_POST", "0"))''',
)


# --- truncation function, inserted before load_events -------------------
sub(
    "function",
    "def load_events() -> Tuple[List[Event], LoadStats]:",
    '''def truncate_to_infection_window(events: List[Event]) -> Tuple[List[Event], float]:
    """
    Keep only events within [boundary - PRE, boundary + POST], and return the
    kept events together with the infection offset REBASED against the new
    first event.

    Rebasing is the whole point. The harness computes attack truth as
    injectionStart + offset. If the offset is left at its original value after
    the head of the capture has been removed, the boundary lands in the wrong
    place by exactly the amount that was cut -- a plausible-looking number that
    is wrong, which is harder to notice than an absent one.
    """
    if not events:
        return events, INFECTION_OFFSET_SECONDS
    if SOURCE_WINDOW_PRE <= 0 and SOURCE_WINDOW_POST <= 0:
        return events, INFECTION_OFFSET_SECONDS
    if INFECTION_OFFSET_SECONDS <= 0:
        print("  WARNING: SOURCE_WINDOW set but INFECTION_OFFSET_SECONDS is 0;")
        print("           no boundary to centre on. Truncation skipped.")
        return events, INFECTION_OFFSET_SECONDS

    capture_start = events[0].ts
    boundary = capture_start + INFECTION_OFFSET_SECONDS
    lo = boundary - SOURCE_WINDOW_PRE if SOURCE_WINDOW_PRE > 0 else events[0].ts
    hi = boundary + SOURCE_WINDOW_POST if SOURCE_WINDOW_POST > 0 else events[-1].ts

    kept = [e for e in events if lo <= e.ts <= hi]

    if not kept:
        print("  WARNING: source window contains no events. Truncation skipped.")
        return events, INFECTION_OFFSET_SECONDS

    pre_count = sum(1 for e in kept if e.ts < boundary)
    post_count = len(kept) - pre_count
    rebased = boundary - kept[0].ts

    print("-" * 72)
    print("  SOURCE WINDOW TRUNCATION")
    print(f"     window:            -{SOURCE_WINDOW_PRE:.0f}s / +{SOURCE_WINDOW_POST:.0f}s "
          f"around the infection boundary")
    print(f"     events:            {len(kept)} of {len(events)} kept "
          f"({pre_count} pre-infection, {post_count} post)")
    print(f"     source span kept:  {kept[-1].ts - kept[0].ts:.1f}s "
          f"(capture span {events[-1].ts - events[0].ts:.1f}s)")
    print(f"     offset rebased:    {INFECTION_OFFSET_SECONDS:.1f}s "
          f"-> {rebased:.1f}s from the new first event")
    if pre_count == 0:
        print("     WARNING: no pre-infection events in the window. The negative")
        print("              class will be empty and the run cannot support a rate.")
    print("-" * 72)

    return kept, rebased


def load_events() -> Tuple[List[Event], LoadStats]:''',
)


# --- apply after loading, before scheduling -----------------------------
sub(
    "apply",
    """    offsets, schedule_info = compute_schedule_offsets(
        events=events,""",
    """    events, INFECTION_OFFSET_SECONDS = truncate_to_infection_window(events)

    offsets, schedule_info = compute_schedule_offsets(
        events=events,""",
)


io.open(P + ".bak_prewindow", "w", encoding="utf-8").write(
    io.open(P, encoding="utf-8").read()
)
io.open(P, "w", encoding="utf-8").write(s)
print(f"\nwrote {P}  (backup: {P}.bak_prewindow)")
print()
print("IMPORTANT: the 'apply' edit assigns to INFECTION_OFFSET_SECONDS inside a")
print("function. That function must declare 'global INFECTION_OFFSET_SECONDS'")
print("near its top, or Python creates a local and the rebased offset never")
print("reaches compute_infection_offset_replay(). Check and add it if missing.")

