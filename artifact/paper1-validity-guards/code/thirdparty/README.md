# Third-party detector test kit

Implements `registration/THIRD_PARTY_DETECTORS_REGISTRATION.md` (locked at
b34fdf2) with the clarifications in `THIRD_PARTY_DETECTORS_AMENDMENTS.md`.
Run on the machine holding the CTU-13 replay database, one step at a time:

    bash run_all.sh setup        tools, venv, Kitsune clone, versions
    bash run_all.sh inputs       export replayed flows; join to .binetflow; TRUE/ARRIVAL inputs
    bash run_all.sh windows      the kit's windows must equal Chiron's (stops otherwise)
    bash run_all.sh rf           D3
    bash run_all.sh slips-pilot  D1 format check on Slips' bundled sample
    bash run_all.sh slips        D1 on registered inputs
    PCAP=... BOUNDARY=... INFECTED=... C2=... bash run_all.sh kitsune   D2
    bash run_all.sh audit        guards (lookback per detector) + statistics + P1-P6

| file | role |
|---|---|
| export_flows.js | every replayed document with both clocks, from Mongo |
| build_inputs.py | joins rows to documents by the replay's own raw line; writes TRUE and ARRIVAL .binetflow (labels blanked) |
| common.py | windows identical to analyze_ctu13.js; Pearson/Fisher; run files guard_audit.py reads |
| rf.py, make_rf_runs.py | D3 |
| run_slips.sh, slips_parse.py, make_slips_runs.py | D1 |
| kitsune_run.py | D2 |
| check_windows.py | window identity check (C9) |
| guard_param.py | guard_audit.py unmodified, lookback per detector (§6) |
| stats.py | registered statistics, P1-P6, exploratory drift checks (A2) |

The kit was tested end to end on synthetic flows and packets before the lock
of A1; no registered data was read in testing.
