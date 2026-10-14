# Artifact: Perfect Scores, No Detection — Validity Guards for Hybrid Security Evaluation

Everything needed to check the paper's numbers without rerunning a replay:
the detector core at the version evaluated, the scoring harness, the per-window
record of every run the paper reports, the governed-generation outputs, the
guard audit script with its outputs at each date, and the held-out registration.

Server addresses in code have been replaced by `BACKEND_HOST` and `OLLAMA_HOST`.
Raw captures are not included; they are public from the Stratosphere Laboratory
(CTU-13, Malware Capture Facility, CTU-Mixed).

## Layout

| Path | Contents |
|---|---|
| `code/backend/` | Backend snapshot frozen 2026-10-08. Detector core: `services/copilotCore.js` (`copilotCore-v4.3-dos-burst-only`). CTU-13 scorer: `analyze_ctu13.js`. Grounding checker: `check_grounding.js`. Route coverage: `check_path_coverage.js`. |
| `code/scripts/` | Replay harness (`orchestrator.py`, `replay_pcap_events.py`, `replay_ctu13.py`, `run_full_experiment.js`) and `guard_audit.py`, guard set `2026-10-14a` (twelve conditions). |
| `runs/archive92/` | The 92 archived runs audited in Section VI. `MANIFEST.tsv` maps each file to its original location. |
| `runs/corpus_reruns/` | Table VII (ten captures, deployed and ablated), Table VI (WannaCry, labels applied / not applied), Table IX (held-out Mixed-7). |
| `runs/ctu13_normalized/` | Table IV: CTU-13 s1, s2, s6, s8, s9 under normalized scoring at 1, 2, 3 and 5-minute windows. |
| `runs/ctu13_deployed_v43/` | Tables II–III, one-minute cells: deployed core on s2, s6, s8, s9. |
| `runs/grounding/` | Table V arms (`grounding_baseline`, `_v2`, `_v3`, `_ungoverned`), the depth-2 test (`_v4_depth`), live (`_v5_scoped`), deduplicated prompt (`_v6_dedup`), temperature control (`_v7_temp08`), refusal gate checks. Each citation records `via`: `literal` (strict) or `search` (leaf-key fallback). |
| `audits/` | The same 92 runs audited under the guard set on each date: 9 and 10 conditions (2026-09-09), 10 with the corrected key (2026-10-05), 12 (2026-10-14). |
| `registration/` | `HELDOUT_REGISTRATION.md`, dated 2026-08-09, written before any held-out capture was fetched. |
| `analysis/` | Scripts behind the 2026-10-14 revision, and the published-evaluation screen (`run_genstudy.py`, the locked queries, the verdicts). |

## Reproducing the headline numbers

All commands run from this directory with Python 3, standard library only.

```
# Twelve-condition audit of the 92 archived runs: 92 of 92 withheld
python3 -I code/scripts/guard_audit.py --csv runs/archive92/*.json | grep -c ',True,'

# Table IV, and the s9 correlation after the first replay hour (every interval spans zero)
python3 -I analysis/warmup_ctu2.py runs/ctu13_normalized

# Tables VII and VIII from the raw per-window records
python3 -I analysis/table7.py runs/corpus_reruns/*.json

# Trailing-hour counts at replay start (the Sality lookback leak)
python3 -I analysis/malware_lookback.py runs/corpus_reruns
```

`analysis/bootstrap.py` (Table V intervals) expects the grounding files at the
paths listed at the top of the script; point them at `runs/grounding/`.

## Record format

Malware and held-out runs: `injectionStart`, `detectorConfig` (core version,
profile, `normalised`, reachable budget, gate values as the backend reported
them), and `results[]`, one per scored window, with `timestamp` (window end),
`phase`, `truth` (`Normal`, `Attack`, or null for an excluded straddling
window), `detectorPredicted`, `riskScore`, `riskComponents`, `attackScores`,
`attackMetrics` (including `attacksLastHour`).

CTU-13 runs: `ingest_span`, `config` (window and stride), and `windows[]` with
`windowEnd`, `botnet_fraction`, `riskScore`, `riskComponents`,
`attackTypeScores`.
