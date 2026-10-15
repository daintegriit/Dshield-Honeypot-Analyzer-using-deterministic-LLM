# First-author verification of the temporal screen

Protocol §6: every paper coded EXPOSED or MITIGATED, plus a seeded 20% (seed
20261014) of the rest, is checked against the paper by the first author, and
the number of codes changed is reported. The sample (`VERIFY_LIST.txt`, 14
papers: 1 coded EXPOSED + 13 random) was drawn after coding completed
(amendment A4). Verification was done 2026-10-14, paper by paper, against the
full text.

- `VERIFY_DECISIONS.tsv` — one row per decision: `all/AGREE`, or the question,
  the adjudicated code, the verified code, and the quoted reason.
- `apply_verify.py` — applies the decisions to `TEMPORAL_SCREEN_CODES.tsv`,
  sets Q4 to NA where Q1 is no longer YES (protocol: Q4 only if Q1 is YES),
  and recomputes every outcome with the locked §5 rule.
- `TEMPORAL_SCREEN_CODES_VERIFIED.tsv` — the result; `verified_change` marks
  papers whose codes changed.

## Result

8 codes changed in 7 of 14 papers; 4 outcomes moved:

| paper | change | outcome |
|---|---|---|
| 2508.14192 | Q3 YES→UNSTATED | EXPOSED→UNASSESSABLE |
| 2605.06629 | Q1 UNSTATED→NO | UNASSESSABLE→NOT_EXPOSED |
| 2605.07536 | Q3 UNSTATED→YES, Q4 NOT_STATED→HANDLED | UNASSESSABLE→MITIGATED |
| 2605.23004 | Q2 UNSTATED→NO | unchanged NOT_EXPOSED |
| 2606.29797 | Q1 NO→UNSTATED | unchanged NOT_EXPOSED |
| 2608.24454 | Q2 UNSTATED→NO | UNASSESSABLE→NOT_EXPOSED |
| 2609.39584 | Q1 YES→UNSTATED (Q4→NA) | unchanged UNASSESSABLE |

Seven of the eight changed codes were codes on which both coders A and B
agreed before adjudication; Cohen's kappa therefore measures agreement between
correlated coders, not accuracy.

Final (68 coded): NOT_EXPOSED 30, MITIGATED 1, EXPOSED 0, UNASSESSABLE 37.
Excluded: 9 NOT_DETECTION_EVAL, 1 NOT_RETRIEVED. Q3 stated (YES or NO) in 4 of 68.
    aa79cad8d3ecda8806f82bc330a1785b54f3288b25cc485c14b30786c742742f  VERIFY_DECISIONS.tsv
    bfde6da4c043a1c4101dda62035edc6e3d3be6fef7196b47f3ea0daf5e277a02  TEMPORAL_SCREEN_CODES_VERIFIED.tsv
    cc819c92e0121a3db4ea80a9a416443e1df8dd2911aa8188bb6e13b1f7cc2d9d  apply_verify.py
