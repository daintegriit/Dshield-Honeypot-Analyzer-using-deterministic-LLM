# Protocol: screening published evaluations for the replay-age confound
Written 2026-10-14, before the full text of any paper in the sample was read
for this study. Committed to the public repository before screening begins;
the commit timestamp is the lock.

## 1. Question
Section V-B of the paper shows that a feature aggregated over a trailing
interval scores the start of any stream by how long the stream has run, and that
when benign data precedes attack data in time, the class comparison inherits
that difference. This study asks how often published intrusion-detection
evaluations are exposed to the same confound, using only what a paper states
about its method. It does not ask whether any reported result is correct.

## 2. Sample
Every result of the four searches already locked for the earlier screens, in
their stated date range (2025-01-01 to the search date), excluding the two
papers examined before the first protocol:

    CIC-IDS2017      arxiv_search_20260909.xml               15
    UNSW-NB15        Q1_UNSW-NB15_20261008T171556Z.xml        50
    CTU-13           Q2_CTU-13_20261008T171602Z.xml            7
    CSE-CIC-IDS2018  Q3_CSE-CIC-IDS2018_20261008T171609Z.xml  11
    total results 83; four papers appear in two searches; 79 unique

The list is in `TEMPORAL_SCREEN_SAMPLE.tsv`. Each paper is coded once; a paper
returned by two searches is reported under both. The 72 papers of the earlier
screens are a subset and are reported separately as such, once the record of
which 58 of the 68 October results were screened is added to this folder.

A paper is recorded and not coded if its full text cannot be retrieved, or if it
reports no detection evaluation on traffic data. Both are counted and listed.

## 3. Unit
The paper's primary evaluation: the one whose result the abstract reports. If
the abstract reports several, the first named. If the paper evaluates several
datasets, the dataset of the search that returned it.

## 4. Questions
Each answered YES, NO or UNSTATED, with the section or page and a supporting
quotation of at most 25 words.

**Q1 Temporal aggregation.** Does the detector's input include any feature or
context computed across more than one record ordered in time: a sliding or
tumbling time window, a per-host or per-connection count or rate over an
interval, a sequence model over consecutive records, or a graph or snapshot
built over a time interval? Statistics computed within a single flow (for
example CICFlowMeter's per-flow features) do NOT count. Record the lookback
length if stated.

**Q2 Ordered evaluation.** Are evaluation records presented to the detector in
time order (streaming, replay, or contiguous time windows or sequences), rather
than as independently shuffled records?

**Q3 Class-time separation.** In the evaluation data as used, does one class
predominantly precede the other within a stream, or are the classes drawn from
disjoint time segments: a benign-only day or capture, a pre-infection prefix,
attack-only capture files, or separate benign and attack captures concatenated
or evaluated as streams? A structural fact about the dataset counts only if the
paper's use of the data preserves it.

**Q4 Warm-up handling** (only if Q1 is YES). Does the paper state that windows
or sequences whose lookback is not fully populated, at the start of each stream,
file or segment, are discarded, pre-filled with representative traffic, or
otherwise handled? HANDLED, NOT STATED, or NA.

**Q5 State scope** (exploratory; only if Q1 is YES and more than one capture or
file is evaluated). Does the paper state that aggregation state is reset or
scoped per capture? STATED, NOT STATED, or NA.

## 5. Outcome
    EXPOSED       Q1 YES, Q2 YES, Q3 YES, and Q4 NOT STATED
    MITIGATED     Q1 YES, Q2 YES, Q3 YES, and Q4 HANDLED
    NOT EXPOSED   any of Q1, Q2, Q3 is NO
    UNASSESSABLE  none of Q1 to Q3 is NO, and at least one is UNSTATED

EXPOSED means the reported comparison is open to the confound and the paper
gives a reader no means to rule it out. It does not mean the result is wrong.
All four counts are reported, by dataset and in total, with every paper's codes
and quotations in `TEMPORAL_SCREEN_CODES.tsv`.

## 6. Coding procedure
Two coders read each paper independently and blind to each other's codes. A
disagreement on Q1 to Q4 goes to a third coder who reads only the two cited
passages and the paper's method section, and records the resolution and reason.
Cohen's kappa is reported for Q1, Q2 and Q3 before resolution.

The three coders are instances of a language model (Claude), each given only
this protocol and the paper's text. Every paper coded EXPOSED or MITIGATED, and
a random 20% of the rest (seeded with 20261014), is then checked against the
paper by the first author, and the number of codes he changed is reported.

## 7. Disclosure
The first author read these papers for the earlier screens, which recorded
class counts, confusion matrices and sweeps; temporal design was not coded then.
Before this protocol was written, one abstract page in the sample
(arXiv 2604.04952) was retrieved to test access; only its title was read.

## 8. Amendments
Any change after the lock is appended below with a timestamp and a reason. No
amendment after the first paper is coded may change a question or the outcome
rule; such a change would require a new protocol and a new sample.
