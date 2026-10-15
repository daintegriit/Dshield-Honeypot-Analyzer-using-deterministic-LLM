# Amendments to TEMPORAL_SCREEN_PROTOCOL.md
The protocol was locked by commit a1b5bc5 (2026-10-14T20:48:06-04:00).

## A1 -- 2026-10-14T20:51-04:00, before any paper was coded
Access route. The coding environment cannot download files from arXiv directly.
Coders read each paper through a web-fetch tool that returns the passages a
coder requests from the paper's abstract page, HTML rendering or PDF, rather
than the raw document. Each coder requests the dataset, feature, windowing,
split, ordering and evaluation passages, and quotes only from what the tool
returns. A paper whose text the tool cannot return is recorded as not retrieved
(protocol section 2). No question, code or outcome rule is changed.

Batching. The 79 papers are coded in ten batches of seven or eight, in sample
order. Coders A and B each code every batch, in separate sessions that cannot
see each other's output; coder C sees only the two cited passages and the
method section for each disagreement.

## A2 -- 2026-10-14T20:52-04:00, before any paper was coded
Count correction. Section 2 says four papers appear in two searches, leaving 79
unique. In fact three appear in two searches and one (2604.12655) in three
(CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15), so the 83 results are 78 unique
papers. The sample itself (TEMPORAL_SCREEN_SAMPLE.tsv) is unchanged.
Batching is therefore nine batches of eight and one of six.

## A3 -- 2026-10-14T21:04-04:00, before these papers were coded
Four papers were refused by arXiv's rate limit for both coders. The first author
downloaded them in a browser. 2601.13197 has been withdrawn by its authors (v2 is
a withdrawal notice with no text) and is recorded as NOT_RETRIEVED, reason
withdrawn. For 2605.22529, 2606.18771 and 2607.02687, coders A and B read the full
text extracted from the PDF (pdftotext), in separate sessions, under the same
questions and rules. This is a fuller access route than A1's fetch tool; no
question, code or outcome rule changes.

## A4 -- 2026-10-14T21:10-04:00, before any verification by the first author
The section 6 verification sample must be drawn after coding is complete. A draw
made earlier, over 65 coded papers before the three PDF papers were coded, was
superseded before anyone used it. The sample is the EXPOSED/MITIGATED papers plus
a seeded (20261014) random 20% of the remaining 67 coded papers, drawn once, over
the final codes. Both lists are kept in the record (VERIFY_LIST_superseded.txt,
VERIFY_LIST.txt).
