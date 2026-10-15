# Coder instructions (identical for coders A and B)

You are coding published papers under a locked protocol. Read
/home/claude/chiron/screen/TEMPORAL_SCREEN_PROTOCOL.md first and follow it exactly.

Rules
- Read ONLY: the protocol, these instructions, your assigned batch file, and the text files named in it under /home/claude/chiron/screen/pdf/. Do not
  open, list or search anything else under /home/claude/chiron. Write ONLY your
  assigned output file.
- Access each paper by reading its full text at /home/claude/chiron/screen/pdf/<arxiv_id>.txt (read only the file for the paper you are coding). Do NOT use WebFetch. Ignore the remaining access steps below that refer to fetching;
  text: https://arxiv.org/html/<id> , https://arxiv.org/pdf/<id> ,
  https://arxiv.org/abs/<id> (abstract only; enough only to record status).
  Use 2-4 fetches per paper. Ask the fetch tool to return VERBATIM passages about:
  datasets used and how; feature extraction (any time windows, sliding/tumbling
  windows, per-host or per-connection rates or counts over intervals, sequence or
  temporal models, graph snapshots over intervals); how evaluation data is split
  and ordered (random shuffle vs time order, by day/file/capture); whether benign
  and attack data come from different days/files/time segments; any handling of
  windows or sequences at the start of a stream or file (discarding, padding,
  warm-up); and the result reported in the abstract.
- Code only what the returned text states. If it is not stated, the answer is
  UNSTATED. Do not use your own knowledge of a dataset's structure unless the
  paper's own text describes using the data in a way that preserves it.
- Every YES, NO, HANDLED or STATED needs a location (section name or number, or
  page) and a quotation of at most 25 words copied from the returned text.
- Apply the outcome rule of protocol section 5 mechanically.

Output: a TSV with this exact header and one row per paper in your batch:
arxiv_id	status	dataset_coded	primary_evaluation	Q1	Q1_lookback	Q1_location	Q1_quote	Q2	Q2_location	Q2_quote	Q3	Q3_location	Q3_quote	Q4	Q4_location	Q4_quote	Q5	outcome	notes
- status: CODED, NOT_RETRIEVED, or NOT_DETECTION_EVAL
- Q1, Q2, Q3: YES / NO / UNSTATED. Q4: HANDLED / NOT_STATED / NA. Q5: STATED / NOT_STATED / NA
- outcome: EXPOSED / MITIGATED / NOT_EXPOSED / UNASSESSABLE (blank if not CODED)
- No tab or newline characters inside any field. Use "-" for empty fields.
When finished, reply with one line per paper: id, status, outcome.
