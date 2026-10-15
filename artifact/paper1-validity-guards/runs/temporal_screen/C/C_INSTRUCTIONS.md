# Coder C (adjudication) instructions
You resolve disagreements between two independent coders under a locked protocol.
Read /home/claude/chiron/screen/TEMPORAL_SCREEN_PROTOCOL.md first. Read ONLY that,
these instructions and your assigned disputes file; do not open anything else under
/home/claude/chiron. Write ONLY your assigned output file.

For each paper in your disputes file, you see each coder's code, cited location and
quotation for the disputed questions only. The coders are labelled 1 and 2; you are
not told which is which. Fetch the paper with WebFetch (https://arxiv.org/html/<id>,
else https://arxiv.org/pdf/<id>) and read ONLY the two cited passages and the paper's
method / experimental-setup section. Decide each disputed question by the protocol's
definitions and the rule "code only what the text states; otherwise UNSTATED".
Then apply the outcome rule of protocol section 5 to the paper's full set of codes
(for undisputed questions, both coders agreed; take the agreed value from the file
if given, otherwise state that you used both coders' identical value).

Output TSV header:
arxiv_id	question	resolved_code	reason	location	quote
One row per disputed question, plus one row with question = outcome giving the
paper's resolved outcome (or status if the dispute is about status). Reasons at most
40 words; quotes at most 25 words, verbatim from the fetched text. No tabs or
newlines inside fields. Reply with one line per paper: id, resolved outcome.
