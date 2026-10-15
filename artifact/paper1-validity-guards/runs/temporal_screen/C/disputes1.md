## 2604.14663v1
Dataset coded: A=CIC-IDS2017 | B=CIC-IDS2017
Disputed: Q1, Q2
- Q1, Coder 1: NO | location: Sec. IV.B / IV.F | quote: Flow inter-arrival time statistics were computed as
- Q1, Coder 2: UNSTATED | location: Sec. IV.B | quote: Flow inter-arrival time statistics were computed as
- Q2, Coder 1: UNSTATED | location: Sec. V.A | quote: An 80:20 stratified split (seed 42) was applied.
- Q2, Coder 2: NO | location: Sec. V.A | quote: An 80:20 stratified split (seed 42) was applied.
Agreed by both coders: Q3=UNSTATED, Q4=NA, Q5=NA

## 2607.07739v1
Dataset coded: A=UNSW-NB15 | B=UNSW-NB15
Disputed: Q1, Q4
- Q1, Coder 1: YES | location: Sec III-A, Definition 1 | quote: Indirectly Controllable (IC): Aggregated statistics over multiple flows that the attacker can influence through sustained behavioral changes
- Q1, Coder 2: UNSTATED | location: Sec IV-A | quote: -
- Q4, Coder 1: NOT_STATED | location: - | quote: -
- Q4, Coder 2: NA | location: - | quote: -
Agreed by both coders: Q2=NO, Q3=UNSTATED, Q5=NA

## 2605.08910v1
Dataset coded: A=UNSW-NB15 | B=UNSW-NB15
Disputed: Q2
- Q2, Coder 1: NO | location: Sec 6.1 | quote: with a stratified 70-30 train-test split
- Q2, Coder 2: UNSTATED | location: - | quote: -
Agreed by both coders: Q1=UNSTATED, Q3=UNSTATED, Q4=NA, Q5=NA

## 2510.17883v2
Dataset coded: A=UNSW-NB15 | B=UNSW-NB15
Disputed: Q1
- Q1, Coder 1: UNSTATED | location: - | quote: -
- Q1, Coder 2: NO | location: Sec 3.3; Sec 4.2 | quote: we render each row to text and rely on instruction following ... Each flow was rendered to a short natural language record
Agreed by both coders: Q2=UNSTATED, Q3=UNSTATED, Q4=NA, Q5=NA

## 2607.16276v1
Dataset coded: A=CSE-CIC-IDS2018 | B=CSE-CIC-IDS2018
Disputed: status, Q1, Q2, Q3, Q4
- status, Coder 1: NOT_DETECTION_EVAL | notes: Builds a benign-to-SSDP time-binned trace from CSE-CIC-IDS2018 and fits anomaly model to benign traffic, but reports no detection metrics (only qualitative: IDS score rises near attack transition, Fig 5). Abstract result is quantum-network delivery, not detection. Borderline: if treated as detection eval, time bins (Sec III.B) and benign-then-attack trace would suggest Q1/Q2/Q3 YES, Q4 NOT_STATED.
- status, Coder 2: CODED | notes: Borderline status: no classification metrics; abstract result is controller delivery driven by the IDS score, coded as the detection-dependent primary evaluation. Q1 borderline: score is per time bin (tumbling), but whether model input aggregates flows or per-flow scores are averaged is not stated; model and features unnamed. Model fit on benign traffic, then applied to the trace; attack period = bins with oracle rate > 0.5. Q1 quote joins two adjacent sentences.
- Q1, Coder 1: - | location: - | quote: -
- Q1, Coder 2: YES | location: Sec. III.B | quote: The flow table was divided into consecutive time bins. ... In each bin, we computed two cyber quantities.
- Q2, Coder 1: - | location: - | quote: -
- Q2, Coder 2: YES | location: Sec. III.B | quote: The trace begins in a benign regime, transitions into an SSDP attack regime
- Q3, Coder 1: - | location: - | quote: -
- Q3, Coder 2: YES | location: Sec. III.B | quote: The trace begins in a benign regime, transitions into an SSDP attack regime
- Q4, Coder 1: - | location: - | quote: -
- Q4, Coder 2: NOT_STATED | location: - | quote: -
Agreed by both coders: none

## 2502.06031v1
Dataset coded: A=CSE-CIC-IDS2018 | B=CSE-CIC-IDS2018
Disputed: Q3
- Q3, Coder 1: YES | location: Sec. III.A, Table I | quote: Friday-16-02-2018 TrafficForML CICFlowMeter.csv
- Q3, Coder 2: UNSTATED | location: - | quote: -
Agreed by both coders: Q1=NO, Q2=UNSTATED, Q4=NA, Q5=NA
