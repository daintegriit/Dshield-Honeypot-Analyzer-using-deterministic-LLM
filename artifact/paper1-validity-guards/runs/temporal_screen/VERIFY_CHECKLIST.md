# Verification checklist (protocol section 6; sample drawn over the final codes, amendment A4)

For each paper: open the link, check each code against the definitions in TEMPORAL_SCREEN_PROTOCOL.md section 4, and mark AGREE or CHANGE (with the new code and a one-line reason). Paper 1 is the only EXPOSED paper; papers 2-14 are the seeded random 20% (seed 20261014) of the remaining 67 coded papers.

## 1. 2508.14192v1  (CIC-IDS2017)  outcome: EXPOSED
https://arxiv.org/abs/2508.14192v1
Primary evaluation: Noise-robust one-class CTGN on CIC-IDS2017 dynamic graphs (Tue/Wed/Thu/Fri datasets); abstract: significant improvements over TGN-SVDD, especially as noise increases
- Q1 = YES | Sec. 2 | "which is updated using a learnable memory function (e.g., GRU) after each interaction event."   -> AGREE / CHANGE: ____
- Q2 = YES | Sec. 4 (Noise); Sec. 2 | "where t_test is the timestamp of the first test event, and T is the maximum timestamp in the dataset."   -> AGREE / CHANGE: ____
- Q3 = YES | Sec. 4 (Data set) | "The initial segments contain only normal traffic, with attacks reserved for testing."   -> AGREE / CHANGE: ____
- Q4 = NOT_STATED | - | "-"   -> AGREE / CHANGE: ____

## 2. 2510.09619v1  (CIC-IDS2017+UNSW-NB15)  outcome: UNASSESSABLE
https://arxiv.org/abs/2510.09619v1
Primary evaluation: Bayesian online changepoint streaming detector on streams from UNSW-NB15 and CICIDS2017; abstract: improved precision-recall and well-calibrated probabilities (no numbers)
- Q1 = YES | Sec. 3; Sec. 4 | "We model the stream of feature vectors {x_t} extracted from network flows / Initialise P(r_0 = 0) = 1 and the sufficient statistics for the benign and malicious models."   -> AGREE / CHANGE: ____
- Q2 = YES | Sec. 5 | "Each stream is partitioned chronologically / To mimic a streaming scenario, the detector processes one event at a time and cannot revisit past data."   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NOT_STATED | - | "-"   -> AGREE / CHANGE: ____

## 3. 2602.16098v1  (UNSW-NB15)  outcome: UNASSESSABLE
https://arxiv.org/abs/2602.16098v1
Primary evaluation: ZAID zone-adaptive zero-day detection; cross-domain evaluation on UNSW-NB15 with rare attack categories withheld (Sec IV-G); abstract reports up to 83.16% accuracy on unseen attacks
- Q1 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 4. 2602.17973v2  (CSE-CIC-IDS2018)  outcome: UNASSESSABLE
https://arxiv.org/abs/2602.17973v2
Primary evaluation: Federated IDS (PenTiDef) accuracy/F1 vs FLARE and FedCC on Edge-IIoTSet and CIC-IDS2018
- Q1 = UNSTATED | Sec. 6.4 | "71 features and a label column after preprocessing" (adjudicated: Paper gives only a feature count; it does not name the features, say they are per-flow statistics, or describe any temporal aggregation. Per-flow nature would be inferred from the dataset, not stated.)   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 5. 2603.17717v4  (UNSW-NB15)  outcome: NOT_EXPOSED
https://arxiv.org/abs/2603.17717v4
Primary evaluation: Attack classification on under-sampled UMNIDS unified dataset (reprocessed CIC-IDS-2017, CIC-IoT-2023, UNSW-NB15, CIC-DDoS) with stratified 80/20 split; XGBoost test F1 96.33%
- Q1 = YES | Sec II-A | "features that capture historical and temporal patterns in network traffic"   -> AGREE / CHANGE: ____
- Q2 = NO | Sec II-B | "after we performed an 80/20 train/test stratified split, with respect to the attack type variable"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NOT_STATED | - | "-"   -> AGREE / CHANGE: ____

## 6. 2604.14663v1  (CIC-IDS2017)  outcome: NOT_EXPOSED
https://arxiv.org/abs/2604.14663v1
Primary evaluation: EdgeDetect federated MLP on CIC-IDS2017; 98.0% multi-class accuracy, 97.9% macro F1
- Q1 = UNSTATED | Sec. IV.B | "Flow inter-arrival time statistics were computed as" (adjudicated: Eq. 7 gives IAT mean/std over n timestamps but never states whether these span packets within one flow or multiple flows; no windows described. Scope not stated, so neither YES nor NO.)   -> AGREE / CHANGE: ____
- Q2 = NO | Sec. V.A | "An 80:20 stratified split (seed 42) was applied." (adjudicated: A seeded stratified 80:20 split samples records per class at random, i.e. independently shuffled records; no streaming, replay or contiguous windows are described.)   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 7. 2605.06629v1  (UNSW-NB15)  outcome: UNASSESSABLE
https://arxiv.org/abs/2605.06629v1
Primary evaluation: IDS evasion test: RF/XGBoost/CNN1D on generated attack flows paired with real benign flows (abstract gives no numeric result)
- Q1 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | Sec. 3.4 | "Then each classifier was evaluated on 8,000 generated attack flows paired with 8,000 real benign flows" (adjudicated: Pairing generated attack flows with real benign flows says nothing about presentation order; the paper does not state shuffling, random sampling or time order for the evaluation records.)   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 8. 2605.07536v1  (CTU-13)  outcome: UNASSESSABLE
https://arxiv.org/abs/2605.07536v1
Primary evaluation: GESR benign-only graph anomaly detection over 30 s window snapshots on CTU-13 (Table 2 ROC-AUC 0.9804; abstract reports CICIDS2017 ROC-AUC 0.9753)
- Q1 = YES | Sec 3.2 Graph Construction | "traffic is partitioned into fixed time windows to construct a sequence of communication graphs. The window size is set to 30 seconds for CTU-13"   -> AGREE / CHANGE: ____
- Q2 = YES | Sec 4.1 Experimental Setup | "Benign graph snapshots are ordered chronologically. ... All baselines use the same chronological split"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NOT_STATED | - | "-"   -> AGREE / CHANGE: ____

## 9. 2605.23004v2  (CTU-13)  outcome: NOT_EXPOSED
https://arxiv.org/abs/2605.23004v2
Primary evaluation: Lightweight ML (Random Forest) botnet flow classification on CTU-13 (abstract: PR-AUC ~0.54, ROC-AUC 0.97)
- Q1 = NO | Sec 3.2 | "we use: total bytes and packets (log-transformed), bytes-per-packet ratio, flow duration, and protocol and port indicators"   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 10. 2605.27299v1  (CIC-IDS2017)  outcome: NOT_EXPOSED
https://arxiv.org/abs/2605.27299v1
Primary evaluation: Risk-averse alert prioritization on CIC-IDS2017 detector outputs; NDCG_rel@100 0.9963 vs 0.8215 baseline under detector degradation
- Q1 = NO | Sec. 4.1 | "covers 78 network flow features (source/destination IP, ports, protocol, packet statistics, etc.)"   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | Sec. 4.1 | "Sort day files by weekday. If the day-based train split (Mon/Tue) has at least 5% attacks, use Mon/Tue for training, Wed for validation, Thu/Fri for test."   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 11. 2606.29797v2  (UNSW-NB15)  outcome: NOT_EXPOSED
https://arxiv.org/abs/2606.29797v2
Primary evaluation: Multi-level distributional entropy features from flow summaries; abstract: CICIDS-2018 F1 0.73 hides DR 0.44; coded on UNSW-NB15 200K stratified sample
- Q1 = NO | Sec 4 | "computes entropy analytically from the statistical summaries already present in pre-aggregated flow records"   -> AGREE / CHANGE: ____
- Q2 = NO | Sec 5.2 | "Both are trained under stratified 5-fold crossvalidation"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 12. 2608.24454v1  (CTU-13)  outcome: UNASSESSABLE
https://arxiv.org/abs/2608.24454v1
Primary evaluation: Hardened GNN flow-graph NIDS under structural adversarial attacks, CTU-13 by botnet family (abstract: superior clean detection and robustness)
- Q1 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 13. 2609.16363v1  (UNSW-NB15)  outcome: NOT_EXPOSED
https://arxiv.org/abs/2609.16363v1
Primary evaluation: Flow-based FPGA IDS on reconstructed UNSW-NB15 packet traces (accuracy 86.92% to 97.68%)
- Q1 = NO | Sec. II.C | "The aggregated feature vectors corresponding to the latest eight packets from the flow are forwarded to the intrusion detection engine."   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 14. 2609.39584v1  (UNSW-NB15)  outcome: UNASSESSABLE
https://arxiv.org/abs/2609.39584v1
Primary evaluation: Trust-aware federated CNN-BiLSTM IDS on UNSW-NB15, CICIDS2017, Edge-IIoTset; abstract: superior detection accuracy, rapid convergence, Byzantine tolerance (no numbers; 94% in Sec. V.C)
- Q1 = YES | Sec. III.A; Sec. IV.B | "static 2D tabular data is reshaped into 3D sequential tensors (Samples × Timesteps × Features) using overlapping sliding windows" (adjudicated: Method states records are reshaped into Samples x Timesteps x Features tensors via overlapping sliding windows for a BiLSTM: a sequence model over consecutive records. Lookback length not stated.)   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NOT_STATED | - | "-" (adjudicated: Q1 is YES; the paper does not describe handling of windows at the start of a stream (no discarding, padding or pre-fill stated).)   -> AGREE / CHANGE: ____
