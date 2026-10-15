# Verification checklist (protocol section 6)

For each paper: open the link, check each code against the definitions in TEMPORAL_SCREEN_PROTOCOL.md section 4, and mark AGREE or CHANGE (with the new code and a one-line reason). Paper 1 is the only EXPOSED paper; papers 2-14 are the seeded random 20% (seed 20261014) of the rest.

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

## 3. 2602.17973v2  (CSE-CIC-IDS2018)  outcome: UNASSESSABLE
https://arxiv.org/abs/2602.17973v2
Primary evaluation: Federated IDS (PenTiDef) accuracy/F1 vs FLARE and FedCC on Edge-IIoTSet and CIC-IDS2018
- Q1 = UNSTATED | Sec. 6.4 | "71 features and a label column after preprocessing" (adjudicated: Paper gives only a feature count; it does not name the features, say they are per-flow statistics, or describe any temporal aggregation. Per-flow nature would be inferred from the dataset, not stated.)   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 4. 2603.10413v1  (UNSW-NB15)  outcome: UNASSESSABLE
https://arxiv.org/abs/2603.10413v1
Primary evaluation: Multi-layer ensemble (autoencoder + classifiers) adversarial-robust NIDS on UNSW-NB15 (abstract names UNSW-NB15 first; no numeric result in abstract)
- Q1 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
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

## 6. 2605.04407v1  (UNSW-NB15)  outcome: UNASSESSABLE
https://arxiv.org/abs/2605.04407v1
Primary evaluation: Same-dataset 70/30 evaluation of ML models on UNSW-NB15 (RF 95.08% accuracy), plus cross-dataset to TON_IoT
- Q1 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 7. 2605.05644v1  (CIC-IDS2017)  outcome: NOT_EXPOSED
https://arxiv.org/abs/2605.05644v1
Primary evaluation: AoI-guided client selection for federated IDS; AoI reduced ~39-41%, Macro-F1/AUC usually preserved (CIC-IDS2017 Friday DDoS+PortScan subset among datasets)
- Q1 = NO | Experimental Setup (model description) | "lightweight softmax classifier"   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | Experimental Setup | "Training data are partitioned non-IID using a Dirichlet split (alpha=0.3)"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | Experimental Setup, Datasets | "We evaluate on CIC-IDS2017 flows (Friday DDoS + PortScan mini subset)"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 8. 2605.06629v1  (UNSW-NB15)  outcome: UNASSESSABLE
https://arxiv.org/abs/2605.06629v1
Primary evaluation: IDS evasion test: RF/XGBoost/CNN1D on generated attack flows paired with real benign flows (abstract gives no numeric result)
- Q1 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | Sec. 3.4 | "Then each classifier was evaluated on 8,000 generated attack flows paired with 8,000 real benign flows" (adjudicated: Pairing generated attack flows with real benign flows says nothing about presentation order; the paper does not state shuffling, random sampling or time order for the evaluation records.)   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 9. 2605.18647v1  (CIC-IDS2017+UNSW-NB15)  outcome: NOT_EXPOSED
https://arxiv.org/abs/2605.18647v1
Primary evaluation: Federated Naive Bayes with ICC regularization; F1-macro on NSL-KDD, CIC-IDS2017 (0.7556 vs 0.6771), UNSW-NB15
- Q1 = NO | Sec. III.C | "Numerical flow statistics are handled by GaussianNB after StandardScaler normalization."   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | Table III | "Train / Val / Test | 60% / 20% / 20%"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | Sec. IV.A | "Eight Parquet files, binarized (BENIGN=0, any attack=1), proportionally subsampled."   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 10. 2605.26166v1  (UNSW-NB15)  outcome: UNASSESSABLE
https://arxiv.org/abs/2605.26166v1
Primary evaluation: XGBoost-BalSamp / online pseudo-labelling classification on UNSW-NB15; 95.45% accuracy
- Q1 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 11. 2606.05714v1  (CSE-CIC-IDS2018)  outcome: NOT_EXPOSED
https://arxiv.org/abs/2606.05714v1
Primary evaluation: Hybrid CNN-LSTM on CSE-CIC-IDS2018 (Kaggle mirror): 99.1% accuracy, ~99.0% precision and recall, FPR ~2.0%
- Q1 = NO | Sec 3.5 (LSTM) | "Individual network flows were treated as sequences of 10 timesteps, with each timestep corresponding to a subset of engineered features."   -> AGREE / CHANGE: ____
- Q2 = NO | Sec 3.3 | "partitioned into 80% training and 20% testing subsets using stratified random sampling."   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 12. 2607.00763v1  (UNSW-NB15)  outcome: UNASSESSABLE
https://arxiv.org/abs/2607.00763v1
Primary evaluation: Train-on-synthetic test-on-real detection; abstract reports CICIDS2017 F1-macro 0.96; UNSW-NB15 used as cross-dataset validation
- Q1 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q2 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q3 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
- Q4 = NA | - | "-"   -> AGREE / CHANGE: ____

## 13. 2607.13203v2  (UNSW-NB15)  outcome: UNASSESSABLE
https://arxiv.org/abs/2607.13203v2
Primary evaluation: BARS feature selection for false-alarm reduction; UNSW-NB15 FPR reduced 15.4% vs CMD at k=20 (abstract: up to 32% fewer false alarms)
- Q1 = UNSTATED | - | "-"   -> AGREE / CHANGE: ____
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
