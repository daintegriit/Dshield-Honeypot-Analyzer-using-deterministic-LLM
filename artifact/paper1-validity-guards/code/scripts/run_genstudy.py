#!/usr/bin/env python3
"""Generalization study (protocol locked 2026-10-08 17:15:25 UTC).
Applies check_published_matrix.py, unmodified, to every included result.
Values transcribed from the papers; UNVERIFIED against PDFs until marked."""
import sys, os
sys.path.insert(0, os.path.expanduser('~/research/scripts'))
from check_published_matrix import Evaluation, report

E = [
 Evaluation("UNSW-NB15 | 2609.24393 | RF-41 hold-out, binary (Table II, Sec III)",
            class_counts={"Attack": 63974, "Normal": 444065},
            tp=62305, fp=2005, tn=442060, fn=1669),
 Evaluation("UNSW-NB15 | 2605.26166 | XGBoost-BalSamp, binary (Fig. 4 caption, Sec 8.2)",
            class_counts={"Attack": 32935},
            tp=31617, fp=1040, tn=17560, fn=1318),
 Evaluation("UNSW-NB15 | 2605.26166 | PseudoFilter+MixupAug+LiteAE best run (Fig. 5 caption)",
            fp=3, fn=19705),
 Evaluation("UNSW-NB15 | 2605.05275 | per-class F1, test set (Table I)",
            class_counts={"Normal": 37000, "DoS": 4089, "Reconnaissance": 3496,
                          "Shellcode": 378, "Worms": 44}),
 Evaluation("UNSW-NB15 | 2603.28838 | per-class F1, test set (Table I)",
            class_counts={"Normal": 37000, "DoS": 4089, "Reconnaissance": 3496,
                          "Shellcode": 378, "Worms": 44}),
 Evaluation("CTU-13 | 2604.04952 | ML Defender, Neris held-out (Table 3, Sec 8.13)",
            class_counts={"Malicious": 646, "Benign": 12077},
            tp=646, fp=2, tn=12075, fn=0),
 Evaluation("CTU-13 | 2604.04952 | Suricata ET Open, Neris (Table 12)",
            class_counts={"Malicious": 646, "Benign": 12077},
            tp=0, fp=0, fn=646),
 Evaluation("CTU-13 | 2604.04952 | Zeek default scripts, Neris (Sec 8.14)",
            class_counts={"Malicious": 646, "Benign": 12077},
            tp=14, fp=0, fn=632),
 Evaluation("CSE-CIC-IDS2018 | 2608.11291 | DQN, per-class, split unstated (Table V)",
            class_counts={"Benign": 1935399, "Botnet": 28907, "Brute-force": 18820,
                          "DDoS": 155191, "DoS": 39314, "Web attack": 173}),
 Evaluation("CSE-CIC-IDS2018 | 2606.05714 | 'representative sample', binary (Fig. 9 caption)",
            tp=4, fp=1, tn=3, fn=0),
]
for ev in E:
    report(ev)
