# Held-out corpus registration
Date: 2026-08-09

Development (may be scored, tuned against, inspected freely):
  CTU-Mixed-Capture-1
  CTU-13 scenarios 1, 2, 6, 8, 9            [used in first paper]
  Stratosphere malware captures, 10          [used in first paper]
  CTU-Normal captures                        [benign; false-positive testing]

Held out (not scored until the detector is final):
  CTU-Mixed-Capture-6, 7, 8, 9-1, 9-2
  CTU-13 scenarios not listed above

Only READMEs have been read for the held-out set, to establish label structure.
No traffic has been examined and no capture downloaded.

Rationale: every corpus used in the first paper was also used during
development, stated there as the most significant limitation of the detection
findings. This split is declared before any held-out capture is fetched.
