To start a pcap replay 

First unzip the pcap you want

Then zeek -r the pcap
example:
zeek -r 2025-12-28-ten-days-of-scans-and-probes-and-web-traffic-hitting-my-web-server.pcap \
  Log::default_logdir=zeek_logs/2025-12-28-ten-days-of-scans-and-probes-and-web-traffic-hitting-my-web-server

This will create the needed files and put them where they need to be.

Then navigate to 
pcaps/zeek_logs/scripts

run
python3 replay_pcap_events.py

This now streams the pcaps to the ingestion endpoint

###############################################################################################################


###############################################################################################################


###############################################################################################################


###############################################################################################################


###############################################################################################################



zeek -r 2018-04-03_win12.pcap \
  Log::default_logdir=zeek_logs/2018-04-03_win12






Add pcaps to pcap folder you can run the code below in the terminal 
it will zeek each pcap and add the needed files to their respective folders in the zeek_logs folder
  for f in *.pcap; do
  name=$(basename "$f" .pcap)
  mkdir -p zeek_logs/$name
  zeek -r "$f" -C \
    -e 'redef LogAscii::use_json = T;' \
    -e 'redef LogAscii::json_timestamps = JSON::TS_ISO8601;' \
    -e 'redef Log::default_logdir = "zeek_logs/'"$name"'";'
done


To start the experiment run this in the terminal:
ATTACK_START_RAW_TS=1970-01-01T01:04:33.86657Z node run_full_experiment.js

Update this to the start date for whatever pcap you are working with:
ATTACK_START_RAW_TS=1970-01-01T01:04:33.86657Z

capinfos 2017-12-18_win2.pcap | egrep -i "First packet time|Last packet time|Capture duration"

capinfos 2017-12-18_win2ccleaner_320-1.pcap | egrep -i "First packet time|Last packet time|Capture duration"

Days:Hours:Mins -> S

2017-06-24_win6trickbot_267-1
Duration: 11 days 01:25:02
Tue Jun 13 20:07:16 CEST 2017
started win6
Tue Jun 13 20:13:07 CEST 2017
infected
Sat Jun 24 21:34:26 CEST 2017
power off
ATTACK_START_RAW_TS=1970-01-01T00:07:05.926353Z node run_full_experiment.js
5400s


2017-06-24_win10emotet_271-1
Duration: 16 days 02:02:37
Thu Jun 8 20:46:14 CEST 2017
started win9
Thu Jun 8 20:53:24 CEST 2017
infected
Sat Jun 24 22:49:20 CEST 2017
power off
5400s
ATTACK_START_RAW_TS=1970-01-01T00:07:10Z node run_full_experiment.js


2017-07-03_capture-win13mitm_281-1
Mon Jul 3 18:27:05 CEST 2017
started win13
Mon Jul 3 18:31:28 CEST 2017
infected
Mon Jul 3 18:33:02 CEST 2017
I opened the IE without any page.
Mon Jul 3 18:35:31 CEST 2017
https://www.us.hsbc.com
Mon Jul 3 18:43:03 CEST 2017
power off
ATTACK_START_RAW_TS=1970-01-01T00:04:23Z node run_full_experiment.js
958s


2017-07-11_capture-win2wannacryfailed_283-1
Tue Jul 11 09:01:37 CEST 2017
started win2
Tue Jul 11 09:06:05 CEST 2017
infected
Tue Jul 11 09:15:30 CEST 2017
power off
ATTACK_START_RAW_TS=1970-01-01T00:04:28Z node run_full_experiment.js
833s


2017-07-11_capture-win2wannacrysuccessful_284-1
Tue Jul 11 15:30:17 CEST 2017
started win2
The hostsnames www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com and www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com were redirected to 127.0.0.1 in the hosts file of the windows computer.
Tue Jul 11 15:37:16 CEST 2017
infected
The files in this computer were not encrypted.
Some seconds after finding the other Win 7 computer in the network with IP 192.168.1.135, it infected it. After this, the IP 192.168.1.135 started to scan and attack on port 445/tcp.
However, the files in the computer 192.168.1.135 were not encrypted.
Tue Jul 11 15:46:47 CEST 2017
power off
ATTACK_START_RAW_TS=1970-01-01T00:06:59Z node run_full_experiment.js
990s


2017-07-13_capture-win2NotPeya_298-1
Thu Jul 13 17:30:13 CEST 2017
started win2
Thu Jul 13 17:37:09 CEST 2017
infected
ATTACK_START_RAW_TS=1970-01-01T00:06:56Z node run_full_experiment.js
416s


2017-12-18_win2ccleaner_320-1
Fri Sep 22 17:46:49 CEST 2017
started win2
Fri Sep 22 17:48:26 CEST 2017
infected
Mon Dec 18 14:50:22 CET 2017
power off
ATTACK_START_RAW_TS=1970-01-01T00:01:37Z node run_full_experiment.js
5400s


2018-04-03_win6_ramnit343-1
Tue Feb 20 22:28:00 CET 2018
started win6
Tue Feb 20 22:32:55 CET 2018
Date of last Last packet in tcpdump before infection (1970/01/01 01:04:46.988037)
infected
Wed Feb 21 06:37:21 CET 2018
power off
ATTACK_START_RAW_TS=1970-01-01T01:04:46Z node run_full_experiment.js
5400s


2018-04-03_win11cobalt_345-1
Thu Mar 1 18:25:05 CET 2018
started win11
Thu Mar 1 18:29:12 CET 2018
Date of last Last packet in tcpdump before infection (1970/01/01 01:03:38.616650)
infected
Wed Mar 28 10:09:40 CET 2018
power off
ATTACK_START_RAW_TS=1970-01-01T01:03:38Z node run_full_experiment.js
5400s

2018-04-03_win12
Thu Mar 1 18:50:23 CET 2018
started win12
Thu Mar 1 18:55:08 CET 2018
Date of last Last packet in tcpdump before infection (1970/01/01 01:04:33.86657)
infected
Wed Mar 28 10:09:55 CET 2018
power off
ATTACK_START_RAW_TS=1970-01-01T01:04:33.86657Z node run_full_experiment.js
5400s


so im good regardiong pcaps we can now start looking at the risk and port mapping just to esnure our system can really detect anything right ?



needed to extend out and threast classificatuon needed a bieeter risk score 

“Using only connection-level telemetry, volumetric signals dominated and C2 was not inferred. Multi-log enrichment is required for command-and-control behavioral detection.


→ TS=1970-01-02T04:58:50.763554Z SRC=192.168.1.116 SPT=51303 DST=36.66.107.162 DPT=443 PROTO=TCP BYTES=3300
→ TS=1970-01-02T05:00:58.241973Z SRC=192.168.1.116 SPT=51304 DST=36.66.107.162 DPT=443 PROTO=TCP BYTES=3332
→ TS=1970-01-02T05:03:05.534406Z SRC=192.168.1.116 SPT=51305 DST=168.194.80.70 DPT=443 PROTO=TCP BYTES=3300
→ TS=1970-01-02T05:03:07.067705Z SRC=192.168.1.116 SPT=51306 DST=168.194.80.70 DPT=443 PROTO=TCP BYTES=3332
→ TS=1970-01-02T05:03:07.432956Z SRC=192.168.1.116 SPT=51307 DST=186.208.102.185 DPT=443 PROTO=TCP BYTES=3302
→ TS=1970-01-02T05:03:07.968319Z SRC=192.168.1.116 SPT=51308 DST=186.208.102.185 DPT=443 PROTO=TCP BYTES=3334
→ TS=1970-01-02T05:03:08.320111Z SRC=192.168.1.116 SPT=51309 DST=115.186.139.104 DPT=443 PROTO=TCP BYTES=3302
→ TS=1970-01-02T05:05:15.802823Z SRC=192.168.1.116 SPT=51310 DST=115.186.139.104 DPT=443 PROTO=TCP BYTES=3334
→ TS=1970-01-02T05:07:23.072349Z SRC=192.168.1.116 SPT=51311 DST=217.31.110.43 DPT=443 PROTO=TCP BYTES=3300
→ TS=1970-01-02T05:07:24.357412Z SRC=192.168.1.116 SPT=51312 DST=217.31.110.43 DPT=443 PROTO=TCP BYTES=3332
→ TS=1970-01-02T05:07:24.443097Z SRC=192.168.1.116 SPT=51313 DST=184.160.113.13 DPT=443 PROTO=TCP BYTES=3301
→ TS=1970-01-02T05:09:31.910806Z SRC=192.168.1.116 SPT=51314 DST=184.160.113.13 DPT=443 PROTO=TCP BYTES=3333
→ TS=1970-01-02T05:11:39.232540Z SRC=192.168.1.116 SPT=51315 DST=84.42.159.138 DPT=443 PROTO=TCP BYTES=3300
→ TS=1970-01-02T05:13:46.757274Z SRC=192.168.1.116 SPT=51316 DST=84.42.159.138 DPT=443 PROTO=TCP BYTES=3332
→ TS=1970-01-02T05:15:54.047783Z SRC=192.168.1.116 SPT=51317 DST=82.146.94.150 DPT=443 PROTO=TCP BYTES=3300
→ TS=1970-01-02T05:18:01.473581Z SRC=192.168.1.116 SPT=51318 DST=82.146.94.150 DPT=443 PROTO=TCP BYTES=3332
→ TS=1970-01-02T05:19:05.099094Z SRC=192.168.1.116 SPT=51319 DST=82.146.94.86 DPT=443 PROTO=TCP BYTES=3283
→ TS=1970-01-02T05:19:07.348064Z SRC=192.168.1.116 SPT=51320 DST=82.146.94.86 DPT=443 PROTO=TCP BYTES=3315
→ TS=1970-01-02T05:19:13.219265Z SRC=192.168.1.116 SPT=51321 DST=186.208.106.234 DPT=443 PROTO=TCP BYTES=3302
→ TS=1970-01-02T05:19:14.808675Z SRC=192.168.1.116 SPT=51322 DST=186.208.106.234 DPT=443 PROTO=TCP BYTES=3334
→ TS=1970-01-02T05:19:15.197687Z SRC=192.168.1.116 SPT=51323 DST=96.9.69.131 DPT=443 PROTO=TCP BYTES=3261

[2026-02-15T19:33:25.395Z] phase=injection | window=5m
Prediction: Attack | Truth: Attack
Risk: 90 | State: critical

--- Attack Volume ---
5m=450 | 15m=1348 | 1h=2121 | burstRatio5mOverHour=0.212

--- Attack Type Scores (0..100) ---
dos=96.2 | scan=84.59158023645293 | brute_force=70 | web_probe=70 | c2=0 | impact=0

Dominant: dos (96.2)

--- Risk Components ---
volume=60 | severity=0 | behavior=25 | couplingBonus=5

--- Scanning Indicators ---
authPortPressure=196447 | webPortPressure=370693 | sourceEntropy=0 | portEntropy=3.0739475295566154





------


