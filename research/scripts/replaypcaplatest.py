#!/usr/bin/env python3
"""
Zeek Multi-Log PCAP Replay → DShield-style raw ingestion

Replays:
- conn.log
- dns.log
- http.log
- ssl.log

Into existing ingestController (NO backend changes).

Preserves:
- IPv4 only
- Chronological ordering
- Raw string ingestion format
- CSV artifact
"""

from dataclasses import fields
import os
import time
import csv
import uuid
import ipaddress
import requests
from datetime import datetime, timezone

# ---------------- CONFIG ----------------

INGEST_URL = os.environ.get(
    "INGEST_ENDPOINT",
    "http://34.232.64.91:5002/api/ingest/log"
)

INGEST_SHARED_KEY = os.environ.get("INGEST_SHARED_KEY")

PCAP_NAME = "2018-04-03_win6_ramnit343-1"
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ZEEK_BASE = os.path.join(
    BASE_DIR,
    "..",
    "pcaps",
    "zeek_logs",
    PCAP_NAME
)


LOG_FILES = {
    "conn": f"{ZEEK_BASE}/conn.log",
    "dns": f"{ZEEK_BASE}/dns.log",
    "http": f"{ZEEK_BASE}/http.log",
    "ssl": f"{ZEEK_BASE}/ssl.log",
}

OUTPUT_DIR = "../outputs/replays"
TARGET_DURATION_SECONDS = int(os.environ.get("REPLAY_DURATION", 5400))
REPLAY_MODE = os.environ.get("REPLAY_MODE", "normalized").lower()

# TARGET_DURATION_SECONDS = 5400  # 1.5 hours

# ---------------- HELPERS ----------------

def iso_utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")

def zeek_ts_to_iso(ts):
    return datetime.fromtimestamp(float(ts), timezone.utc).isoformat().replace("+00:00", "Z")

def is_ipv4(ip):
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False

# ---------------- RAW BUILDERS ----------------

def build_raw_conn(fields):
    proto = fields[6].lower()
    if proto not in ("tcp", "udp"):
        return None

    src = fields[2]
    dst = fields[4]

    if not is_ipv4(src) or not is_ipv4(dst):
        return None

    try:
        spt = int(fields[3])
        dpt = int(fields[5])
    except:
        return None

    orig_bytes = 0 if fields[9] == "-" else int(fields[9])
    resp_bytes = 0 if fields[10] == "-" else int(fields[10])
    total_bytes = orig_bytes + resp_bytes

    ts = zeek_ts_to_iso(fields[0])

    return (
        f"TS={ts} "
        f"SRC={src} SPT={spt} "
        f"DST={dst} DPT={dpt} "
        f"PROTO={proto.upper()} "
        f"BYTES={total_bytes}"
    )

def build_raw_dns(fields):
    src = fields[2]
    dst = fields[4]

    if not is_ipv4(src) or not is_ipv4(dst):
        return None

    ts = zeek_ts_to_iso(fields[0])
    query = fields[9]
    qtype = fields[11]

    return (
        f"TS={ts} "
        f"SRC={src} DST={dst} "
        f"PROTO=DNS "
        f"QUERY={query} "
        f"QTYPE={qtype}"
    )

def build_raw_http(fields):
    src = fields[2]
    dst = fields[4]

    if not is_ipv4(src) or not is_ipv4(dst):
        return None

    ts = zeek_ts_to_iso(fields[0])
    method = fields[7]
    host = fields[8]
    uri = fields[9]
    status = fields[15]

    return (
        f"TS={ts} "
        f"SRC={src} DST={dst} "
        f"PROTO=HTTP "
        f"METHOD={method} "
        f"HOST={host} "
        f"URI={uri} "
        f"STATUS={status}"
    )

def build_raw_ssl(fields):
    src = fields[2]
    dst = fields[4]

    if not is_ipv4(src) or not is_ipv4(dst):
        return None

    try:
        spt = int(fields[3])
        dpt = int(fields[5])
    except:
        return None

    ts = zeek_ts_to_iso(fields[0])
    version = fields[6]
    server_name = fields[9]

    return (
        f"TS={ts} "
        f"SRC={src} SPT={spt} "
        f"DST={dst} DPT={dpt} "
        f"PROTO=SSL "
        f"SNI={server_name} "
        f"TLS_VERSION={version}"
    )


# ---------------- MAIN ----------------

def main():
    try:
        requests.get(INGEST_URL.replace("/api/ingest/log", ""), timeout=2)
    except Exception:
        print("❌ Ingest service not reachable.")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    run_id = iso_utc_now()
    replay_id = str(uuid.uuid4())[:8]
    csv_path = f"{OUTPUT_DIR}/{run_id}_{replay_id}_{PCAP_NAME}.csv"

    headers = {
        "Authorization": f"Bearer {INGEST_SHARED_KEY}",
        "Content-Type": "application/json",
    }

    print("=== MULTI-LOG ATTACK REPLAY ===")
    print(f"PCAP:   {PCAP_NAME}")
    print(f"Ingest: {INGEST_URL}")
    print("=" * 60)

    events = []

    # ---------------- LOAD ALL LOGS ----------------

    for log_type, path in LOG_FILES.items():
        if not os.path.exists(path):
            continue

        with open(path, "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue

                fields = line.strip().split("\t")

                if log_type == "conn":
                    raw = build_raw_conn(fields)
                elif log_type == "dns":
                    raw = build_raw_dns(fields)
                elif log_type == "http":
                    raw = build_raw_http(fields)
                elif log_type == "ssl":
                    raw = build_raw_ssl(fields)
                else:
                    raw = None

                if not raw:
                    continue

                ts = float(fields[0])
                events.append((ts, raw))

    events.sort(key=lambda x: x[0])

    print("🔥 FINAL EVENTS AFTER FILTER:", len(events))  


    if not events:
        print("❌ No events extracted.")
        return

    num_events = len(events)

    first_ts = events[0][0]
    last_ts = events[-1][0]

    natural_duration = last_ts - first_ts

    if REPLAY_MODE == "natural":

        print("\n🌍 REPLAY MODE: NATURAL")
        print("Natural duration:", natural_duration)

        sleep_between = None

    else:

        print("\n🧪 REPLAY MODE: NORMALIZED")

        sleep_between = TARGET_DURATION_SECONDS / num_events

        print("Target duration:", TARGET_DURATION_SECONDS)
        print("Sleep per event:", sleep_between)

    print("Total events:", num_events)

    with open(csv_path, "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([
            "run_id",
            "pcap",
            "event_index",
            "timestamp",
            "raw"
        ])

        for idx, (ts, raw) in enumerate(events):
            payload = {"raw": raw}

            try:
                r = requests.post(
                    INGEST_URL,
                    headers=headers,
                    json=payload,
                    timeout=30
                )
                if r.status_code not in (200, 201):
                    print("❌ Ingest rejected:", r.text)
            except Exception as e:
                print("❌ Ingest connection error:", e)
                return

            writer.writerow([
                run_id,
                PCAP_NAME,
                idx,
                zeek_ts_to_iso(ts),
                raw
            ])

            print("→", raw, flush=True)
            if REPLAY_MODE == "normalized":

                time.sleep(sleep_between)

            else:

                if idx < len(events) - 1:

                    next_ts = events[idx + 1][0]

                    delta = next_ts - ts

                    if delta > 0:
                        time.sleep(delta)

    print("✅ Replay complete")
    print(f"📁 Artifact written: {csv_path}")

if __name__ == "__main__":
    main()








