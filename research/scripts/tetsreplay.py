#!/usr/bin/env python3

import os
import time
import csv
import uuid
import ipaddress
import requests
from datetime import datetime, timezone, timedelta

# ---------------- CONFIG ----------------

INGEST_URL = os.environ.get(
    "INGEST_ENDPOINT",
    "http://34.232.64.91:5002/api/ingest/log"
)

INGEST_SHARED_KEY = os.environ.get("INGEST_SHARED_KEY")
PCAP_NAME = os.environ.get("PCAP_NAME", "default_pcap")

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

OUTPUT_DIR = os.path.join(BASE_DIR, "..", "outputs", "replays", PCAP_NAME)
TARGET_DURATION_SECONDS = int(os.environ.get("TARGET_DURATION_SECONDS", "5400"))

# ---------------- TIME ANCHOR ----------------

BASE_TIME = datetime.now(timezone.utc)

def zeek_ts_to_iso(ts):
    return (BASE_TIME + timedelta(seconds=float(ts))) \
        .isoformat() \
        .replace("+00:00", "Z")

# ---------------- HELPERS ----------------

def iso_utc_now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")

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
    except Exception:
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
    except Exception:
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

# ---------------- LOADING ----------------

def load_events():
    events = []

    for log_type, path in LOG_FILES.items():
        if not os.path.exists(path):
            continue

        with open(path, "r") as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue

                fields = line.strip().split("\t")

                raw = None
                if log_type == "conn":
                    raw = build_raw_conn(fields)
                elif log_type == "dns":
                    raw = build_raw_dns(fields)
                elif log_type == "http":
                    raw = build_raw_http(fields)
                elif log_type == "ssl":
                    raw = build_raw_ssl(fields)

                if not raw:
                    continue

                try:
                    ts = float(fields[0])
                except Exception:
                    continue

                events.append((ts, raw))

    events.sort(key=lambda x: x[0])
    return events

# ---------------- MAIN ----------------

def main():
    base_url = INGEST_URL.replace("/api/ingest/log", "")

    try:
        requests.get(base_url, timeout=2)
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
    print(f"Target duration: {TARGET_DURATION_SECONDS}s")
    print("=" * 60)

    events = load_events()

    if not events:
        print("❌ No events extracted.")
        return

    num_events = len(events)
    print("Total events:", num_events)

    # Spread events evenly across target duration.
    # First event at t=0, last event at ~TARGET_DURATION_SECONDS.
    if num_events == 1:
        interval_seconds = TARGET_DURATION_SECONDS
    else:
        interval_seconds = TARGET_DURATION_SECONDS / (num_events - 1)

    start_monotonic = time.monotonic()
    start_wall = time.time()

    sent_count = 0
    late_events = 0
    max_lag_seconds = 0.0

    session = requests.Session()

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
            scheduled_offset = idx * interval_seconds
            scheduled_time = start_monotonic + scheduled_offset

            # Wait BEFORE sending, based on absolute schedule
            while True:
                now = time.monotonic()
                remaining = scheduled_time - now
                if remaining <= 0:
                    break
                time.sleep(min(remaining, 0.05))

            actual_send_time = time.monotonic()
            lag = actual_send_time - scheduled_time
            if lag > 0.001:
                late_events += 1
                if lag > max_lag_seconds:
                    max_lag_seconds = lag

            payload = {"raw": raw}

            try:
                r = session.post(
                    INGEST_URL,
                    headers=headers,
                    json=payload,
                    timeout=5
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

            sent_count += 1

            # Reduce terminal overhead: print periodically instead of every line
            if idx < 5 or idx % 100 == 0 or idx == num_events - 1:
                elapsed = actual_send_time - start_monotonic
                print(
                    f"→ sent {idx + 1}/{num_events} "
                    f"| elapsed={elapsed:.2f}s "
                    f"| scheduled={scheduled_offset:.2f}s "
                    f"| lag={lag:.4f}s"
                )

    actual_duration = time.monotonic() - start_monotonic

    print("✅ Replay complete")
    print(f"📁 Artifact written: {csv_path}")
    print(f"⏱ Expected duration: {TARGET_DURATION_SECONDS}s")
    print(f"⏱ Actual duration:   {actual_duration:.2f}s")
    print(f"📦 Events sent:      {sent_count}")
    print(f"⏰ Late events:      {late_events}")
    print(f"📉 Max lag:          {max_lag_seconds:.4f}s")

    if actual_duration > TARGET_DURATION_SECONDS + 1:
        print("⚠️ Replay exceeded target duration.")
        print("⚠️ Cause: backend / network / print overhead slower than required pacing.")
        print("⚠️ To get closer to target, reduce terminal printing and/or backend latency.")

if __name__ == "__main__":
    main()




