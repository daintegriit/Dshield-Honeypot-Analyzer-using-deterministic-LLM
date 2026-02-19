#!/usr/bin/env python3
import os
import time
import json
import requests
from datetime import datetime

# ===== CONFIG =====
BACKEND_URL = os.environ.get("INGEST_ENDPOINT", "http://YOUR_DASHBOARD_PUBLIC_IP:5002/api/ingest/log")
INGEST_SHARED_KEY = os.environ.get("INGEST_SHARED_KEY")

# verified DShield log path:
LOG_FILE = "/var/log/dshield.log"

# ===== Tail -F follower =====
def follow(path):
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line.rstrip("\n")


# ===== Send event to backend =====
def send_event(raw_line):
    payload = {
        "honeypotId": "dshield-aws",
        "raw": raw_line
    }

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {INGEST_SHARED_KEY}"
    }

    try:
        resp = requests.post(BACKEND_URL, headers=headers, data=json.dumps(payload), timeout=5)
        if resp.status_code >= 300:
            print(f"[{datetime.utcnow().isoformat()}] ❌ Failed ({resp.status_code}) {resp.text}")
        else:
            print(f"[{datetime.utcnow().isoformat()}] ✔ Sent log line")
    except Exception as e:
        print(f"[{datetime.utcnow().isoformat()}] ❌ ERROR sending: {e}")


# ===== Main =====
def main():
    print("=== Starting Honeypot Forwarder ===")
    print(f"Watching: {LOG_FILE}")
    print(f"Sending to: {BACKEND_URL}")

    for line in follow(LOG_FILE):
        send_event(line)


if __name__ == "__main__":
    main()