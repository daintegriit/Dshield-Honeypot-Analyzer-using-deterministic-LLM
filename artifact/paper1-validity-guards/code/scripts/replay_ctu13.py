#!/usr/bin/env python3
"""
CTU-13 Labeled NetFlow Replay -> Chiron ingest
==============================================

Purpose
-------
Replay CTU-13 bidirectional Argus NetFlows (.binetflow) into the Chiron ingest
endpoint, carrying the hand-curated ground-truth label with every flow.

Why this matters
----------------
Unlike the pcap replay (which infers truth from a single infection time
boundary), CTU-13 provides PER-FLOW labels: Botnet / Normal / Background,
manually assigned by the Stratosphere lab. That gives:
  - real precision / recall / FPR against verified ground truth
  - labeled benign traffic (Normal) for false-positive measurement
  - explicitly labeled C&C channels (CC*) to evaluate C2 detection specifically

Label taxonomy (from the dataset)
---------------------------------
  *Botnet*      -> malicious    (subclass 'c2' when the label contains '-CC')
  *Normal*      -> benign       (real user machines: Stribrek, Grill, Jist, ...)
  *Background*  -> excluded from metrics (unlabeled / uncertain by CTU definition)

Note the taxonomy must be matched by SUBSTRING, not prefix:
  flow=From-Normal-V42-Stribrek      -> normal
  flow=Normal-V42-HTTP-windowsupdate -> normal   (no 'From-' prefix)
  flow=To-Normal-V42-UDP-NTP-server  -> normal   ('To-' prefix)

Emitted raw line format (matches the existing Chiron parser)
------------------------------------------------------------
  TS=<iso8601Z> SRC=<ip> SPT=<port> DST=<ip> DPT=<port> PROTO=<UPPER> BYTES=<n>

Payload posted to /api/ingest/log
---------------------------------
  {
    "raw": "<raw line>",
    "source": "replay",
    "replay_pcap": "ctu13-s<N>",
    "ctu_label": "<original full label>",
    "ctu_class": "botnet" | "normal",
    "ctu_subclass": "c2" | "spam" | "dns" | "ad" | "download" | "other"
  }

Usage
-----
  python3 replay_ctu13.py --scenario 1
  python3 replay_ctu13.py --scenario 1 --include-background --background-sample 0.1
  python3 replay_ctu13.py --scenario 1 --limit 1000 --dry-run
"""

import os
import sys
import csv
import time
import random
import argparse
import ipaddress
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

import requests


# ============================================================
# CONFIG
# ============================================================

INGEST_URL = os.environ.get(
    "INGEST_ENDPOINT", "http://localhost:5002/api/ingest/log"
)
INGEST_SHARED_KEY = os.environ.get("INGEST_SHARED_KEY")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_CTU_DIR = os.path.join(BASE_DIR, "..", "ctu13", "CTU-13-Dataset")

# Rate limiting: the backend ingests sequentially; this mirrors the pcap replay.
SEND_DELAY = float(os.environ.get("SEND_DELAY", "0.02"))  # ~50 events/sec
POST_TIMEOUT_SECONDS = float(os.environ.get("POST_TIMEOUT_SECONDS", "20"))
PROGRESS_EVERY = int(os.environ.get("PROGRESS_EVERY", "500"))

# .binetflow column indices (header:
#   StartTime,Dur,Proto,SrcAddr,Sport,Dir,DstAddr,Dport,State,sTos,dTos,
#   TotPkts,TotBytes,SrcBytes,Label)
COL_START = 0
COL_DUR = 1
COL_PROTO = 2
COL_SRC = 3
COL_SPORT = 4
COL_DIR = 5
COL_DST = 6
COL_DPORT = 7
COL_STATE = 8
COL_TOTPKTS = 11
COL_TOTBYTES = 12
COL_SRCBYTES = 13
COL_LABEL = 14


# ============================================================
# LABEL CLASSIFICATION
# ============================================================

def classify_label(label: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Map a raw CTU-13 label to (ctu_class, ctu_subclass).

    Returns (None, None) for Background / unrecognised labels so callers can
    exclude them from metrics.

    Matching is by substring because the dataset uses several prefixes:
      From-Botnet-*, To-Botnet-*, From-Normal-*, To-Normal-*, Normal-*, ...
    Order matters: check Botnet before Normal, because some botnet labels
    reference normal-looking services (e.g. HTTP-Google-Net).
    """
    if not label:
        return (None, None)

    l = label.lower()

    # Background is explicitly NOT ground truth for benign — CTU treats it as
    # unlabeled/uncertain. Excluded from metrics.
    if "background" in l:
        return (None, None)

    if "botnet" in l:
        # Subclass: the labels encode behaviour. '-cc' marks Command & Control
        # channels, which is the ground truth for the C2 detector specifically.
        if "-cc" in l:
            sub = "c2"
        elif "spam" in l:
            sub = "spam"
        elif "dns" in l:
            sub = "dns"
        elif "-ad-" in l or "-ad" in l or "yieldmanager" in l:
            sub = "ad"
        elif "binary-download" in l:
            sub = "download"
        elif "icmp" in l:
            sub = "icmp"
        else:
            sub = "other"
        return ("botnet", sub)

    if "normal" in l:
        return ("normal", "normal")

    return (None, None)


# ============================================================
# PARSING
# ============================================================

def parse_start_time(value: str) -> Optional[datetime]:
    """CTU format: 2011/08/10 09:46:59.607825 (no timezone; treat as UTC)."""
    try:
        dt = datetime.strptime(value.strip(), "%Y/%m/%d %H:%M:%S.%f")
        return dt.replace(tzinfo=timezone.utc)
    except Exception:
        try:
            dt = datetime.strptime(value.strip(), "%Y/%m/%d %H:%M:%S")
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def to_iso(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def safe_port(value: str) -> Optional[int]:
    """
    Ports are usually decimal, but Argus can emit hex (0x...) for some protos,
    and ICMP rows may carry non-port values. Return None when unusable.
    """
    if value is None:
        return None
    v = value.strip()
    if not v:
        return None
    try:
        if v.lower().startswith("0x"):
            return int(v, 16)
        return int(v)
    except Exception:
        return None


def is_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.strip()).version == 4
    except Exception:
        return False


def safe_int(value: str, default: int = 0) -> int:
    try:
        return int(float(value))
    except Exception:
        return default


def build_raw(row: List[str]) -> Optional[str]:
    """
    Build a Chiron-compatible raw line.

    SrcAddr is always the flow initiator in Argus regardless of the Dir column
    (Dir describes observed direction, not who opened the flow), so the mapping
    SrcAddr->SRC / DstAddr->DST is correct for all direction values.
    """
    try:
        src = row[COL_SRC].strip()
        dst = row[COL_DST].strip()

        if not is_ipv4(src) or not is_ipv4(dst):
            return None

        dt = parse_start_time(row[COL_START])
        if dt is None:
            return None

        proto = row[COL_PROTO].strip().upper()  # parser regex expects [A-Z0-9]+
        if not proto:
            proto = "UNKNOWN"

        spt = safe_port(row[COL_SPORT])
        dpt = safe_port(row[COL_DPORT])
        total_bytes = safe_int(row[COL_TOTBYTES], 0)

        parts = [f"TS={to_iso(dt)}", f"SRC={src}"]
        if spt is not None:
            parts.append(f"SPT={spt}")
        parts.append(f"DST={dst}")
        if dpt is not None:
            parts.append(f"DPT={dpt}")
        parts.append(f"PROTO={proto}")
        parts.append(f"BYTES={total_bytes}")

        return " ".join(parts)
    except Exception:
        return None


# ============================================================
# LOADING
# ============================================================

def load_flows(
    path: str,
    include_background: bool,
    background_sample: float,
    limit: Optional[int],
) -> Tuple[List[Dict], Dict[str, int]]:
    """
    Read the .binetflow, classify labels, build payloads.
    Returns (payloads, stats).
    """
    stats = {
        "rows_read": 0,
        "botnet": 0,
        "normal": 0,
        "background_kept": 0,
        "background_skipped": 0,
        "unparseable": 0,
        "c2": 0,
    }

    payloads: List[Dict] = []
    rng = random.Random(1337)  # deterministic subsampling

    with open(path, "r", encoding="utf-8", errors="replace") as f:
        reader = csv.reader(f)
        header = next(reader, None)  # skip header row

        for row in reader:
            stats["rows_read"] += 1

            if len(row) <= COL_LABEL:
                stats["unparseable"] += 1
                continue

            label = row[COL_LABEL].strip()
            cls, sub = classify_label(label)

            if cls is None:
                # Background / unrecognised
                if not include_background:
                    stats["background_skipped"] += 1
                    continue
                if rng.random() > background_sample:
                    stats["background_skipped"] += 1
                    continue
                cls, sub = "background", "background"
                stats["background_kept"] += 1

            raw = build_raw(row)
            if raw is None:
                stats["unparseable"] += 1
                continue

            if cls == "botnet":
                stats["botnet"] += 1
                if sub == "c2":
                    stats["c2"] += 1
            elif cls == "normal":
                stats["normal"] += 1

            payloads.append({
                "raw": raw,
                "source": "replay",
                "ctu_label": label,
                "ctu_class": cls,
                "ctu_subclass": sub,
                "_ts": row[COL_START].strip(),  # kept for sorting, stripped before POST
            })

            if limit and len(payloads) >= limit:
                break

    # Preserve chronological order (the file is mostly ordered, but not guaranteed)
    payloads.sort(key=lambda p: p["_ts"])
    for p in payloads:
        p.pop("_ts", None)

    return payloads, stats


# ============================================================
# MAIN
# ============================================================

def main() -> None:
    ap = argparse.ArgumentParser(description="Replay CTU-13 labeled netflows into Chiron")
    ap.add_argument("--scenario", type=int, required=True, help="CTU-13 scenario number (1-13)")
    ap.add_argument("--ctu-dir", default=DEFAULT_CTU_DIR, help="Path to CTU-13-Dataset dir")
    ap.add_argument("--include-background", action="store_true",
                    help="Also replay Background flows (excluded from metrics)")
    ap.add_argument("--background-sample", type=float, default=0.1,
                    help="Fraction of Background to keep when included (default 0.1)")
    ap.add_argument("--limit", type=int, default=None, help="Cap number of flows (testing)")
    ap.add_argument("--dry-run", action="store_true", help="Parse and report, do not POST")
    ap.add_argument("--ingest-url", default=INGEST_URL)
    args = ap.parse_args()

    # Locate the scenario's .binetflow
    scen_dir = os.path.join(args.ctu_dir, str(args.scenario))
    if not os.path.isdir(scen_dir):
        print(f"❌ Scenario dir not found: {scen_dir}")
        sys.exit(1)

    candidates = [f for f in os.listdir(scen_dir) if f.endswith(".binetflow")]
    if not candidates:
        print(f"❌ No .binetflow in {scen_dir}")
        sys.exit(1)

    path = os.path.join(scen_dir, candidates[0])
    pcap_name = f"ctu13-s{args.scenario}"

    print("=" * 72)
    print("           CTU-13 LABELED NETFLOW REPLAY")
    print("=" * 72)
    print(f"  Scenario:            {args.scenario}")
    print(f"  File:                {path}")
    print(f"  Ingest:              {args.ingest_url}")
    print(f"  Include background:  {args.include_background}"
          + (f" (sample={args.background_sample})" if args.include_background else ""))
    print(f"  Limit:               {args.limit or 'none'}")
    print(f"  Dry run:             {args.dry_run}")
    print("=" * 72)
    print(f"PCAP_NAME={pcap_name}")

    print("\n📂 Loading and classifying flows...")
    t0 = time.time()
    payloads, stats = load_flows(
        path=path,
        include_background=args.include_background,
        background_sample=args.background_sample,
        limit=args.limit,
    )
    load_secs = time.time() - t0

    print("\n📊 Load statistics")
    print("-" * 72)
    print(f"  rows read:           {stats['rows_read']:,}")
    print(f"  botnet flows:        {stats['botnet']:,}   (of which C&C: {stats['c2']:,})")
    print(f"  normal flows:        {stats['normal']:,}")
    print(f"  background kept:     {stats['background_kept']:,}")
    print(f"  background skipped:  {stats['background_skipped']:,}")
    print(f"  unparseable:         {stats['unparseable']:,}")
    print(f"  TO REPLAY:           {len(payloads):,}")
    print(f"  load time:           {load_secs:.1f}s")
    print("-" * 72)

    if not payloads:
        print("❌ Nothing to replay.")
        sys.exit(1)

    est = len(payloads) * SEND_DELAY
    print(f"\n⏱  Estimated replay time: {est/60:.1f} min at {1/SEND_DELAY:.0f} events/sec")

    if args.dry_run:
        print("\n🔍 DRY RUN — sample payloads:")
        for p in payloads[:3]:
            print(f"  {p['ctu_class']:10s} {p['ctu_subclass']:10s} {p['raw'][:90]}")
        print("\n✅ Dry run complete. No data sent.")
        return

    # ---- send ----
    session = requests.Session()
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {INGEST_SHARED_KEY}",
    }

    # reachability probe
    base = args.ingest_url.replace("/api/ingest/log", "")
    try:
        requests.get(base, timeout=3)
    except Exception:
        print(f"❌ Ingest service not reachable at {base}")
        sys.exit(1)

    print(f"\n🚀 Replaying {len(payloads):,} flows...\n")
    sent = 0
    failed = 0
    start = time.time()

    for idx, payload in enumerate(payloads):
        body = dict(payload)
        body["replay_pcap"] = pcap_name

        try:
            resp = session.post(
                args.ingest_url, headers=headers, json=body,
                timeout=POST_TIMEOUT_SECONDS,
            )
            if resp.status_code in (200, 201):
                sent += 1
            else:
                failed += 1
                if failed <= 5:
                    print(f"❌ Ingest rejected [{resp.status_code}]: {resp.text[:120]}")
        except Exception as e:
            failed += 1
            if failed <= 5:
                print(f"❌ Ingest error (skipping): {e}")

        if idx % PROGRESS_EVERY == 0 or idx == len(payloads) - 1:
            elapsed = time.time() - start
            eps = sent / elapsed if elapsed > 0 else 0
            pct = 100.0 * (idx + 1) / len(payloads)
            print(f"→ {idx+1:>7,}/{len(payloads):,} ({pct:5.1f}%) "
                  f"| sent={sent:,} failed={failed:,} "
                  f"| {eps:5.1f} eps | {elapsed/60:5.1f} min")

        time.sleep(SEND_DELAY)

    total = time.time() - start
    print("\n" + "=" * 72)
    print("✅ REPLAY COMPLETE")
    print("=" * 72)
    print(f"  scenario:        {args.scenario} ({pcap_name})")
    print(f"  sent:            {sent:,}")
    print(f"  failed:          {failed:,}")
    print(f"  duration:        {total/60:.1f} min")
    print(f"  effective eps:   {sent/total if total else 0:.2f}")
    print("=" * 72)
    print("\nGround truth is stored per-document as ctu_class / ctu_subclass.")
    print("Query examples:")
    print('  db.attacks.countDocuments({ replay_pcap: "%s", ctu_class: "botnet" })' % pcap_name)
    print('  db.attacks.countDocuments({ replay_pcap: "%s", ctu_class: "normal" })' % pcap_name)
    print('  db.attacks.countDocuments({ replay_pcap: "%s", ctu_subclass: "c2" })' % pcap_name)


if __name__ == "__main__":
    main()
