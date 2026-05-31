#!/usr/bin/env python3

import os
import time
import csv
import uuid
import ipaddress
import requests
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Tuple


# ============================================================
# CONFIG
# ============================================================

BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "50"))
BATCH_MAX_DELAY = float(os.environ.get("BATCH_MAX_DELAY", "0.5"))

INGEST_URL = os.environ.get(
    "INGEST_ENDPOINT", "http://34.232.64.91:5002/api/ingest/log"
)

INGEST_SHARED_KEY = os.environ.get("INGEST_SHARED_KEY")
PCAP_NAME = os.environ.get("PCAP_NAME", "default_pcap")

# Desired wall-clock replay duration
TARGET_DURATION_SECONDS = int(os.environ.get("TARGET_DURATION_SECONDS", "5400"))

# Replay mode:
# - scaled_ts (recommended): preserve relative event timing shape
# - flat: evenly space events across target duration
REPLAY_MODE = os.environ.get("REPLAY_MODE", "scaled_ts").strip().lower()

# If true, cap events to what the measured network floor appears able to sustain
TRUNCATE = os.environ.get("TRUNCATE", "0") == "1"

IPV4_ONLY = os.environ.get("IPV4_ONLY", "1") == "1"

# Latency probe controls
LATENCY_PROBE_COUNT = int(os.environ.get("LATENCY_PROBE_COUNT", "5"))
LATENCY_HEADROOM = float(os.environ.get("LATENCY_HEADROOM", "1.10"))

# Optional soft spin threshold before send precision loop
SPIN_THRESHOLD_SECONDS = float(os.environ.get("SPIN_THRESHOLD_SECONDS", "0.003"))

# Request timeout
POST_TIMEOUT_SECONDS = float(os.environ.get("POST_TIMEOUT_SECONDS", "20"))

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
ZEEK_BASE = os.path.join(BASE_DIR, "..", "pcaps", "zeek_logs", PCAP_NAME)

LOG_FILES: Dict[str, str] = {
    "conn": os.path.join(ZEEK_BASE, "conn.log"),
    "dns": os.path.join(ZEEK_BASE, "dns.log"),
    "http": os.path.join(ZEEK_BASE, "http.log"),
    "ssl": os.path.join(ZEEK_BASE, "ssl.log"),
}

OUTPUT_DIR = os.path.join(BASE_DIR, "..", "outputs", "replays", PCAP_NAME)

VALID_REPLAY_MODES = {"scaled_ts", "flat", "natural"}


# ============================================================
# TIME ANCHOR
# ============================================================

BASE_TIME = datetime.now(timezone.utc)


def zeek_ts_to_iso(ts: float) -> str:
    """
    Anchor a Zeek-relative timestamp onto current UTC wall time.
    This is appropriate when Zeek logs contain capture-relative time rather
    than Unix epoch time.
    """
    return (BASE_TIME + timedelta(seconds=float(ts))).isoformat().replace("+00:00", "Z")


def iso_utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")


# ============================================================
# DATA STRUCTURES
# ============================================================


@dataclass
class Event:
    ts: float
    raw: str
    log_type: str
    line_number: int


@dataclass
class LoadStats:
    total_lines_seen: Dict[str, int] = field(default_factory=dict)
    total_events_kept: Dict[str, int] = field(default_factory=dict)
    dropped_comment_or_blank: Dict[str, int] = field(default_factory=dict)
    dropped_parse_error: Dict[str, int] = field(default_factory=dict)
    dropped_non_ipv4: Dict[str, int] = field(default_factory=dict)
    dropped_bad_proto: Dict[str, int] = field(default_factory=dict)
    dropped_missing_file: Dict[str, int] = field(default_factory=dict)

    def init_log(self, log_type: str) -> None:
        self.total_lines_seen.setdefault(log_type, 0)
        self.total_events_kept.setdefault(log_type, 0)
        self.dropped_comment_or_blank.setdefault(log_type, 0)
        self.dropped_parse_error.setdefault(log_type, 0)
        self.dropped_non_ipv4.setdefault(log_type, 0)
        self.dropped_bad_proto.setdefault(log_type, 0)
        self.dropped_missing_file.setdefault(log_type, 0)


# ============================================================
# HELPERS
# ============================================================


def validate_config() -> None:
    if REPLAY_MODE not in VALID_REPLAY_MODES:
        raise ValueError(
            f"Invalid REPLAY_MODE={REPLAY_MODE!r}. "
            f"Valid values: {', '.join(sorted(VALID_REPLAY_MODES))}"
        )

    if TARGET_DURATION_SECONDS <= 0:
        raise ValueError("TARGET_DURATION_SECONDS must be > 0")


def is_ipv4(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


def is_ip_allowed(ip: str) -> bool:
    if IPV4_ONLY:
        return is_ipv4(ip)
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def safe_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except Exception:
        return None


def print_header() -> None:
    print("=" * 72)
    print("                MULTI-LOG ATTACK REPLAY — ELITE EDITION")
    print("=" * 72)
    print(f"  PCAP:                 {PCAP_NAME}")
    print(f"  Ingest endpoint:      {INGEST_URL}")
    print(
        f"  Target duration:      {TARGET_DURATION_SECONDS}s ({TARGET_DURATION_SECONDS // 60} min)"
    )
    print(f"  Replay mode:          {REPLAY_MODE}")
    print(f"  IPv4 only:            {IPV4_ONLY}")
    print(f"  Truncate if needed:   {TRUNCATE}")
    print(f"  Zeek folder:          {ZEEK_BASE}")
    print("=" * 72)
    print(f"PCAP_NAME={PCAP_NAME}")


# ============================================================
# LATENCY PROBE
# ============================================================


def probe_latency(
    session: requests.Session, url: str, headers: Dict[str, str], n: int = 5
) -> Optional[float]:
    """
    Sends n probe POSTs to estimate average round-trip latency.
    Returns average latency in seconds, or None if all probes fail.
    """
    print(f"\n📡 Probing network latency ({n} requests)...")
    samples: List[float] = []

    for i in range(n):
        start = time.monotonic()
        try:
            session.post(
                url,
                headers=headers,
                json={"raw": "PROBE=1"},
                timeout=POST_TIMEOUT_SECONDS,
            )
            elapsed = time.monotonic() - start
            samples.append(elapsed)
            print(f"  probe {i + 1}/{n}: {elapsed * 1000:.1f} ms")
        except Exception as e:
            print(f"  ⚠️ Probe {i + 1}/{n} failed: {e}")

    if not samples:
        print("  ❌ All probes failed. Cannot determine latency floor.")
        return None

    avg = sum(samples) / len(samples)
    sustainable_eps = 1.0 / max(avg * LATENCY_HEADROOM, 1e-9)

    print(f"  ✅ Avg probe latency: {avg * 1000:.1f} ms")
    print(f"  ✅ Headroom-adjusted max sustainable EPS: {sustainable_eps:.2f}")
    return avg


# ============================================================
# RAW BUILDERS
# ============================================================


def build_raw_conn(fields: List[str], stats: LoadStats, log_type: str) -> Optional[str]:
    # Expected indexes:
    # 0 ts, 2 id.orig_h, 3 id.orig_p, 4 id.resp_h, 5 id.resp_p, 6 proto,
    # 9 orig_bytes, 10 resp_bytes
    try:
        proto = fields[6].lower()
        if proto not in ("tcp", "udp"):
            stats.dropped_bad_proto[log_type] += 1
            return None

        src = fields[2]
        dst = fields[4]

        if not is_ip_allowed(src) or not is_ip_allowed(dst):
            stats.dropped_non_ipv4[log_type] += 1
            return None

        spt = safe_int(fields[3])
        dpt = safe_int(fields[5])
        if spt is None or dpt is None:
            stats.dropped_parse_error[log_type] += 1
            return None

        orig_bytes = 0 if fields[9] == "-" else int(fields[9])
        resp_bytes = 0 if fields[10] == "-" else int(fields[10])
        total_bytes = orig_bytes + resp_bytes
        ts_iso = zeek_ts_to_iso(float(fields[0]))

        return (
            f"TS={ts_iso} "
            f"SRC={src} SPT={spt} "
            f"DST={dst} DPT={dpt} "
            f"PROTO={proto.upper()} "
            f"BYTES={total_bytes}"
        )
    except Exception:
        stats.dropped_parse_error[log_type] += 1
        return None


def build_raw_dns(fields: List[str], stats: LoadStats, log_type: str) -> Optional[str]:
    # Expected indexes:
    # 0 ts, 2 id.orig_h, 4 id.resp_h, 9 query, 11 qtype_name
    try:
        src = fields[2]
        dst = fields[4]

        if not is_ip_allowed(src) or not is_ip_allowed(dst):
            stats.dropped_non_ipv4[log_type] += 1
            return None

        ts_iso = zeek_ts_to_iso(float(fields[0]))
        query = fields[9]
        qtype = fields[11]

        return (
            f"TS={ts_iso} "
            f"SRC={src} DST={dst} "
            f"PROTO=DNS "
            f"QUERY={query} "
            f"QTYPE={qtype}"
        )
    except Exception:
        stats.dropped_parse_error[log_type] += 1
        return None


def build_raw_http(fields: List[str], stats: LoadStats, log_type: str) -> Optional[str]:
    # Typical http.log indexes:
    # 0 ts
    # 2 id.orig_h
    # 3 id.orig_p
    # 4 id.resp_h
    # 5 id.resp_p
    # 7 method
    # 8 host
    # 9 uri
    # 15 status_code

    try:
        src = fields[2]
        dst = fields[4]

        if not is_ip_allowed(src) or not is_ip_allowed(dst):
            stats.dropped_non_ipv4[log_type] += 1
            return None

        spt = safe_int(fields[3])
        dpt = safe_int(fields[5])

        if spt is None or dpt is None:
            stats.dropped_parse_error[log_type] += 1
            return None

        ts_iso = zeek_ts_to_iso(float(fields[0]))
        method = fields[7]
        host = fields[8]
        uri = fields[9]
        status = fields[15]

        return (
            f"TS={ts_iso} "
            f"SRC={src} SPT={spt} "
            f"DST={dst} DPT={dpt} "
            f"PROTO=HTTP "
            f"METHOD={method} "
            f"HOST={host} "
            f"URI={uri} "
            f"STATUS={status}"
        )

    except Exception:
        stats.dropped_parse_error[log_type] += 1
        return None


def build_raw_ssl(fields: List[str], stats: LoadStats, log_type: str) -> Optional[str]:
    try:
        src = fields[2]
        dst = fields[4]

        if not is_ip_allowed(src) or not is_ip_allowed(dst):
            stats.dropped_non_ipv4[log_type] += 1
            return None

        spt = safe_int(fields[3])
        dpt = safe_int(fields[5])
        if spt is None or dpt is None:
            stats.dropped_parse_error[log_type] += 1
            return None

        ts_iso = zeek_ts_to_iso(float(fields[0]))
        version = fields[6]
        server_name = fields[9]

        return (
            f"TS={ts_iso} "
            f"SRC={src} SPT={spt} "
            f"DST={dst} DPT={dpt} "
            f"PROTO=SSL "
            f"SNI={server_name} "
            f"TLS_VERSION={version}"
        )
    except Exception:
        stats.dropped_parse_error[log_type] += 1
        return None


# ============================================================
# LOADING
# ============================================================


def load_events() -> Tuple[List[Event], LoadStats]:
    stats = LoadStats()
    events: List[Event] = []

    for log_type, path in LOG_FILES.items():
        stats.init_log(log_type)

        if not os.path.exists(path):
            stats.dropped_missing_file[log_type] += 1
            print(f"  ⚠️ Missing log: {path}")
            continue

        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line_number, line in enumerate(f, start=1):
                stats.total_lines_seen[log_type] += 1

                if line.startswith("#") or not line.strip():
                    stats.dropped_comment_or_blank[log_type] += 1
                    continue

                fields = line.rstrip("\n").split("\t")

                try:
                    ts = float(fields[0])
                except Exception:
                    stats.dropped_parse_error[log_type] += 1
                    continue

                raw: Optional[str] = None
                if log_type == "conn":
                    raw = build_raw_conn(fields, stats, log_type)
                elif log_type == "dns":
                    raw = build_raw_dns(fields, stats, log_type)
                elif log_type == "http":
                    raw = build_raw_http(fields, stats, log_type)
                elif log_type == "ssl":
                    raw = build_raw_ssl(fields, stats, log_type)

                if not raw:
                    continue

                events.append(
                    Event(
                        ts=ts,
                        raw=raw,
                        log_type=log_type,
                        line_number=line_number,
                    )
                )
                stats.total_events_kept[log_type] += 1

    events.sort(key=lambda e: e.ts)
    return events, stats


def print_load_stats(stats: LoadStats) -> None:
    print("\n📊 Load statistics by log")
    print("-" * 72)
    for log_type in LOG_FILES.keys():
        seen = stats.total_lines_seen.get(log_type, 0)
        kept = stats.total_events_kept.get(log_type, 0)
        blank = stats.dropped_comment_or_blank.get(log_type, 0)
        parse = stats.dropped_parse_error.get(log_type, 0)
        non_ipv4 = stats.dropped_non_ipv4.get(log_type, 0)
        bad_proto = stats.dropped_bad_proto.get(log_type, 0)
        missing = stats.dropped_missing_file.get(log_type, 0)

        print(
            f"{log_type:>5} | seen={seen:<8} kept={kept:<8} "
            f"blank/comment={blank:<8} parse_err={parse:<8} "
            f"ip_drop={non_ipv4:<8} proto_drop={bad_proto:<8} missing={missing}"
        )
    print("-" * 72)


# ============================================================
# SCHEDULING
# ============================================================


def compute_schedule_offsets(
    events: List[Event], target_duration_seconds: int, replay_mode: str
) -> Tuple[List[float], Dict[str, float]]:
    """
    Returns:
      - offsets: list of scheduled offsets (seconds since replay start)
      - schedule_info: diagnostics for logging
    """
    num_events = len(events)
    if num_events == 0:
        raise ValueError("Cannot schedule zero events")

    first_ts = events[0].ts
    last_ts = events[-1].ts
    source_span = max(last_ts - first_ts, 0.0)

    schedule_info: Dict[str, float] = {
        "num_events": float(num_events),
        "first_ts": first_ts,
        "last_ts": last_ts,
        "source_span": source_span,
        "target_duration_seconds": float(target_duration_seconds),
    }

    if num_events == 1:
        offsets = [0.0]
        schedule_info["schedule_span"] = 0.0
        schedule_info["effective_eps"] = 1.0 / max(target_duration_seconds, 1)
        return offsets, schedule_info

    if replay_mode == "flat":
        interval = target_duration_seconds / num_events
        offsets = [i * interval for i in range(num_events)]
        schedule_span = offsets[-1] - offsets[0]
        effective_eps = num_events / max(target_duration_seconds, 1e-9)

        schedule_info["interval"] = interval
        schedule_info["schedule_span"] = schedule_span
        schedule_info["effective_eps"] = effective_eps
        return offsets, schedule_info


    # ============================================================
    # NATURAL MODE
    # ============================================================

    if replay_mode == "natural":

        offsets = [
            event.ts - first_ts
            for event in events
        ]

        schedule_span = offsets[-1] - offsets[0]

        effective_eps = (
            num_events / max(schedule_span, 1e-9)
        )

        schedule_info["schedule_span"] = schedule_span
        schedule_info["effective_eps"] = effective_eps
        schedule_info["natural_replay"] = 1.0

        return offsets, schedule_info    
    

    # scaled_ts mode
    if source_span <= 0:
        # Fallback for zero-span captures
        interval = target_duration_seconds / num_events
        offsets = [i * interval for i in range(num_events)]
        schedule_span = offsets[-1] - offsets[0]
        effective_eps = num_events / max(target_duration_seconds, 1e-9)

        schedule_info["interval"] = interval
        schedule_info["schedule_span"] = schedule_span
        schedule_info["effective_eps"] = effective_eps
        schedule_info["zero_span_fallback"] = 1.0
        return offsets, schedule_info

    # Scale original relative offsets into target duration
    scale = target_duration_seconds / source_span
    offsets = [(event.ts - first_ts) * scale for event in events]
    schedule_span = offsets[-1] - offsets[0]
    effective_eps = num_events / max(target_duration_seconds, 1e-9)

    schedule_info["scale"] = scale
    schedule_info["schedule_span"] = schedule_span
    schedule_info["effective_eps"] = effective_eps
    return offsets, schedule_info


def maybe_truncate_events_for_network_floor(
    events: List[Event], target_duration_seconds: int, avg_latency: Optional[float]
) -> Tuple[List[Event], bool, Optional[int], Optional[float]]:

    if not avg_latency:
        return events, False, None, None

    max_sustainable_eps = 1.0 / max(avg_latency * LATENCY_HEADROOM, 1e-9)
    derived_eps = len(events) / max(target_duration_seconds, 1e-9)

    if derived_eps <= max_sustainable_eps:
        return events, False, None, max_sustainable_eps

    max_sendable = int(max_sustainable_eps * target_duration_seconds)

    if TRUNCATE and max_sendable > 0:
        return events[:max_sendable], True, max_sendable, max_sustainable_eps

    return events, False, max_sendable, max_sustainable_eps


# ============================================================
# MAIN
# ============================================================


def main() -> None:
    validate_config()
    print_header()

    base_url = INGEST_URL.replace("/api/ingest/log", "")

    try:
        requests.get(base_url, timeout=2)
    except Exception:
        print("❌ Ingest service not reachable.")
        return

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    run_id = iso_utc_now()
    replay_id = str(uuid.uuid4())[:8]
    csv_path = os.path.join(OUTPUT_DIR, f"{run_id}_{replay_id}_{PCAP_NAME}.csv")
    obs_windows = TARGET_DURATION_SECONDS // 60

    headers = {
        "Authorization": f"Bearer {INGEST_SHARED_KEY}",
        "Content-Type": "application/json",
    }

    session = requests.Session()

    # --------------------------------------------------------
    # Probe latency
    # --------------------------------------------------------
    avg_latency = probe_latency(
        session=session,
        url=INGEST_URL,
        headers=headers,
        n=LATENCY_PROBE_COUNT,
    )

    # --------------------------------------------------------
    # Load events
    # --------------------------------------------------------
    print("\n📂 Loading Zeek events...")
    events, stats = load_events()
    print_load_stats(stats)

    if not events:
        print("\n❌ No valid replay events extracted.")
        return

    # --------------------------------------------------------
    # Network floor check + optional truncation
    # --------------------------------------------------------
    original_event_count = len(events)
    events, did_truncate, max_sendable, max_sustainable_eps = (
        maybe_truncate_events_for_network_floor(
            events=events,
            target_duration_seconds=TARGET_DURATION_SECONDS,
            avg_latency=avg_latency,
        )
    )

    if avg_latency is not None:
        print("\n🧪 Network floor analysis")
        print("-" * 72)
        print(f"  avg probe latency:        {avg_latency * 1000:.2f} ms")
        print(f"  adjusted max EPS:         {max_sustainable_eps:.4f}")
        print(
            f"  requested target EPS:     {original_event_count / TARGET_DURATION_SECONDS:.4f}"
        )
        if did_truncate:
            print(f"  truncation applied:       YES")
            print(f"  max sendable events:      {max_sendable}")
            print(f"  original events:          {original_event_count}")
            print(f"  truncated events:         {len(events)}")
        else:
            print(f"  truncation applied:       NO")
            if max_sendable is not None and original_event_count > max_sendable:
                print(f"  ⚠️ Target rate appears above network floor.")
                if not TRUNCATE:
                    print(f"  ⚠️ TRUNCATE=0, so replay will still attempt full send.")
        print("-" * 72)

    # --------------------------------------------------------
    # Schedule events
    # --------------------------------------------------------
    offsets, schedule_info = compute_schedule_offsets(
        events=events,
        target_duration_seconds=TARGET_DURATION_SECONDS,
        replay_mode=REPLAY_MODE,
    )

    num_events = len(events)
    first_ts = schedule_info["first_ts"]
    last_ts = schedule_info["last_ts"]
    source_span = schedule_info["source_span"]
    schedule_span = schedule_info["schedule_span"]
    effective_eps = schedule_info["effective_eps"]

    print("\n🕒 Replay schedule summary")
    print("-" * 72)
    print(f"  total events:            {num_events}")
    print(f"  source first ts:         {first_ts:.6f}")
    print(f"  source last ts:          {last_ts:.6f}")
    print(f"  source span:             {source_span:.6f}s ({source_span / 60:.2f} min)")
    print(
        f"  target duration:         {TARGET_DURATION_SECONDS}s ({TARGET_DURATION_SECONDS / 60:.2f} min)"
    )
    print(f"  schedule span:           {schedule_span:.6f}s")
    print(f"  observation windows:     {obs_windows} x 1-minute buckets")
    print(f"  effective EPS:           {effective_eps:.6f}")

    if REPLAY_MODE == "scaled_ts":
        if "scale" in schedule_info:
            print(f"  replay scale factor:     {schedule_info['scale']:.8f}")
        if "zero_span_fallback" in schedule_info:
            print(f"  zero-span fallback:      YES")
    elif REPLAY_MODE == "flat":
        print(f"  flat interval:           {schedule_info['interval'] * 1000:.3f} ms")
    print("-" * 72)

    # --------------------------------------------------------
    # Replay loop (BATCHED)
    # --------------------------------------------------------
    start_monotonic = time.monotonic()
    sent_count = 0
    late_events = 0
    max_lag_seconds = 0.0
    total_lag_seconds = 0.0

    batch = []
    batch_first_scheduled_time = None
    last_flush_time = time.monotonic()

    print("\n🚀 Starting replay (BATCH MODE)...\n")

    with open(csv_path, "w", newline="", encoding="utf-8") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            [
                "run_id",
                "pcap",
                "event_index",
                "log_type",
                "source_ts",
                "scheduled_offset_seconds",
                "scheduled_wall_ts",
                "actual_wall_ts",
                "lag_seconds",
                "raw",
            ]
        )

        for idx, event in enumerate(events):
            scheduled_offset = offsets[idx]
            scheduled_time = start_monotonic + scheduled_offset

            # ---- timing control ----
            while True:
                now = time.monotonic()
                remaining = scheduled_time - now
                if remaining <= SPIN_THRESHOLD_SECONDS:
                    break
                time.sleep(min(remaining - SPIN_THRESHOLD_SECONDS, 0.05))

            while time.monotonic() < scheduled_time:
                pass

            actual_send_monotonic = time.monotonic()
            lag = actual_send_monotonic - scheduled_time

            if lag > 0.001:
                late_events += 1
                max_lag_seconds = max(max_lag_seconds, lag)
            total_lag_seconds += lag

            actual_wall_dt = datetime.now(timezone.utc)
            scheduled_wall_dt = BASE_TIME + timedelta(seconds=scheduled_offset)

            # ---- add to batch ----
            batch.append({"raw": event.raw})

            if batch_first_scheduled_time is None:
                batch_first_scheduled_time = scheduled_time

            # ---- write CSV immediately (keeps audit accurate) ----
            writer.writerow(
                [
                    run_id,
                    PCAP_NAME,
                    idx,
                    event.log_type,
                    f"{event.ts:.6f}",
                    f"{scheduled_offset:.6f}",
                    scheduled_wall_dt.isoformat().replace("+00:00", "Z"),
                    actual_wall_dt.isoformat().replace("+00:00", "Z"),
                    f"{lag:.6f}",
                    event.raw,
                ]
            )

            sent_count += 1

            # ---- flush conditions ----
            now = time.monotonic()
            batch_age = now - last_flush_time

            should_flush = (
                len(batch) >= BATCH_SIZE
                or batch_age >= BATCH_MAX_DELAY
                or idx == num_events - 1
            )

            if should_flush:

                # =========================================
                # SAFE SEQUENTIAL INGEST
                # =========================================

                for payload in batch:

                    try:

                        response = session.post(
                            INGEST_URL,
                            headers=headers,
                            json=payload,
                            timeout=POST_TIMEOUT_SECONDS,
                        )

                        if response.status_code not in (200, 201):

                            print(
                                f"❌ Ingest rejected "
                                f"[{response.status_code}]: "
                                f"{response.text}"
                            )

                    except Exception as e:

                        print(
                            f"❌ Batch ingest error: {e}"
                        )

                        return


                    time.sleep(0.02)

                # =========================================
                # RESET BATCH
                # =========================================

                batch = []

                batch_first_scheduled_time = None

                last_flush_time = now

            # ---- progress logging ----
            if idx < 5 or idx % 500 == 0 or idx == num_events - 1:
                elapsed = actual_send_monotonic - start_monotonic
                actual_eps = sent_count / elapsed if elapsed > 0 else 0.0
                window_num = int(elapsed // 60) + 1

                print(
                    f"→ {idx + 1:>6}/{num_events} "
                    f"| elapsed={elapsed:>8.2f}s "
                    f"| window={window_num:>2}/{obs_windows} "
                    f"| eps={actual_eps:>8.2f} "
                    f"| lag={lag * 1000:>6.2f}ms "
                    f"| batch={len(batch)}"
                )

    # --------------------------------------------------------
    # Final summary
    # --------------------------------------------------------
    actual_duration = time.monotonic() - start_monotonic
    actual_eps = sent_count / actual_duration if actual_duration > 0 else 0.0
    avg_lag_seconds = total_lag_seconds / sent_count if sent_count else 0.0
    duration_delta = abs(actual_duration - TARGET_DURATION_SECONDS)

    print("\n" + "=" * 72)
    print("✅ REPLAY COMPLETE")
    print("=" * 72)
    print(f"  📁 Artifact:             {csv_path}")
    print(f"  📦 Events sent:          {sent_count} / {num_events}")
    print(f"  🧠 Replay mode:          {REPLAY_MODE}")
    print(
        f"  ⏱ Target duration:       {TARGET_DURATION_SECONDS:.2f}s ({TARGET_DURATION_SECONDS / 60:.2f} min)"
    )
    print(
        f"  ⏱ Actual duration:       {actual_duration:.2f}s ({actual_duration / 60:.2f} min)"
    )
    print(f"  🪟 Windows covered:       {int(actual_duration // 60)} x 1-min")
    print(f"  ⚡ Actual EPS:            {actual_eps:.6f}")
    print(
        f"  ⏰ Late events:           {late_events} ({(100.0 * late_events / sent_count) if sent_count else 0.0:.2f}%)"
    )
    print(f"  📉 Avg lag:               {avg_lag_seconds * 1000:.3f} ms")
    print(f"  📉 Max lag:               {max_lag_seconds * 1000:.3f} ms")
    print("=" * 72)

    if duration_delta > 60:
        print(f"⚠️ Actual duration is off target by {duration_delta:.2f}s.")

    if sent_count > 0 and (late_events / sent_count) > 0.10:
        print("⚠️ More than 10% of events were late.")
        print("⚠️ Network, target duration, or event density may be too aggressive.")

    if REPLAY_MODE == "flat":
        print(
            "⚠️ Note: flat replay intentionally removes original burst/gap timing structure."
        )
    else:
        print(
            "✅ Scaled timestamp replay preserved original temporal shape within target duration."
        )


if __name__ == "__main__":
    main()








