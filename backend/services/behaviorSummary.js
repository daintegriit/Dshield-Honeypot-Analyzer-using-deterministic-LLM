// backend/services/behaviorSummary.js
// FEATURE EXTRACTION ONLY
// ---------------------------------------------------------------------
// Goal:
//   Convert raw DShield logs into a compact, structured situation report.
//   This module MUST NOT make final "Attack/Normal" decisions or produce
//   an overall risk score. It only extracts deterministic signals + normalized
//   factors so copilotCore (decision layer) can fuse them.
// This separation ensures the summary is a stable, explainable representation
// of observed behavior, while copilotCore can evolve its reasoning and scoring
// without breaking the summary's consistency or explainability.

const DShieldLog = require("../models/DShieldLogModel");

// -------------------------
// Safe helpers
// -------------------------
function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function safeNumber(x, fallback = 0) {
  const n = Number(x);
  return Number.isFinite(n) ? n : fallback;
}

function toIso(ts) {
  try {
    return new Date(ts).toISOString();
  } catch {
    return null;
  }
}

function isValidDate(d) {
  return d instanceof Date && Number.isFinite(d.getTime());
}

/**
 * Parse a timestamp-like value into epoch ms.
 * Supports:
 *  - Date object
 *  - ISO string
 *  - epoch ms / epoch seconds
 *  - numeric string
 */
function toEpochMs(ts) {
  if (ts == null) return null;

  // Date
  if (ts instanceof Date) return isValidDate(ts) ? ts.getTime() : null;

  // number (ms or seconds)
  if (typeof ts === "number") {
    if (!Number.isFinite(ts)) return null;
    // heuristic: seconds are usually 10 digits; ms are 13+
    if (ts > 0 && ts < 1e12) return Math.round(ts * 1000);
    return Math.round(ts);
  }

  // string
  if (typeof ts === "string") {
    const s = ts.trim();
    if (!s) return null;

    // numeric string
    if (/^\d+(\.\d+)?$/.test(s)) {
      const num = Number(s);
      if (!Number.isFinite(num)) return null;
      if (num > 0 && num < 1e12) return Math.round(num * 1000);
      return Math.round(num);
    }

    // ISO / date parse
    const d = new Date(s);
    return isValidDate(d) ? d.getTime() : null;
  }

  return null;
}

// -------------------------
// Extended Port → Service Labeling
// -------------------------
// Strategy:
//   1) exact known ports
//   2) well-known ranges for categories
//   3) fallback to WELL_KNOWN / REGISTERED / DYNAMIC
//
// Note: labels are for explainability + aggregation, not attribution.
const PORT_LABELS_EXACT = Object.freeze({
  // Remote access / auth
  20: "FTP-DATA",
  21: "FTP",
  22: "SSH",
  23: "TELNET",
  25: "SMTP",
  49: "TACACS",
  53: "DNS",
  67: "DHCP",
  68: "DHCP",
  69: "TFTP",
  79: "FINGER",
  88: "KERBEROS",
  110: "POP3",
  111: "RPCBIND",
  113: "IDENT",
  119: "NNTP",
  123: "NTP",
  135: "MS-RPC",
  137: "NETBIOS-NS",
  138: "NETBIOS-DGM",
  139: "NETBIOS-SSN",
  143: "IMAP",
  161: "SNMP",
  162: "SNMPTRAP",
  179: "BGP",
  389: "LDAP",
  427: "SLP",
  443: "HTTPS",
  445: "SMB",
  465: "SMTPS",
  500: "IKE",
  502: "MODBUS",
  514: "SYSLOG",
  515: "LPD",
  520: "RIP",
  523: "IBM-DB2-ADMIN",
  548: "AFP",
  554: "RTSP",
  563: "NNTPS",
  587: "SMTP-SUBMISSION",
  593: "MS-RPC-HTTP",
  623: "IPMI",
  636: "LDAPS",
  873: "RSYNC",
  902: "VMWARE-AUTH",
  989: "FTPS-DATA",
  990: "FTPS",
  993: "IMAPS",
  995: "POP3S",

  // Web / proxies / alt web
  80: "HTTP",
  81: "HTTP-ALT",
  3000: "DEV-WEB",
  5000: "APP/ALT",
  5173: "VITE-DEV",
  5601: "KIBANA",
  8000: "HTTP-ALT",
  8080: "HTTP-PROXY",
  8081: "HTTP-ALT",
  8443: "HTTPS-ALT",
  8888: "HTTP-ALT",
  9000: "WEB-ALT",
  9090: "WEB-ALT",
  9200: "ELASTIC",
  9300: "ELASTIC-TRANSPORT",

  // Databases / caching
  1433: "MSSQL",
  1521: "ORACLE",
  2049: "NFS",
  2375: "DOCKER-API",
  2376: "DOCKER-TLS",
  2380: "ETCD-PEER",
  2381: "ETCD-METRICS",
  3306: "MYSQL",
  3389: "RDP",
  3625: "TROJAN? (RISKY)",
  5432: "POSTGRES",
  5672: "RABBITMQ",
  5900: "VNC",
  5985: "WINRM",
  5986: "WINRM-SSL",
  6379: "REDIS",
  6443: "K8S-API",
  6667: "IRC",
  7001: "WEBLOGIC",
  7199: "CASSANDRA-JMX",
  7474: "NEO4J",
  7687: "NEO4J-BOLT",
  8008: "HTTP-ALT",
  8086: "INFLUXDB",
  8125: "STATSD",
  8161: "ACTIVEMQ",
  8500: "CONSUL",
  8545: "ETH-RPC",
  8554: "RTSP-ALT",
  8600: "CONSUL-DNS",
  8649: "GANGLIA",
  9042: "CASSANDRA",
  9092: "KAFKA",
  9100: "NODE-EXPORTER",
  11211: "MEMCACHED",
  15672: "RABBITMQ-MGMT",
  27017: "MONGODB",

  // OT/ICS (common)
  102: "S7COMM",
  1911: "TRIDIUM-FOX",
  1962: "PCWORX",
  20000: "DNP3",
  44818: "ETHERNET/IP",
  47808: "BACNET",

  // VPN / tunnels
  1194: "OPENVPN",
  1701: "L2TP",
  1723: "PPTP",
  4500: "IPSEC-NAT-T",
});

function portBucket(port) {
  const p = Number(port);
  if (!Number.isFinite(p) || p <= 0) return "UNKNOWN_PORT";

  if (PORT_LABELS_EXACT[p]) return PORT_LABELS_EXACT[p];

  // Well-known categories/ranges
  if (p >= 0 && p <= 1023) return "WELL_KNOWN";
  if (p >= 1024 && p <= 49151) return "REGISTERED";
  return "DYNAMIC";
}

function portLabel(port) {
  const p = Number(port);
  if (!Number.isFinite(p) || p <= 0) return "UNKNOWN_PORT";
  return PORT_LABELS_EXACT[p] || portBucket(p);
}

// -------------------------
// Entropy helper
// -------------------------
function shannonEntropyFromCounts(countMap) {
  const counts = Object.values(countMap);
  const total = counts.reduce((a, b) => a + b, 0);
  if (total <= 0) return 0;
  let h = 0;
  for (const c of counts) {
    const p = c / total;
    if (p > 0) h -= p * Math.log2(p);
  }
  return h;
}

// -------------------------
// Scan-likeness signals
// -------------------------
function computeScanSignals(events) {
  // events: [{ source_ip, target_port, timestamp_ms }]
  const byIp = new Map();
  for (const e of events) {
    const ip = e.source_ip || "UNKNOWN";
    if (!byIp.has(ip)) byIp.set(ip, []);
    byIp.get(ip).push(e);
  }

  const scanCandidates = [];

  for (const [ip, arr] of byIp.entries()) {
    if (ip === "UNKNOWN") continue;

    const ports = new Set(arr.map((x) => String(x.target_port ?? "")));
    const distinctPorts = ports.size;

    const times = arr
      .map((x) => safeNumber(x.timestamp_ms))
      .filter((t) => t > 0)
      .sort((a, b) => a - b);

    let spanSec = 0;
    if (times.length >= 2) spanSec = (times[times.length - 1] - times[0]) / 1000;

    // Heuristic:
    // - many distinct ports in small time span => scan-y
    // spanFactor compresses long spans; increases when span is tight.
    const spanFactor = spanSec <= 0 ? 1 : 1 / Math.log2(spanSec + 2);

    // Score range 0..20
    const score = clamp(distinctPorts * spanFactor, 0, 20);

    // Candidate thresholds (deterministic)
    if (distinctPorts >= 6 || score >= 4) {
      scanCandidates.push({
        ip,
        totalEvents: arr.length,
        distinctPorts,
        spanSec: Math.round(spanSec),
        scanScore: Number(score.toFixed(2)),
      });
    }
  }

  scanCandidates.sort((a, b) => b.scanScore - a.scanScore);
  return scanCandidates.slice(0, 10);
}

// -------------------------
// Main Summary Builder
// -------------------------
async function buildBehaviorSummary({ minutes = 60, limit = 5000 } = {}) {
  const nowMs = Date.now();
  const windowStartMs = nowMs - minutes * 60 * 1000;

  // Pull recent logs
  const logs = await DShieldLog.find({ timestamp: { $gte: windowStartMs } })
    .sort({ timestamp: -1 })
    .limit(limit)
    .lean();

  // Normalize into events we care about
  const events = logs
    .map((l) => {
      const ts =
        l.timestamp ?? l.time ?? l.createdAt ?? l.ts ?? l.TS ?? null;

      const tsMs = toEpochMs(ts);

      return {
        timestamp_ms: tsMs,
        timestamp_iso: tsMs ? new Date(tsMs).toISOString() : null,

        source_ip: l.source_ip || l.src || l.SRC || null,
        target_ip: l.target_ip || l.dst || l.DST || null,

        target_port: l.target_port ?? l.dpt ?? l.DPT ?? null,
        source_port: l.source_port ?? l.spt ?? l.SPT ?? null,

        protocol: (l.protocol || l.PROTO || "UNKNOWN").toString().toUpperCase(),
        severity: (l.severity || "unknown").toString().toLowerCase(),
        numericSeverity: l.numericSeverity ?? l.severity_score ?? null,

        attack_category: l.attack_category || l.attack_type || "Unknown",

        country: l.country || l.geo?.country || null,
        asn: l.asn || l.geo?.asn || null,
      };
    })
    // keep only events that truly belong to this window by their event timestamp when present
    .filter((e) => (e.timestamp_ms ? e.timestamp_ms >= windowStartMs : true));

  const total = events.length;

  // Aggregations
  const byProtocol = {};
  const byPort = {};
  const byService = {};
  const bySourceIp = {};
  const byAttackCategory = {};
  const bySeverity = {};
  const byCountry = {};
  const byAsn = {};

  let highSeverityCount = 0;

  // Time bucketing (minute bins)
  const bins = new Map(); // key=minuteEpochMs, value=count

  for (const e of events) {
    const proto = String(e.protocol || "UNKNOWN");
    byProtocol[proto] = (byProtocol[proto] || 0) + 1;

    const portKey = e.target_port == null ? "null" : String(e.target_port);
    byPort[portKey] = (byPort[portKey] || 0) + 1;

    const svc = portLabel(e.target_port);
    byService[svc] = (byService[svc] || 0) + 1;

    const ip = e.source_ip || "UNKNOWN";
    bySourceIp[ip] = (bySourceIp[ip] || 0) + 1;

    const cat = String(e.attack_category || "Unknown");
    byAttackCategory[cat] = (byAttackCategory[cat] || 0) + 1;

    const sev = String(e.severity || "unknown");
    bySeverity[sev] = (bySeverity[sev] || 0) + 1;

    if (e.country) byCountry[e.country] = (byCountry[e.country] || 0) + 1;
    if (e.asn) byAsn[String(e.asn)] = (byAsn[String(e.asn)] || 0) + 1;

    const ns = safeNumber(e.numericSeverity, 0);
    if (ns >= 4 || sev === "high" || sev === "critical") highSeverityCount += 1;

    if (e.timestamp_ms && e.timestamp_ms > 0) {
      const minuteKey = Math.floor(e.timestamp_ms / 60000) * 60000;
      bins.set(minuteKey, (bins.get(minuteKey) || 0) + 1);
    }
  }

  function topK(map, k = 10) {
    return Object.entries(map)
      .sort((a, b) => b[1] - a[1])
      .slice(0, k)
      .map(([key, count]) => ({ key, count }));
  }

  // Burst detection: compare latest minute to median minute count in the window
  const binArr = Array.from(bins.entries()).sort((a, b) => a[0] - b[0]);
  const counts = binArr.map(([, c]) => c);
  const sortedCounts = [...counts].sort((a, b) => a - b);
  const median =
    sortedCounts.length === 0
      ? 0
      : sortedCounts[Math.floor(sortedCounts.length / 2)];

  const latestBin = binArr.length ? binArr[binArr.length - 1] : null;
  const latestCount = latestBin ? latestBin[1] : 0;

  const burstRatio =
    median > 0 ? latestCount / median : latestCount > 0 ? 999 : 0;

  // Entropy (spread vs focused)
  const portEntropy = shannonEntropyFromCounts(byPort);
  const srcEntropy = shannonEntropyFromCounts(bySourceIp);

  // Concentration (dominance)
  const topSrc = topK(bySourceIp, 1)[0];
  const topPort = topK(byPort, 1)[0];

  const topSrcPct = total > 0 && topSrc ? topSrc.count / total : 0;
  const topPortPct = total > 0 && topPort ? topPort.count / total : 0;

  // Scan-like offenders
  const scanSignals = computeScanSignals(
    events
      .filter((e) => e.source_ip && e.target_port != null && e.timestamp_ms)
      .map((e) => ({
        source_ip: e.source_ip,
        target_port: e.target_port,
        timestamp_ms: e.timestamp_ms,
      }))
  );

  // -------------------------
  // Normalized factors (0..1)
  // -------------------------
  // These are *inputs* to scoring, not a score.
  const severityFactor = total > 0 ? highSeverityCount / total : 0;

  // Top scan candidate’s scanScore is 0..20 → normalize to 0..1
  const scanFactor =
    scanSignals.length > 0
      ? clamp(scanSignals[0].scanScore / 20, 0, 1)
      : 0;

  // burstRatio can be huge when baseline is 0; compress with log
  const burstFactor = clamp(Math.log2(burstRatio + 1) / 6, 0, 1);

  // Focus = average dominance of top src and top port
  const focusFactor = clamp((topSrcPct + topPortPct) / 2, 0, 1);

  return {
    generatedAt: new Date().toISOString(),

    window: {
      minutes,
      start: toIso(windowStartMs),
      end: toIso(nowMs),
      sampleLimit: limit,
      totalEvents: total,
      minutesWithEvents: binArr.length,
    },

    distributions: {
      protocols: topK(byProtocol, 10),
      ports: topK(byPort, 10).map((x) => ({
        ...x,
        service: portLabel(Number(x.key)),
        bucket: portBucket(Number(x.key)),
      })),
      services: topK(byService, 15),
      severities: topK(bySeverity, 10),
      attackCategories: topK(byAttackCategory, 10),
      countries: topK(byCountry, 10),
      asns: topK(byAsn, 10),
      topSourceIps: topK(bySourceIp, 10),
    },

    signals: {
      // activity shape
      latestMinuteCount: latestCount,
      medianMinuteCount: median,
      burstRatio: Number(burstRatio.toFixed(2)),

      // spread / focus
      portEntropy: Number(portEntropy.toFixed(2)),
      sourceEntropy: Number(srcEntropy.toFixed(2)),
      topSourceIpConcentration: Number(topSrcPct.toFixed(3)),
      topPortConcentration: Number(topPortPct.toFixed(3)),

      // behavioral indicators
      scanCandidates: scanSignals,

      // severity
      highSeverityCount,

      // normalized scoring inputs (0..1)
      normalized: {
        severityFactor: Number(severityFactor.toFixed(3)),
        scanFactor: Number(scanFactor.toFixed(3)),
        burstFactor: Number(burstFactor.toFixed(3)),
        focusFactor: Number(focusFactor.toFixed(3)),
      },
    },
  };
}

// -------------------------
// Multi-window wrapper
// -------------------------
async function buildMultiWindowBehaviorSummary({
  windows = [2, 5, 15, 30, 60],
  limit = 5000,
} = {}) {
  const summaries = {};
  for (const minutes of windows) {
    summaries[`window_${minutes}m`] = await buildBehaviorSummary({ minutes, limit });
  }
  return {
    generatedAt: new Date().toISOString(),
    windows,
    summaries,
  };
}

// -------------------------
// Exports
// -------------------------
module.exports = {
  buildBehaviorSummary,
  buildMultiWindowBehaviorSummary,
  portLabel, // useful for UI/tooling
  portBucket,
};
