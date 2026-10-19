// backend/services/copilotCore.js
// Deterministic intelligence core for Threat Copilot (Multi-Signal / Multi-Attack-Type)
// - Keeps windowed-first logic with lifetime fallback safety net.
//
// EXPERIMENT ISOLATION:
//   buildCopilotCore accepts an optional { sourceFilter } option.
//   When sourceFilter is "replay" (or "honeypot"), every Attack query is scoped
//   to that source, so replayed pcap traffic can be scored in isolation from live
//   honeypot background. When sourceFilter is null/undefined, behavior is
//   unchanged (scores all traffic) — full backward compatibility.


const Attack = require("../models/AttackModel");
const Severity = require("../models/SeverityModel");
const Port = require("../models/PortModel");
const ASN = require("../models/ASNModel");

const CORE_VERSION = "copilotCore-v4.3-dos-burst-only";

/**
 * RISK BUDGET REACHABILITY
 * ---------------------------------------------------------------------------
 * Each risk component has a nominal point budget. A component is REACHABLE in a
 * deployment only if that deployment supplies its inputs. The severity component
 * is driven by events labelled `critical`, and severity is assigned by a
 * target-port heuristic (22/23/445/3389) encoding a HONEYPOT assumption --
 * nothing legitimate touches those ports on a honeypot. Replayed NetFlow corpora
 * do not share that assumption: measured 1,062 critical of 257,646 CTU-13 botnet
 * flows (0.41%), so the component is present in code and ~0 in practice.
 *
 * Scoring against the nominal budget in an environment that cannot supply it
 * yields a ceiling below the state thresholds. That is a units mismatch, not a
 * detection failure.
 *
 * DEPLOYMENT CONFIGURATION, like LOCAL_NETWORKS. Declared per environment and
 * held CONSTANT across every window in a run. Never recompute per window: a
 * window with no critical events would get a smaller denominator and therefore
 * an inflated score, inflating benign windows specifically and manufacturing
 * apparent recall.
 *
 * No value here is chosen by looking at detection results.
 */
const RISK_BUDGET = Object.freeze({
  severity: 25,
  behavior: 20,
  entropy: 20,
  concentration: 15,
  amplifier: 25,
  c2: 20,
  impact: 12,
  coupling: 5,
});

const REACHABILITY_PROFILES = Object.freeze({
  honeypot: {
    severity: true,
    behavior: true,
    entropy: true,
    // Corrected 2026-08-08 after coreConsistency flagged both as declared
    // unreachable while contributing: concentration 2.44, impact 12.00.
    concentration: true,  // falsified (rho = -0.42) but still summed
    amplifier: true,
    c2: true,
    impact: true,
    coupling: false,      // observed zero across every run to date
  },
  netflow: {
    severity: false,      // measured 0.41% critical on CTU-13
    behavior: false,      // auth-port pressure absent
    entropy: true,
    concentration: false,
    amplifier: true,
    c2: true,
    impact: false,
    coupling: false,
  },
});

const RISK_PROFILE = process.env.RISK_PROFILE || "honeypot";
const RISK_NORMALISE = process.env.RISK_NORMALISE === "1";

// ----------------------------
// Config 
// ----------------------------
const CFG = Object.freeze({
  recentLimit: 20000,

  // C2 thresholds
  c2: {
    // Env-overridable for ablation. The default of 30 events per window
    // encodes an implicit minimum traffic RATE that varies with window
    // width: 30/min at a 1-minute window, 6/min at five. Measured
    // consequence: c2Score is zero in every window of seven malware
    // captures delivering 2-18 events/min, which is indistinguishable in
    // the output from having evaluated the traffic and found no C2.
    minEvents: Number(process.env.C2_MIN_EVENTS ?? 30),
    minFlowCount: Number(process.env.C2_MIN_FLOW_COUNT ?? 12),
    dominantFlowRatio: 0.40,  // one flow dominates window
    lowBurstMax: 0.40,        // C2 is usually not bursty like DoS
    maxPortDiversity: 4,      // C2 often reuses same port(s)
    periodicityCvMax: 0.65,   // coefficient of variation for inter-arrivals
    periodicitySpanMinSec: Number(process.env.C2_MIN_SPAN_SEC ?? 90)
  },
});

// ----------------------------
// Helpers 
// ----------------------------
function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function mean(arr) {
  if (!arr || arr.length === 0) return null;
  return arr.reduce((a, b) => a + b, 0) / arr.length;
}

function stddev(arr) {
  if (!arr || arr.length < 2) return null;
  const m = mean(arr);
  const v = arr.reduce((sum, x) => sum + Math.pow(x - m, 2), 0) / (arr.length - 1);
  return Math.sqrt(v);
}

// NOTE: probability-like normalization (not exponential softmax)
function softmaxLike(scoresObj) {
  const entries = Object.entries(scoresObj || {});
  const vals = entries.map(([, v]) => (typeof v === "number" ? v : 0));
  const total = vals.reduce((a, b) => a + b, 0);

  if (total <= 0) {
    const out = {};
    for (const [k] of entries) out[k] = 0;
    return out;
  }

  const out = {};
  for (const [k, v] of entries) out[k] = clamp(v / total, 0, 1);
  return out;
}

function pickTop(scoresObj) {
  const entries = Object.entries(scoresObj || {}).sort((a, b) => b[1] - a[1]);
  if (!entries.length) return { type: "unknown", score: 0 };
  return { type: entries[0][0], score: entries[0][1] };
}

// ----------------------------
// LOCAL / EXTERNAL CLASSIFICATION
// ----------------------------
//
// The C2 detector only inspects flows that CROSS the local<->external boundary,
// because that is where beaconing lives (infected host -> outside C&C server).
// Deciding what counts as "local" is therefore load-bearing: if the boundary is
// wrong, flowMap stays empty and the entire C2 analysis silently does nothing.
//
// BUG THIS FIXES (found 2026-07-15, CTU-13 evaluation):
//   The previous implementation only recognised RFC1918 space. CTU-13 hosts are
//   on 147.32.0.0/16 (CVUT public university addresses), so NO flow ever crossed
//   the boundary. Measured: topFlowCount = 0 on scenarios 1/2/6/9 — the C2
//   detector was structurally disabled, and the resulting "null results" were
//   not measurements of a failing detector, they were measurements of a
//   detector that never ran.
//
// "Local" is a DEPLOYMENT property, not a property of IP ranges:
//   - the live honeypot's local net is 172.31.0.0/16 (RFC1918, fine)
//   - CTU-13's local net is 147.32.0.0/16 (public, needs declaring)
// So it must be configurable, not hardcoded to one dataset.
//
// Configure via env:
//   LOCAL_NETWORKS=147.32.0.0/16,10.0.0.0/8
// RFC1918 + loopback are ALWAYS treated as local regardless of config.
// ----------------------------

/** Parse "a.b.c.d/len" into { base:uint32, mask:uint32 }. Returns null if invalid. */
function parseCidr(cidr) {
  const m = String(cidr).trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/);
  if (!m) return null;

  const octets = [ +m[1], +m[2], +m[3], +m[4] ];
  const len = +m[5];
  if (octets.some((o) => !Number.isInteger(o) || o < 0 || o > 255)) return null;
  if (!Number.isInteger(len) || len < 0 || len > 32) return null;

  // >>> 0 keeps everything unsigned; JS bitwise ops are signed 32-bit.
  const base =
    ((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]) >>> 0;
  const mask = len === 0 ? 0 : (0xffffffff << (32 - len)) >>> 0;

  return { base: (base & mask) >>> 0, mask };
}

/** IPv4 dotted-quad -> uint32. Returns null if not a valid IPv4 literal. */
function ipToUint32(ip) {
  const m = String(ip).trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return null;
  const o = [ +m[1], +m[2], +m[3], +m[4] ];
  if (o.some((x) => !Number.isInteger(x) || x < 0 || x > 255)) return null;
  return ((o[0] << 24) | (o[1] << 16) | (o[2] << 8) | o[3]) >>> 0;
}

// Parsed once at module load. Invalid entries are reported and skipped rather
// than silently ignored — a typo here disables C2 detection, which is exactly
// the failure mode this fix exists to prevent.
const LOCAL_NETWORKS = (() => {
  const raw = process.env.LOCAL_NETWORKS;
  if (!raw) return [];
  const out = [];
  for (const entry of raw.split(",")) {
    const t = entry.trim();
    if (!t) continue;
    const parsed = parseCidr(t);
    if (parsed) {
      out.push({ cidr: t, ...parsed });
    } else {
      console.warn(`⚠️ copilotCore: ignoring invalid LOCAL_NETWORKS entry: "${t}"`);
    }
  }
  if (out.length) {
    console.log(
      `🌐 copilotCore: extra local networks = ${out.map((n) => n.cidr).join(", ")}`
    );
  }
  return out;
})();

/**
 * Is this address on the LOCAL side of the monitored boundary?
 * Always-local: RFC1918 (10/8, 172.16/12, 192.168/16), loopback, 0.0.0.0.
 * Additionally local: anything matching LOCAL_NETWORKS.
 *
 * Name note: this replaces isPrivateIp(). "Private" was the wrong concept —
 * CTU-13's local hosts sit on public address space.
 */
function isLocalIp(ip) {
  if (!ip || typeof ip !== "string") return false;

  // RFC1918 + loopback — always local, config or not.
  if (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    ip.startsWith("127.") ||
    ip === "0.0.0.0"
  ) {
    return true;
  }

  if (LOCAL_NETWORKS.length === 0) return false;

  const addr = ipToUint32(ip);
  if (addr === null) return false;

  for (const net of LOCAL_NETWORKS) {
    if (((addr & net.mask) >>> 0) === net.base) return true;
  }
  return false;
}

// Back-compat alias: older call sites may still say isPrivateIp.
const isPrivateIp = isLocalIp;

function entropyFromCountsMap(m) {
  const total = Array.from(m.values()).reduce((a, b) => a + b, 0);
  if (total <= 0) return 0;
  let h = 0;
  for (const c of m.values()) {
    const p = c / total;
    if (p > 0) h -= p * Math.log2(p);
  }
  return h;
}

function topFromMap(m) {
  const entries = Array.from(m.entries()).sort((a, b) => b[1] - a[1]);
  return entries.length ? { ip: entries[0][0], count: entries[0][1] } : null;
}

function toPortNumber(v) {
  const n = Number(v);
  if (!Number.isFinite(n)) return null;
  if (n <= 0 || n > 65535) return null;
  return n;
}

/**
 * Robust destination-port extraction across schema variants.
 */
function getDstPort(e) {
  if (!e || typeof e !== "object") return null;

  const direct = [
    e.target_port,
    e.dpt,
    e.dst_port,
    e.dest_port,
    e.dstPort,
    e.destPort,
    e.dport,
    e.port,
    e.resp_p,
    e.id_resp_p,
    e["id.resp_p"],
  ];

  for (const v of direct) {
    const p = toPortNumber(v);
    if (p) return p;
  }

  const nestedCandidates = [
    e.id?.resp_p,
    e.id?.orig_p,
    e.conn?.id?.resp_p,
    e.conn?.id?.orig_p,
    e.zeek?.id?.resp_p,
    e.zeek?.id?.orig_p,
  ];

  for (const v of nestedCandidates) {
    const p = toPortNumber(v);
    if (p) return p;
  }

  return null;
}

function getSrcIp(e) {
  return (
    e?.src ||
    e?.source_ip ||
    e?.SRC ||
    e?.id?.orig_h ||
    e?.conn?.id?.orig_h ||
    e?.zeek?.id?.orig_h ||
    null
  );
}

function getDstIp(e) {
  return (
    e?.dst ||
    e?.target_ip ||
    e?.DST ||
    e?.id?.resp_h ||
    e?.conn?.id?.resp_h ||
    e?.zeek?.id?.resp_h ||
    null
  );
}

function getProto(e) {
  const p = (e?.proto || e?.protocol || e?.PROTO || "").toString().toUpperCase();
  return p || "UNKNOWN";
}

function getBytes(e) {
  const v =
    e?.bytes ??
    e?.orig_bytes ??
    e?.resp_bytes ??
    e?.conn?.orig_bytes ??
    e?.conn?.resp_bytes ??
    null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

function getTsMs(e) {
  // Prefer event_time (true event time from TS=) when present, else timestamp.
  const t = e?.event_time ?? e?.timestamp;
  if (t instanceof Date) return Number.isFinite(t.getTime()) ? t.getTime() : null;
  const d = new Date(t);
  return Number.isFinite(d.getTime()) ? d.getTime() : null;
}

// coefficient of variation
function coeffOfVariation(arr) {
  if (!arr || arr.length < 3) return null;
  const m = mean(arr);
  if (!m || m <= 0) return null;
  const s = stddev(arr);
  if (s == null) return null;
  return s / m;
}

function buildAttackIndicators({
  dominantAttack,
  scanCandidates,
  authPortPressure,
  webPortPressure,
  dbPortPressure,
  c2Signals,
  attacksLast5Min,
  burstRatio5mOverHour,
  criticalCount,
}) {
  const indicators = {
    highVolumeDetected: attacksLast5Min >= 25,
    burstDetected: burstRatio5mOverHour > 0.35,
    scanningDetected: dominantAttack.type === "scan" || scanCandidates.length > 0,
    webInfrastructureTargeting: (webPortPressure || 0) > 100,
    authenticationTargeting: (authPortPressure || 0) > 50,
    databaseTargeting: (dbPortPressure || 0) > 50,
    c2BehaviorDetected:
      dominantAttack.type === "c2" ||
      c2Signals.topFlowCount >= 12 ||
      c2Signals.dominantFlowRatio >= 0.4,
    severityEscalationDetected: criticalCount > 0,
  };

  const evidenceScore = Object.values(indicators).filter(Boolean).length;

  return {
    indicators,
    evidenceScore,
  };
}

function buildAttackExplanation({
  dominantAttack,
  attackTypeScores,
  topPorts,
  authPortPressure,
  webPortPressure,
  dbPortPressure,
  scanCandidates,
  c2Signals,
  attacksLast5Min,
  burstRatio5mOverHour,
}) {

  const reasons = [];

  if (dominantAttack.type === "dos") {

    if (attacksLast5Min > 100) {
      reasons.push(
        `High short-term attack volume detected with ${attacksLast5Min} attacks observed in the last 5 minutes.`
      );
    }

    if (burstRatio5mOverHour > 0.35) {
      reasons.push(
        `Traffic burst ratio exceeded normal baseline behavior, indicating concentrated attack activity.`
      );
    }
  }

  if (dominantAttack.type === "scan") {

    if (scanCandidates.length > 0) {
      reasons.push(
        `Multiple destination ports are receiving repeated connection attempts, consistent with reconnaissance or scanning activity.`
      );
    }

    reasons.push(
      `Elevated port entropy indicates broad service enumeration behavior.`
    );
  }

  if (dominantAttack.type === "brute_force") {

    if (authPortPressure > 0) {
      reasons.push(
        `Authentication-focused ports such as SSH, Telnet, or RDP are under concentrated targeting pressure.`
      );
    }
  }

  if (dominantAttack.type === "web_probe") {

    if (webPortPressure > 0) {
      reasons.push(
        `Web-facing infrastructure ports are receiving abnormal request concentration.`
      );
    }

    const topWebPort = topPorts.find(p =>
      [80,443,8080,8443,8000,8888].includes(p.port)
    );

    if (topWebPort) {
      reasons.push(
        `Port ${topWebPort.port} is currently one of the dominant targeted web services in the active observation window.`
      );
    }
  }

  if (dominantAttack.type === "c2") {

    if (c2Signals.topFlowCount >= 12) {
      reasons.push(
        `Repeated communication between the same source and destination pair suggests persistent beaconing behavior.`
      );
    }

    if (c2Signals.periodicityCv !== null &&
        c2Signals.periodicityCv < 0.65) {

      reasons.push(
        `Low inter-arrival timing variation indicates potentially automated command-and-control communication patterns.`
      );
    }

    if (c2Signals.dominantFlowRatio > 0.40) {
      reasons.push(
        `One communication flow dominates the active window, which is consistent with centralized remote-control behavior.`
      );
    }
  }

  if (reasons.length === 0) {
    reasons.push(
      `Behavioral indicators remain inconclusive despite elevated telemetry activity.`
    );
  }

  return reasons;
}

// Prose gated on the same determinations as attackIndicators, not on separate
// magnitude thresholds. Previously these diverged: the scanning sentence fired
// on entropyComponent >= 12 while attackIndicators.scanningDetected is
// (dominantAttack.type === "scan" || scanCandidates.length > 0). Entropy
// saturates at its 20-point cap in ~98% of windows, so the report asserted
// scanning behaviour in prose while denying it in the boolean, in the same
// object. Thresholds are not retuned here -- retuning would mean choosing
// constants from observed values, which is fitting. Consistency is structural
// instead.
function buildRiskExplanation({
  indicators,
  riskScore,
  severityComponent,
  behaviorComponent,
  entropyComponent,
  concentrationComponent,
  signalAmplifier,
  c2Bonus,
  impactBonus,
  couplingBonus,
}) {

  const reasons = [];

  // v4.0: volume no longer contributes to risk (it saturated and measured
  // event rate rather than threat). Entropy and concentration replace it.
  if (indicators && indicators.scanningDetected) {
    reasons.push(
      `Traffic is distributed across a wide range of destination ports, consistent with enumeration or scanning behaviour.`
    );
  }

  if (concentrationComponent >= 10) {
    reasons.push(
      `Communication is concentrated among a small number of peers, indicating focused rather than diffuse activity.`
    );
  }

  if (indicators && indicators.severityEscalationDetected) {
    reasons.push(
      `Critical and high severity events materially increased overall system risk.`
    );
  }

  if (indicators && indicators.authenticationTargeting) {
    reasons.push(
      `Behavioral targeting against sensitive service categories increased risk weighting.`
    );
  }

  if (signalAmplifier >= 8) {
    reasons.push(
      `Strong behavioral attack signatures amplified confidence in malicious activity classification.`
    );
  }

  if (c2Bonus > 0) {
    reasons.push(
      `Command-and-control behavioral indicators contributed additional escalation pressure to the overall risk score.`
    );
  }

  // Was impactBonus > 0, which fired on values as small as 0.02 out of 12.
  if (impactBonus >= 1) {
    reasons.push(
      `Observed attack severity and operational impact indicators increased escalation confidence.`
    );
  }

  if (couplingBonus > 0) {
    reasons.push(
      `Simultaneous high-volume and targeted behavioral activity produced compound escalation effects.`
    );
  }

  if (riskScore >= 85) {
    reasons.push(
      `Overall threat posture reached critical operational risk levels.`
    );
  }

  return reasons;
}

function buildConfidenceExplanation({
  confidenceNumeric,
  attackConfidence,
  evidenceScore,
  dominantAttack,
  riskScore,
}) {
  return {
    level: attackConfidence,
    numeric: Number(confidenceNumeric.toFixed(2)),
    evidenceScore,
    explanation:
      attackConfidence === "high"
        ? "Multiple independent behavioral indicators align with elevated operational risk and the dominant attack classification."
        : attackConfidence === "moderate"
        ? "Several behavioral indicators support the detected classification, though not all escalation signals are active."
        : "Observed telemetry contains limited or mixed behavioral evidence.",
    basis: {
      dominantAttackType: dominantAttack.type,
      dominantAttackScore: Number(dominantAttack.score.toFixed(2)),
      riskScore,
      evidenceScore,
    },
  };
}


// ----------------------------
// Core Builder Function
// ----------------------------
// options:
//   minutes      - window size in minutes (default 60)
//   sourceFilter - "replay" | "honeypot" | null. When set, ALL Attack queries are
//                  scoped to that source (experiment isolation). Default null =
//                  score everything (original behavior, fully backward-compatible).
//   windowEnd    - Date|string|null. When set, the core scores the window ENDING
//                  at this instant instead of "now". This makes historical /
//                  offline analysis possible: an analyzer can walk a past replay
//                  and score each window with the SAME production code path.
//                  Default null = score up to now (original behavior).
//
// NOTE ON BOUNDS: when windowEnd is supplied every time-scoped Attack query is
// bounded on BOTH sides ($gte ... $lte windowEnd). Without the upper bound a
// historical window would silently include every document recorded after it.
async function buildCopilotCore({ minutes = 60, sourceFilter = null, windowEnd = null } = {}) {
  const isHistorical = windowEnd != null;
  const anchor = isHistorical ? new Date(windowEnd) : new Date();

  if (isHistorical && !Number.isFinite(anchor.getTime())) {
    throw new Error(`buildCopilotCore: invalid windowEnd: ${windowEnd}`);
  }

  const nowMs = anchor.getTime();
  const oneMinuteAgo = new Date(nowMs - 1 * 60 * 1000);
  const fiveMinutesAgo = new Date(nowMs - 5 * 60 * 1000);
  const fifteenMinutesAgo = new Date(nowMs - 15 * 60 * 1000);
  const oneHourAgo = new Date(nowMs - 60 * 60 * 1000);
  const windowStart = new Date(nowMs - minutes * 60 * 1000);

  // Upper bound applied only in historical mode (live mode stays open-ended so
  // behaviour is byte-for-byte identical to before).
  const upperBound = isHistorical ? { $lte: anchor } : {};

  // POSITIVE-CONTROL OPTIONS (default off; defaults reproduce v4.3 exactly).
  //   SCORE_TIME_FIELD=event_time  scope windows on the true event time parsed
  //                                from TS=, instead of ingest arrival time.
  //   CORE_SCOPE_PCAP=<name>       scope every Attack query to one replay, so no
  //                                other run's traffic can enter the lookback.
  const TIME_FIELD = process.env.SCORE_TIME_FIELD === "event_time" ? "event_time" : "timestamp";
  const SCOPE_PCAP = process.env.CORE_SCOPE_PCAP || null;

  // Time-scoping helper: builds a { <TIME_FIELD>: { $gte, [$lte] } } clause.
  const tsRange = (from) => ({ [TIME_FIELD]: { $gte: from, ...upperBound } });

  // Source-scoping helper: merge a { source } clause into any Attack filter when
  // sourceFilter is set. No-op when sourceFilter is null.
  const withSource = (filter) => {
    let f = sourceFilter ? { ...filter, source: sourceFilter } : filter;
    if (SCOPE_PCAP) f = { ...f, replay_pcap: SCOPE_PCAP };
    return f;
  };


  // ==================================================
  // 1) ATTACK VOLUME SIGNALS (for DoS and general threat level)
  // ==================================================
  const [attacksLast1Min, attacksLast5Min, attacksLast15Min, attacksLastHour] = await Promise.all([
    Attack.countDocuments(withSource(tsRange(oneMinuteAgo))),
    Attack.countDocuments(withSource(tsRange(fiveMinutesAgo))),
    Attack.countDocuments(withSource(tsRange(fifteenMinutesAgo))),
    Attack.countDocuments(withSource(tsRange(oneHourAgo))),
  ]);

  const burstRatio5mOverHour = attacksLastHour > 0 ? attacksLast5Min / attacksLastHour : 0;

  // PAPER-2 CHANGE 2 (default off; unset reproduces the positive-control core).
  //   DOS_EXPECT_AVAILABLE=1  the DoS burst expectation is the share a uniform
  //   stream would put in the last 5 minutes of the history actually available,
  //   min(5,T)/min(60,T), T = minutes since the first event in scope. For
  //   T >= 60 the deployed constant 0.083 is kept unchanged, so no window that
  //   ends an hour or more after its stream starts can change.
  let dosExpected = 0.083;
  let dosHistoryMin = null;
  if (process.env.DOS_EXPECT_AVAILABLE === "1") {
    const first = await Attack.findOne(withSource({ [TIME_FIELD]: { $ne: null, ...upperBound } }))
      .sort({ [TIME_FIELD]: 1 })
      .select({ [TIME_FIELD]: 1 })
      .lean();
    if (first && first[TIME_FIELD]) {
      dosHistoryMin = (nowMs - new Date(first[TIME_FIELD]).getTime()) / 60000;
      if (dosHistoryMin < 60) {
        const T = Math.max(dosHistoryMin, 1e-6);
        dosExpected = Math.min(5, T) / Math.min(60, T);
      }
    }
  }
  const burstRatio15mOverHour = attacksLastHour > 0 ? attacksLast15Min / attacksLastHour : 0;

  // ==================================================
  // 2) LIFETIME CONTEXT (for stability + fallback, and also important signals like top ports and services)
  // ==================================================
  const AUTH_PORTS = new Set([22, 23, 2222, 2223, 3389, 5900]);
  const WEB_PORTS = new Set([80, 443, 8000, 8080, 8443, 8888, 9000, 9443]);
  const DB_PORTS = new Set([1433, 1521, 27017, 3306, 5432, 6379, 9200, 11211]);

  const topPortsLifetime = await Port.find({}).sort({ count: -1 }).limit(10).lean();

  let authPortPressureLifetime = 0;
  let webPortPressureLifetime = 0;
  let dbPortPressureLifetime = 0;

  for (const p of topPortsLifetime) {
    const port = toPortNumber(p?.port);
    const count = Number(p?.count || 0);
    if (!port || !Number.isFinite(count)) continue;
    if (AUTH_PORTS.has(port)) authPortPressureLifetime += count;
    if (WEB_PORTS.has(port)) webPortPressureLifetime += count;
    if (DB_PORTS.has(port)) dbPortPressureLifetime += count;
  }

  let portEntropyLifetime = 0;
  const totalLifetime = topPortsLifetime.reduce((s, p) => s + Number(p?.count || 0), 0);
  if (totalLifetime > 0) {
    for (const p of topPortsLifetime) {
      const c = Number(p?.count || 0);
      const prob = c / totalLifetime;
      if (prob > 0) portEntropyLifetime -= prob * Math.log2(prob);
    }
  }

  const severities = await Severity.find({}).lean();
  const criticalTotal = severities.find((s) => s.level === "critical")?.count || 0;
  const highTotal = severities.find((s) => s.level === "high")?.count || 0;
  const mediumTotal = severities.find((s) => s.level === "medium")?.count || 0;

  // ==================================================
  // 3) ASN CONTEXT (LIFETIME TOP ASN, as a proxy for attacker profile and potential risk)
  // ==================================================
  const topASN = await ASN.findOne({}).sort({ count: -1 }).lean();

  // ==================================================
  // 4) WINDOWED EVENTS
  // ==================================================
  const recentEvents = await Attack.find(
    withSource(tsRange(windowStart)),
    {
      timestamp: 1,
      event_time: 1,
      source: 1,
      src: 1,
      dst: 1,
      dpt: 1,
      proto: 1,
      bytes: 1,
      severity: 1,

      // schema variants 
      source_ip: 1,
      target_ip: 1,
      port: 1,         
      source_port: 1, 
      protocol: 1,
      dst_port: 1,
      dest_port: 1,
      dstPort: 1,
      id: 1,
      conn: 1,
      zeek: 1,
      orig_bytes: 1,
      resp_bytes: 1,
    }
  )
    .sort({ [TIME_FIELD]: 1 })
    .limit(CFG.recentLimit)
    .lean();

  // ---- Windowed severity counts (for impact scoring) ----
  let criticalCount = 0;
  let highCount = 0;
  let mediumCount = 0;

  for (const e of recentEvents) {
    if (e?.severity === "critical") criticalCount++;
    else if (e?.severity === "high") highCount++;
    else if (e?.severity === "medium") mediumCount++;
  }

  // ---- Windowed bytes stats
  const bytesArr = recentEvents.map(getBytes).filter((v) => typeof v === "number");
  const bytesMean = mean(bytesArr);
  const bytesStd = stddev(bytesArr);

  // ---- Windowed port counts (for top ports, scan candidates, and port entropy)
  const portCountsWindowed = new Map();
  let missingPortCount = 0;

  for (const e of recentEvents) {
    const port = getDstPort(e);
    if (!port) {
      missingPortCount++;
      continue;
    }
    portCountsWindowed.set(port, (portCountsWindowed.get(port) || 0) + 1);
  }

  const topPortsWindowed = Array.from(portCountsWindowed.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([port, count]) => ({ port, count }));

  const topPortsForOutput = topPortsWindowed.length ? topPortsWindowed : topPortsLifetime;

  // Windowed scan candidates (simple + deterministic)
  const scanCandidatesWindowed = topPortsWindowed
    .filter((p) => p.count > 20)
    .map((p) => ({ port: p.port, count: p.count }));

  // Windowed port pressures
  let authPortPressureWindowed = 0;
  let webPortPressureWindowed = 0;
  let dbPortPressureWindowed = 0;

  for (const { port, count } of topPortsWindowed) {
    if (AUTH_PORTS.has(port)) authPortPressureWindowed += count;
    if (WEB_PORTS.has(port)) webPortPressureWindowed += count;
    if (DB_PORTS.has(port)) dbPortPressureWindowed += count;
  }

  // Windowed port entropy
  let portEntropyWindowed = 0;
  const totalWindowedPorts = Array.from(portCountsWindowed.values()).reduce((a, b) => a + b, 0);
  if (totalWindowedPorts > 0) {
    for (const c of portCountsWindowed.values()) {
      const p = c / totalWindowedPorts;
      if (p > 0) portEntropyWindowed -= p * Math.log2(p);
    }
  }

  // ---- Src counts + peer counts for entropy (fallback-safe)
  const srcCounts = new Map();
  const peerCounts = new Map();

  for (const e of recentEvents) {
    const src = getSrcIp(e);
    const dst = getDstIp(e);

    if (src) srcCounts.set(src, (srcCounts.get(src) || 0) + 1);

    if (!src || !dst) continue;
    const srcPriv = isPrivateIp(src);
    const dstPriv = isPrivateIp(dst);

    if (srcPriv && !dstPriv) peerCounts.set(dst, (peerCounts.get(dst) || 0) + 1);
    else if (!srcPriv && dstPriv) peerCounts.set(src, (peerCounts.get(src) || 0) + 1);
  }

  const topSourceIp = topFromMap(srcCounts);
  const topExternalPeerIp = topFromMap(peerCounts);
  const sourceEntropy = entropyFromCountsMap(peerCounts.size ? peerCounts : srcCounts);

  // ==================================================
  // 4.5) C2 SIGNALS (WINDOWED, deterministic, explainable)
  // ==================================================
  // Build flow stats for private→external / external→private pairs
  const flowMap = new Map(); // key = `${src}->${dst}`, value = { count, times[] , portsSet }
  const windowPortsSet = new Set();

  for (const e of recentEvents) {
    const src = getSrcIp(e);
    const dst = getDstIp(e);
    if (!src || !dst) continue;

    const srcPriv = isPrivateIp(src);
    const dstPriv = isPrivateIp(dst);

    // focus on cross-boundary flows (most useful for C2)
    const crossesBoundary = (srcPriv && !dstPriv) || (!srcPriv && dstPriv);
    if (!crossesBoundary) continue;

    const ts = getTsMs(e);
    const dpt = getDstPort(e);
    if (dpt) windowPortsSet.add(dpt);

    const key = `${src}->${dst}`;
    if (!flowMap.has(key)) flowMap.set(key, { count: 0, times: [], ports: new Set() });

    const v = flowMap.get(key);
    v.count += 1;
    if (ts) v.times.push(ts);
    if (dpt) v.ports.add(dpt);
  }

  // Find top flow
  let topFlowKey = null;
  let topFlow = null;
  for (const [k, v] of flowMap.entries()) {
    if (!topFlow || v.count > topFlow.count) {
      topFlowKey = k;
      topFlow = v;
    }
  }

  const flowTotal = Array.from(flowMap.values()).reduce((s, v) => s + v.count, 0);
  const dominantFlowRatio = flowTotal > 0 && topFlow ? topFlow.count / flowTotal : 0;

  // Beaconing / periodicity from inter-arrival times (seconds)
  let periodicityCv = null;
  let periodicitySpanSec = 0;

  if (topFlow && topFlow.times && topFlow.times.length >= 4) {
    const times = [...topFlow.times].sort((a, b) => a - b);
    periodicitySpanSec = (times[times.length - 1] - times[0]) / 1000;

    const deltas = [];
    for (let i = 1; i < times.length; i++) {
      const d = (times[i] - times[i - 1]) / 1000;
      if (d > 0) deltas.push(d);
    }

    periodicityCv = coeffOfVariation(deltas); // lower = more periodic
  }

  const portDiversity = windowPortsSet.size;

  // Convert these to a C2 score (0..100), with gated conditions
  const c2Signals = {
    topFlowKey,
    topFlowCount: topFlow?.count || 0,
    dominantFlowRatio: Number(dominantFlowRatio.toFixed(3)),
    periodicityCv: periodicityCv == null ? null : Number(periodicityCv.toFixed(3)),
    periodicitySpanSec: Math.round(periodicitySpanSec),
    portDiversity,
    lowBurst: burstRatio5mOverHour <= CFG.c2.lowBurstMax,
  };

  // Gate: only consider C2 if enough data exists
  let c2Score = 0;
  if (recentEvents.length >= CFG.c2.minEvents && topFlow) {
    const condFlowCount = topFlow.count >= CFG.c2.minFlowCount ? 1 : 0;
    const condDominant = dominantFlowRatio >= CFG.c2.dominantFlowRatio ? 1 : 0;
    const condLowBurst = c2Signals.lowBurst ? 1 : 0;
    const condLowPorts = portDiversity > 0 && portDiversity <= CFG.c2.maxPortDiversity ? 1 : 0;

    // periodicity: low CV + enough span
    const condPeriodic =
      periodicityCv != null &&
      periodicityCv <= CFG.c2.periodicityCvMax &&
      periodicitySpanSec >= CFG.c2.periodicitySpanMinSec
        ? 1
        : 0;

    // Weighted, explainable scoring.
    //
    // C2_REQUIRE_PERIODIC=1 makes periodicity necessary rather than one of
    // five additive terms. Measured motivation: on four hours of benign
    // workstation traffic, a chat client maintaining 865 flows to a single
    // peer satisfied flow count, dominance, low burst and low port diversity
    // and scored 75 -- above the 40-point contribution threshold -- while its
    // inter-arrival coefficient of variation was 18.4 against a 0.65
    // threshold. The one condition distinguishing automated beaconing from
    // human-driven application traffic was neither necessary nor sufficient.
    const requirePeriodic = process.env.C2_REQUIRE_PERIODIC === "1";
    c2Score = (requirePeriodic && !condPeriodic)
      ? 0
      : clamp(
          (condFlowCount ? 25 : 0) +
            (condDominant ? 25 : 0) +
            (condPeriodic ? 25 : 0) +
            (condLowBurst ? 15 : 0) +
            (condLowPorts ? 10 : 0),
          0,
          100
        );
  }

  // ==================================================
  // 5) COHERENT OUTPUT SIGNALS (WINDOWED PRIMARY, LIFETIME FALLBACK)
  // ==================================================
  const authPortPressure = topPortsWindowed.length ? authPortPressureWindowed : null;
  const webPortPressure = topPortsWindowed.length ? webPortPressureWindowed : null;
  const dbPortPressure = topPortsWindowed.length ? dbPortPressureWindowed : null;

  const portEntropy = attacksLast5Min === 0 ? 0 : portEntropyWindowed;
  const scanCandidates = topPortsWindowed.length ? scanCandidatesWindowed : [];

  // ==================================================
  // 6) ATTACK TYPE SCORES
  // ==================================================
  // ------------------------------------------------------------------
  // v4.1: dosScore made rate-independent.
  //
  // WHY: the v3.x/v4.0 form was
  //   min(60, log10(attacksLast5Min+1)*20) + burst terms
  // The log10 term reaches its 60-point cap at ~1,000 events in the window,
  // i.e. under any realistic load. Measured on CTU-13 s1 it saturated in
  // 100% of windows, so pickTop() returned "dos" for every single window at
  // every window size (1/5/15 min) across BOTH v3.7 and v4.0 runs. The
  // attack-type table was therefore uninformative by construction: no other
  // behavioural class could ever win.
  //
  // Volume is not evidence of denial-of-service. A DoS is characterised by
  // traffic CONCENTRATED on a target with an abnormal burst shape — both of
  // which are ratios, not counts.
  //
  // KNOWN LIMITATION (do not paper over this): burstRatio5mOverHour is
  // structurally ~0.083 (5/60) under a constant-rate replay, so this score
  // stays low and flat in the current harness. That is correct behaviour —
  // a constant-rate replay contains no bursts. It means DoS detection is NOT
  // measurable with the present replay methodology; testing it requires
  // preserving the original inter-arrival timing.
  // ------------------------------------------------------------------
  // ------------------------------------------------------------------
  // v4.3: the CONCENTRATION terms are removed from dosScore.
  //
  // WHY (measured, not assumed). The v4.1 form added:
  //     min(30, topPortShare * 30)                 // target concentration
  //   + min(20, (1 - srcEntropyNorm) * 20)         // source concentration
  //
  // Both reward CONCENTRATION. Measured against CTU-13 ground truth with the
  // C2 detector functional (v4.2), mean dosScore on malicious vs benign
  // windows:
  //     scenario 9 (n=100):  malicious 25.17  benign 68.19   delta -43.02
  //     scenario 2 (n=55) :  malicious 35.69  benign 53.36   delta -17.67
  // i.e. dosScore scored BENIGN traffic ~43 points HIGHER than malicious
  // traffic, in both scenarios. It was the strongest signal in the system and
  // it pointed the wrong way.
  //
  // The reason: normal CVUT user traffic concentrates (port 80/443, few peers),
  // while the botnet sprays across many ports/peers. So "concentration" is a
  // marker of NORMAL traffic here, not attack traffic. This is the same
  // hypothesis that was already falsified once, in v4.0's
  // concentrationComponent (rho = -0.42 on scenario 1 at 5-min windows). It was
  // wrong there and it is wrong here.
  //
  // This mattered beyond dosScore itself: strongestSignal = max(dos, scan, c2,
  // ...) feeds signalAmplifier, so an inverted dosScore of ~68 on benign
  // windows meant the amplifier was firing on NORMAL traffic.
  //
  // What remains is burst deviation only — the one property that actually
  // characterises denial-of-service, and a ratio rather than a count.
  //
  // HONEST CONSEQUENCE: under a constant-rate replay burstRatio5mOverHour is
  // structurally ~0.083 (5/60), so dosScore ~= 0 in every window. That is
  // CORRECT — these captures contain no DoS and a constant-rate replay contains
  // no bursts. dosScore now abstains instead of guessing backwards. Testing DoS
  // detection requires a replay that preserves original inter-arrival timing.
  // ------------------------------------------------------------------
  const dosScore = clamp(
    // Burst shape: fraction of the hour's traffic landing in the last 5 min.
    // Uniform traffic gives 5/60 = 0.083 -> 0 points. A real burst pushes it up.
    Math.min(100, Math.max(0, burstRatio5mOverHour - dosExpected) * 150),
    0,
    100
  );

  const scanScore =
    attacksLast5Min === 0
      ? 0
      : clamp(
          Math.min(60, scanCandidates.length * 15) +
          Math.min(25, portEntropyWindowed * 8),
          0,
          100
        );

  const bruteForceScore = clamp(
    Math.min(70, (authPortPressure || 0) / 50),
    0,
    100
  );

  const webProbeScore = clamp(Math.min(70, (webPortPressure || 0) / 80), 0, 100);

  const impactScore = clamp(
    Math.min(70, criticalCount / 20) + Math.min(30, highCount / 50),
    0,
    100
  );

  const attackTypeScores = {
    dos: dosScore,
    scan: scanScore,
    brute_force: bruteForceScore,
    web_probe: webProbeScore,
    c2: c2Score,
    impact: impactScore,
  };

  // ------------------------------------------------------------------
  // v4.0 FIX: `impact` is a SEVERITY AGGREGATE (criticalCount/highCount),
  // not a behaviour. Letting it compete in the type vote means a severity
  // measure can be reported as the "dominant attack type", which is a
  // category error. It stays in attackTypeScores for reporting, but only
  // behavioural classes are eligible to be the dominant attack.
  // ------------------------------------------------------------------
  const behaviouralScores = {
    dos: dosScore,
    scan: scanScore,
    brute_force: bruteForceScore,
    web_probe: webProbeScore,
    c2: c2Score,
  };

  const attackTypeProbabilities = softmaxLike(attackTypeScores);
  const dominantAttack = pickTop(behaviouralScores);

  // ==================================================
  // 7) RISK FABRIC
  // ==================================================

  // ------------------------------------------------------------------
  // v4.0 RISK FABRIC — RATE-INDEPENDENT
  // ------------------------------------------------------------------
  // WHY THIS CHANGED (evidence, not preference):
  //
  // The v3.x volume component was:
  //     volumeAbs = clamp(max(attacksLast1Min*2, attacksLast5Min/2), 0, 60)
  //     volumeRel = clamp(burstRatio5mOverHour * 80, 0, 60)
  //     volumeComponent = max(volumeAbs, volumeRel)
  //
  // volumeAbs saturates at its 60-point cap whenever attacksLast1Min >= 30,
  // i.e. under essentially any real traffic load. Measured against CTU-13
  // scenario 1 (71,348 hand-labeled flows), this produced:
  //     separation margin  +1.37 (1m) / -2.28 (5m) / -0.22 (15m)
  //     rho(risk, botnet_fraction)  +0.08 / -0.21 / -0.21
  //     FPR 1.0, TN 0, balanced accuracy 0.50 at every window size
  // The score was a near-constant measuring event RATE, not threat.
  //
  // Volume cannot separate malicious from benign traffic when both arrive at
  // similar rates -- which is the normal case (CTU-13 s1 is 57% botnet /
  // 43% normal, interleaved). It is retained as reported CONTEXT
  // (attackMetrics) but no longer contributes to risk.
  //
  // The only v3.x component that tracked ground truth was c2Score
  // (mean 9.81 when labeled C&C present vs 0.00 when absent, zero false
  // fires). It works because it is built on RATIOS AND SHAPES
  // (dominantFlowRatio, periodicityCv, portDiversity) rather than counts.
  // v4.0 generalises that principle.
  //
  // WEIGHT DERIVATION (NOT fitted to the evaluation set):
  // Each feature is normalised by its own theoretical range, then given a
  // point budget summing to 100. No constant here was chosen by looking at
  // CTU-13 results.
  // ------------------------------------------------------------------

  // Volume is CONTEXT now, not risk. Kept for reporting/telemetry only.
  const volumeComponent = 0;

  // --- Severity: proportion of the window that is critical, not the count.
  // Rate-independent: 50 critical of 100 events is worse than 50 of 100,000.
  const windowEventCount = recentEvents.length;
  const criticalRatio = windowEventCount > 0 ? criticalCount / windowEventCount : 0;
  const severityComponent = clamp(criticalRatio * 25, 0, 25);

  // --- Behaviour: proportion of window traffic hitting auth services.
  // Previously an absolute count (authPortPressure/150) which scaled with load.
  const authRatio =
    totalWindowedPorts > 0 ? (authPortPressureWindowed || 0) / totalWindowedPorts : 0;
  const behaviorComponent = clamp(authRatio * 20, 0, 20);

  // --- Port entropy: computed since v3.x and NEVER used in the risk score.
  // Shannon entropy over destination ports. Max entropy for k ports is
  // log2(k); with the 10-port view used here the ceiling is log2(10) ~ 3.32.
  // Normalise against that ceiling rather than an arbitrary divisor.
  // HIGH entropy => traffic sprayed across many ports => scan-like.
  const PORT_ENTROPY_CEILING = Math.log2(10);
  const portEntropyNorm =
    PORT_ENTROPY_CEILING > 0 ? clamp(portEntropyWindowed / PORT_ENTROPY_CEILING, 0, 1) : 0;
  const entropyComponent = clamp(portEntropyNorm * 20, 0, 20);

  // --- Peer concentration: computed since v3.x and NEVER used in risk.
  // LOW source entropy => few peers dominate => focused/targeted behaviour.
  // Inverted deliberately: concentration is the signal, not diversity.
  const SOURCE_ENTROPY_CEILING = Math.log2(50);
  const srcEntropyNorm =
    SOURCE_ENTROPY_CEILING > 0 ? clamp(sourceEntropy / SOURCE_ENTROPY_CEILING, 0, 1) : 0;
  // Zero sources is not maximal concentration. With no events,
  // sourceEntropy is 0, so (1 - 0) * 15 awarded this component its full
  // budget on an empty window: measured 2026-08-09, a window with zero
  // events scored 15 raw and 23 normalised, entirely from this term.
  const hasSources = (peerCounts.size || srcCounts.size) > 0;
  const concentrationComponent = hasSources
    ? clamp((1 - srcEntropyNorm) * 15, 0, 15)
    : 0;

  // --------------------------------------------------
  // 1. Primary Behavioral Signals
  // --------------------------------------------------

  const strongestSignal = Math.max(
    attackTypeScores.c2,
    attackTypeScores.dos,
    attackTypeScores.scan,
    attackTypeScores.web_probe,
    attackTypeScores.brute_force,
    attackTypeScores.impact
  );

  // --------------------------------------------------
  // 2. Signal Amplifier (Scaled, gated)
  // --------------------------------------------------

  let signalAmplifier = 0;

  // Mild boost if signal is strong even when volume is modest
  if (strongestSignal >= 45) {
    // scale 45..100 -> 0..15
    signalAmplifier = clamp(((strongestSignal - 45) / 55) * 15, 0, 15);
  }

  // Extra boost only when BOTH signal and volume are strong
  if (strongestSignal >= 60 && attacksLast5Min >= 20) {
    // additional 0..10
    signalAmplifier += clamp(((strongestSignal - 60) / 40) * 10, 0, 10);
  }


  // --------------------------------------------------
  // 3. C2 Specific Boost (malware should matter)
  // --------------------------------------------------

  let c2Bonus = 0;

  // Second gate, independent of CFG.c2.minEvents. c2Score can be computed
  // and still contribute nothing: measured on 284-1 at 5-minute windows,
  // c2 = 25 with c2Bonus = 0. Note the discontinuity -- c2 = 39 gives 0,
  // c2 = 40 gives 10, half the bonus range appearing at a single step.
  if (attackTypeScores.c2 >= Number(process.env.C2_BONUS_MIN_SCORE ?? 40)) {
    // allow C2 to directly influence risk
    c2Bonus = clamp(attackTypeScores.c2 / 4, 0, 20);
  }



  // --------------------------------------------------
  // 4. Impact Escalation Boost
  // --------------------------------------------------
  let impactBonus = 0;

  // gradual base scaling
  impactBonus = Math.min(8, attackTypeScores.impact / 6);

  // escalation bump for confirmed high impact
  if (attackTypeScores.impact >= 60) {
    impactBonus += 4;
  }


  // --------------------------------------------------
  // 5. Coupling Bonus (volume + behavior synergy)
  // --------------------------------------------------

  let couplingBonus = 0;

  // v4.0: previously (volumeComponent > 45 && behaviorComponent > 10), but
  // volumeComponent was always 60, so this fired on behaviour alone. Now it
  // models genuine cross-signal reinforcement: focused peers AND service
  // targeting occurring together.
  if (concentrationComponent > 8 && behaviorComponent > 8) {
    couplingBonus = 5;
  }

  // --------------------------------------------------
  // 6. Final Risk Calculation
  // --------------------------------------------------

  // v4.0: volume removed; entropy + concentration added.
  // Budget: severity 25 + behaviour 20 + entropy 20 + concentration 15
  //         + amplifier 25 + c2Bonus 20 + impactBonus 12 + coupling 5
  // (components are independently clamped; the sum is clamped to 100)
  const riskScoreRaw = clamp(
    Math.round(
      severityComponent +
      behaviorComponent +
      entropyComponent +
      concentrationComponent +
      signalAmplifier +
      c2Bonus +
      impactBonus +
      couplingBonus
    ),
    0,
    100
  );

  // Budget normalisation. Denominator derived from input availability only.
  // honeypot profile sums to 110 -> capped at 100 -> normalised == raw, so
  // existing behaviour and archives are unchanged.
  const reachProfile =
    REACHABILITY_PROFILES[RISK_PROFILE] || REACHABILITY_PROFILES.honeypot;
  const reachableBudget = Object.entries(RISK_BUDGET)
    .filter(([k]) => reachProfile[k])
    .reduce((a, [, v]) => a + v, 0);
  const referenceBudget = Math.min(reachableBudget, 100);
  const riskScoreNormalised =
    referenceBudget > 0
      ? clamp(Math.round((riskScoreRaw / referenceBudget) * 100), 0, 100)
      : 0;

  const riskScore = RISK_NORMALISE ? riskScoreNormalised : riskScoreRaw;

  let state = "stable";
  if (riskScore >= 85) state = "critical";
  else if (riskScore >= 60) state = "high";
  else if (riskScore >= 45) state = "elevated";

  const attackExplanation = buildAttackExplanation({
    dominantAttack,
    attackTypeScores,
    topPorts: topPortsForOutput,
    authPortPressure,
    webPortPressure,
    dbPortPressure,
    scanCandidates,
    c2Signals,
    attacksLast5Min,
    burstRatio5mOverHour,
  });

  // Indicators are computed FIRST so the prose can be gated on the same
  // determinations. Previously the explanation was built before the indicators
  // existed, which is why it used independent magnitude thresholds and could
  // contradict them.
  const attackIndicatorResult = buildAttackIndicators({
    dominantAttack,
    scanCandidates,
    authPortPressure,
    webPortPressure,
    dbPortPressure,
    c2Signals,
    attacksLast5Min,
    burstRatio5mOverHour,
    criticalCount,
  });

  const riskExplanation = buildRiskExplanation({
    indicators: attackIndicatorResult.indicators,
    riskScore,
    severityComponent,
    behaviorComponent,
    entropyComponent,
    concentrationComponent,
    signalAmplifier,
    c2Bonus,
    impactBonus,
    couplingBonus,
  });

  const attackDetected =
    dominantAttack.score >= 40 ||
    riskScore >= 60 ||
    attackIndicatorResult.evidenceScore >= 3;

  let confidenceNumeric = 0;

  confidenceNumeric += dominantAttack.score * 0.5;
  confidenceNumeric += Math.min(25, attackIndicatorResult.evidenceScore * 5);
  confidenceNumeric += Math.min(25, riskScore * 0.25);
  confidenceNumeric = clamp(confidenceNumeric, 0, 100);

  const attackConfidence =
    confidenceNumeric >= 75
      ? "high"
      : confidenceNumeric >= 45
      ? "moderate"
      : "low";

  const confidenceExplanation = buildConfidenceExplanation({
    confidenceNumeric,
    attackConfidence,
    evidenceScore: attackIndicatorResult.evidenceScore,
    dominantAttack,
    riskScore,
  });

  // ==================================================
  // FINAL
  // ==================================================

  // --------------------------------------------------
  // REAL REPLAY CONTROL-PLANE TELEMETRY
  // --------------------------------------------------
  // IMPORTANT:
  // These are REAL orchestration states,
  // NOT inferred attack-classification states.
  //
  // Replay telemetry must only represent
  // actual replay lifecycle truth.
  // --------------------------------------------------

  const replayState =
    process.env.REPLAY_STATE ||
    (
      attacksLast5Min > 0
        ? "injection"
        : "baseline"
    );

  const replayMode =
    process.env.REPLAY_MODE ||
    "scaled_ts";

  const replayPcap =
    process.env.PCAP_NAME ||
    "unknown";

  const replayStartedAt =
    process.env.REPLAY_STARTED_AT ||
    null;

  const injectionStart =
    process.env.INJECTION_START ||
    null;

  const cooldownStart =
    process.env.COOLDOWN_START ||
    null;

  const replayEndedAt =
    process.env.REPLAY_ENDED_AT ||
    null;

  const currentWindow =
    Number(
      process.env.CURRENT_WINDOW || 1
    );

  // --------------------------------------------------
  // REAL REPLAY TIMELINE
  // --------------------------------------------------

  const replayTimeline = [

    {
      phase: "baseline",

      startedAt:
        replayStartedAt,

      endedAt:
        injectionStart,

      isActive:
        replayState ===
        "baseline",

      metadata: {
        replayMode,
        pcapName:
          replayPcap,
      },

      overlay: {

        attacksPerSecond:
          replayState === "baseline"
            ? attacksLast5Min
            : 0,

        attacksLast1Min:
          replayState === "baseline"
            ? attacksLast1Min
            : 0,

        attacksLast5Min:
          replayState === "baseline"
            ? attacksLast5Min
            : 0,

        attacksLast15Min:
          replayState === "baseline"
            ? attacksLast15Min
            : 0,

        attacksLastHour:
          replayState === "baseline"
            ? attacksLastHour
            : 0,

        burstRatio5mOverHour:
          replayState === "baseline"
            ? burstRatio5mOverHour
            : 0,

        dominantAttack:
          replayState === "baseline"
            ? dominantAttack.type
            : "none",

        dominantAttackScore:
          replayState === "baseline"
            ? Number(
                dominantAttack.score.toFixed(2)
              )
            : 0,

        riskScore0to100:
          replayState === "baseline"
            ? riskScore
            : 0,

        state:
          replayState === "baseline"
            ? state
            : "stable",

        attackDetected:
          replayState === "baseline"
            ? attackDetected
            : false,

        attackConfidence:
          replayState === "baseline"
            ? attackConfidence
            : "low",

        evidenceScore:
          replayState === "baseline"
            ? attackIndicatorResult.evidenceScore
            : 0,

        currentWindow,

        windowMinutes:
          minutes,

      },

    },

    {
      phase: "injection",

      startedAt:
        injectionStart,

      endedAt:
        cooldownStart,

      isActive:
        replayState ===
        "injection",

      metadata: {
        replayMode,
        pcapName:
          replayPcap,
      },

      overlay: {

        attacksPerSecond:
          replayState === "injection"
            ? attacksLast5Min
            : 0,

        attacksLast1Min:
          replayState === "injection"
            ? attacksLast1Min
            : 0,

        attacksLast5Min:
          replayState === "injection"
            ? attacksLast5Min
            : 0,

        attacksLast15Min:
          replayState === "injection"
            ? attacksLast15Min
            : 0,

        attacksLastHour:
          replayState === "injection"
            ? attacksLastHour
            : 0,

        burstRatio5mOverHour:
          replayState === "injection"
            ? burstRatio5mOverHour
            : 0,

        dominantAttack:
          replayState === "injection"
            ? dominantAttack.type
            : "none",

        dominantAttackScore:
          replayState === "injection"
            ? Number(
                dominantAttack.score.toFixed(2)
              )
            : 0,

        riskScore0to100:
          replayState === "injection"
            ? riskScore
            : 0,

        state:
          replayState === "injection"
            ? state
            : "stable",

        attackDetected:
          replayState === "injection"
            ? attackDetected
            : false,

        attackConfidence:
          replayState === "injection"
            ? attackConfidence
            : "low",

        evidenceScore:
          replayState === "injection"
            ? attackIndicatorResult.evidenceScore
            : 0,

        currentWindow,

        windowMinutes:
          minutes,

      },

    },

    {
      phase: "cooldown",

      startedAt:
        cooldownStart,

      endedAt:
        replayEndedAt,

      isActive:
        replayState ===
        "cooldown",

      metadata: {
        replayMode,
        pcapName:
          replayPcap,
      },

      overlay: {

        attacksPerSecond:
          replayState === "cooldown"
            ? attacksLast5Min
            : 0,

        attacksLast1Min:
          replayState === "cooldown"
            ? attacksLast1Min
            : 0,

        attacksLast5Min:
          replayState === "cooldown"
            ? attacksLast5Min
            : 0,

        attacksLast15Min:
          replayState === "cooldown"
            ? attacksLast15Min
            : 0,

        attacksLastHour:
          replayState === "cooldown"
            ? attacksLastHour
            : 0,

        burstRatio5mOverHour:
          replayState === "cooldown"
            ? burstRatio5mOverHour
            : 0,

        dominantAttack:
          replayState === "cooldown"
            ? dominantAttack.type
            : "none",

        dominantAttackScore:
          replayState === "cooldown"
            ? Number(
                dominantAttack.score.toFixed(2)
              )
            : 0,

        riskScore0to100:
          replayState === "cooldown"
            ? riskScore
            : 0,

        state:
          replayState === "cooldown"
            ? state
            : "stable",

        attackDetected:
          replayState === "cooldown"
            ? attackDetected
            : false,

        attackConfidence:
          replayState === "cooldown"
            ? attackConfidence
            : "low",

        evidenceScore:
          replayState === "cooldown"
            ? attackIndicatorResult.evidenceScore
            : 0,

        currentWindow,

        windowMinutes:
          minutes,

      },

    },

  ];

  // --------------------------------------------------
  // LIVE TELEMETRY OVERLAY
  // --------------------------------------------------
  // THIS is inference telemetry.
  //
  // These are NOT replay phases.
  // These are analytical overlays rendered
  // on top of replay orchestration.
  // --------------------------------------------------

  const liveReplayOverlay = {

    attacksPerSecond:
      attacksLast5Min,

    attacksLast1Min,

    attacksLast5Min,

    attacksLast15Min,

    attacksLastHour,

    burstRatio5mOverHour,

    burstRatio15mOverHour,

    dominantAttack:
      dominantAttack.type,

    dominantAttackScore:
      Number(
        dominantAttack.score.toFixed(2)
      ),

    riskScore0to100:
      riskScore,

    state,

    attackDetected,

    attackConfidence,

    evidenceScore:
      attackIndicatorResult.evidenceScore,

    currentWindow,

    windowMinutes:
      minutes,

  };

  // --------------------------------------------------
  // FINAL RETURN
  // --------------------------------------------------

  return {

    coreVersion:
      CORE_VERSION,

    generatedAt:
      new Date().toISOString(),

    // Echo the source scope so callers/experiment can confirm isolation.
    sourceFilter:
      sourceFilter || "all",

    // Echo the scoring mode + anchor so offline analysis is auditable.
    scoringMode:
      isHistorical ? "historical" : "live",

    windowEnd:
      anchor.toISOString(),

    windowMinutes:
      minutes,

    windowStart:
      windowStart.toISOString(),

    // ================================================
    // ATTACK METRICS
    // ================================================

    attackMetrics: {

      attacksLast1Min,

      attacksLast5Min,

      attacksLast15Min,

      attacksLastHour,

      burstRatio5mOverHour,

      burstRatio15mOverHour,

    },

    // ================================================
    // SCANNING / ENTROPY
    // ================================================

    scanningIndicators: {

      scanCandidates,

      topPorts:
        topPortsForOutput,

      topSourceIp,

      topExternalPeerIp,

      sourceEntropy:
        Number(
          sourceEntropy.toFixed(3)
        ),

      portEntropy:
        Number(
          portEntropy.toFixed(3)
        ),

      authPortPressure,

      webPortPressure,

      dbPortPressure,

      windowedEventCount:
        recentEvents.length,

      windowedTopPortsCount:
        topPortsWindowed.length,

      windowedMissingPortCount:
        missingPortCount,

      usingWindowedPorts:
        topPortsWindowed.length > 0,

      portDiversity,

    },

    // ================================================
    // SEVERITY
    // ================================================

    severitySignals: {

      criticalTotalLifetime: criticalTotal,

      highTotalLifetime: highTotal,

      mediumTotalLifetime: mediumTotal,

      criticalCountWindow: criticalCount,

      highCountWindow: highCount,

      mediumCountWindow: mediumCount,

      impactScore0to100:
        impactScore,

    },

    // ================================================
    // ATTRIBUTION
    // ================================================

    attributionSignals: {

      topASN:
        topASN || null,

    },

    // ================================================
    // ATTACK CLASSIFICATION
    // ================================================

    attackClassification: {

      attackTypeScores,

      attackTypeProbabilities,

      dominantAttack,

      c2Signals,

    },

    // ================================================
    // RISK FABRIC
    // ================================================

    riskComponents: {

      // v4.0: volume is context only and contributes 0 to risk.
      volumeComponent,

      severityComponent,

      behaviorComponent,

      entropyComponent,

      concentrationComponent,

      signalAmplifier,

      c2Bonus,

      impactBonus,

      couplingBonus,

    },

    // Which fraction of the scoring this deployment can actually exercise.
    // Reported on every window so a zero-recall result is readable as
    // "the corpus could not supply N% of the budget".
    // Gate values as the core actually resolved them, not as a caller assumes.
    // The harness runs in a separate process and cannot observe the backend's
    // environment; without this it records "backend default" and an ablation
    // arm is indistinguishable from a default run in its own output.
    detectorGates: {
      c2: {
        minEvents: CFG.c2.minEvents,
        minFlowCount: CFG.c2.minFlowCount,
        periodicitySpanMinSec: CFG.c2.periodicitySpanMinSec,
      },
      c2BonusMinScore: Number(process.env.C2_BONUS_MIN_SCORE ?? 40),
    },
    scoring: {
      timeField: TIME_FIELD,
      scopePcap: SCOPE_PCAP,
      dosExpectAvailable: process.env.DOS_EXPECT_AVAILABLE === "1",
      dosExpected,
      dosHistoryMin,
    },
    riskBudget: {
      profile: RISK_PROFILE,
      normalised: RISK_NORMALISE,
      nominalBudget: Object.values(RISK_BUDGET).reduce((a, b) => a + b, 0),
      reachableBudget,
      referenceBudget,
      reachable: reachProfile,
      riskScoreRaw,
      riskScoreNormalised,
    },

    // v4.0 rate-independent feature diagnostics (for analysis / auditing)
    rateIndependentFeatures: {

      criticalRatio: Number(criticalRatio.toFixed(4)),

      authRatio: Number(authRatio.toFixed(4)),

      portEntropyNorm: Number(portEntropyNorm.toFixed(4)),

      srcEntropyNorm: Number(srcEntropyNorm.toFixed(4)),

      windowEventCount,

    },

    riskScore0to100:
      riskScore,

    state,

    // ================================================
    // LIFETIME CONTEXT
    // ================================================

    lifetimeContext: {
      scope: "lifetime-cumulative",
      notCurrentWindow: true,

      topPorts:
        topPortsLifetime,

      authPortPressure:
        authPortPressureLifetime,

      webPortPressure:
        webPortPressureLifetime,

      dbPortPressure:
        dbPortPressureLifetime,

      portEntropy:
        Number(
          portEntropyLifetime.toFixed(3)
        ),

      bytesMean,

      bytesStd,

    },

    // ================================================
    // REPLAY CONTROL-PLANE TELEMETRY
    // ================================================

    replay: {

      state:
        replayState,

      replayMode,

      pcapName:
        replayPcap,

      currentWindow,

      startedAt:
        replayStartedAt,

      injectionStart,

      cooldownStart,

      replayEndedAt,

      timeline:
        replayTimeline,

    },

    // ================================================
    // LIVE OVERLAY TELEMETRY
    // ================================================

    replayOverlay:
      liveReplayOverlay,

    // ================================================
    // BACKWARD COMPATIBILITY
    // ================================================

    replayState,

    replayMode,

    currentReplayPhase:
      replayState,

    replayTimeline,

    replayAttackRate:
      attacksLast5Min,

    // ================================================
    // REASONING
    // ================================================

    reasoning: {

      attackDetected,

      attackConfidence,

      confidenceNumeric:
        Number(
          confidenceNumeric.toFixed(2)
        ),

      evidenceScore:
        attackIndicatorResult.evidenceScore,

      attackIndicators:
        attackIndicatorResult.indicators,

      dominantAttackType:
        dominantAttack.type,

      dominantAttackExplanation:
        attackExplanation,

      riskExplanation,

      confidenceExplanation,

      analystSummary:
        attackDetected
          ? attackExplanation.join(" ")
          : "No significant malicious behavioral indicators detected.",

    },

  };
}

module.exports = { buildCopilotCore };
