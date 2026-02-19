// backend/services/copilotCore.js
// Deterministic intelligence core for Threat Copilot (Multi-Signal / Multi-Attack-Type)
// - Keeps windowed-first logic with lifetime fallback safety net. 


const Attack = require("../models/AttackModel");
const Severity = require("../models/SeverityModel");
const Port = require("../models/PortModel");
const ASN = require("../models/ASNModel");

const CORE_VERSION = "copilotCore-v3.5";

// ----------------------------
// Config 
// ----------------------------
const CFG = Object.freeze({
  recentLimit: 20000,

  // C2 thresholds
  c2: {
    minEvents: 30,            // don’t claim C2 off tiny samples
    minFlowCount: 12,         // repeats to same peer
    dominantFlowRatio: 0.40,  // one flow dominates window
    lowBurstMax: 0.40,        // C2 is usually not bursty like DoS
    maxPortDiversity: 4,      // C2 often reuses same port(s)
    periodicityCvMax: 0.65,   // coefficient of variation for inter-arrivals
    periodicitySpanMinSec: 90 // must span some time
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

function isPrivateIp(ip) {
  if (!ip || typeof ip !== "string") return false;
  return (
    ip.startsWith("10.") ||
    ip.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
    ip.startsWith("127.") ||
    ip === "0.0.0.0"
  );
}

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
  const t = e?.timestamp;
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

// ----------------------------
// Core Builder Function
// ----------------------------
async function buildCopilotCore({ minutes = 60 } = {}) {
  const nowMs = Date.now();
  const fiveMinutesAgo = new Date(nowMs - 5 * 60 * 1000);
  const fifteenMinutesAgo = new Date(nowMs - 15 * 60 * 1000);
  const oneHourAgo = new Date(nowMs - 60 * 60 * 1000);
  const windowStart = new Date(nowMs - minutes * 60 * 1000);


  // ==================================================
  // 1) ATTACK VOLUME SIGNALS (for DoS and general threat level)
  // ==================================================
  const [attacksLast5Min, attacksLast15Min, attacksLastHour] = await Promise.all([
    Attack.countDocuments({ timestamp: { $gte: fiveMinutesAgo } }),
    Attack.countDocuments({ timestamp: { $gte: fifteenMinutesAgo } }),
    Attack.countDocuments({ timestamp: { $gte: oneHourAgo } }),
  ]);

  const burstRatio5mOverHour = attacksLastHour > 0 ? attacksLast5Min / attacksLastHour : 0;
  const burstRatio15mOverHour = attacksLastHour > 0 ? attacksLast15Min / attacksLastHour : 0;

  // ==================================================
  // 2) LIFETIME CONTEXT (for stability + fallback, and also important signals like top ports and ASN)
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
    { timestamp: { $gte: windowStart } },
    {
      timestamp: 1,
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
    .sort({ timestamp: 1 })
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

    // Weighted, explainable scoring
    c2Score = clamp(
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
  const dosScore = clamp(
    Math.min(60, Math.log10(attacksLast5Min + 1) * 20) +
      Math.min(25, burstRatio5mOverHour * 100) +
      Math.min(15, burstRatio15mOverHour * 80),
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
  );  const webProbeScore = clamp(Math.min(70, (webPortPressure || 0) / 80), 0, 100);

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

  const attackTypeProbabilities = softmaxLike(attackTypeScores);
  const dominantAttack = pickTop(attackTypeScores);

  // ==================================================
  // 7) RISK FABRIC
  // ==================================================

  // ---- HYBRID VOLUME (absolute + relative) ----
  // Relative catches bursts. Absolute catches sustained injections.
  // Using max() ensures baseline doesn't inflate unless absolute is truly high.

  const volumeAbs = clamp(attacksLast5Min / 2, 0, 60);        
  const volumeRel = clamp(burstRatio5mOverHour * 80, 0, 60); 

  const volumeComponent = Math.max(volumeAbs, volumeRel);


  const severityComponent = clamp(criticalCount / 4, 0, 30);
  const behaviorComponent = clamp((authPortPressure || 0) / 150, 0, 25);

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

  if (attackTypeScores.c2 >= 40) {
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

  if (volumeComponent > 45 && behaviorComponent > 10) {
    couplingBonus = 5;
  }

  // --------------------------------------------------
  // 6. Final Risk Calculation
  // --------------------------------------------------

  const riskScore = clamp(
    Math.round(
      volumeComponent +
      severityComponent +
      behaviorComponent +
      signalAmplifier +
      c2Bonus +
      impactBonus +
      couplingBonus
    ),
    0,
    100
  );

  let state = "stable";
  if (riskScore >= 85) state = "critical";
  else if (riskScore >= 60) state = "high";
  else if (riskScore >= 45) state = "elevated";


  // ==================================================
  // FINAL
  // ==================================================
  return {
    coreVersion: CORE_VERSION,
    generatedAt: new Date().toISOString(),
    windowMinutes: minutes,
    windowStart: windowStart.toISOString(),

    attackMetrics: {
      attacksLast5Min,
      attacksLast15Min,
      attacksLastHour,
      burstRatio5mOverHour,
      burstRatio15mOverHour,
    },

    scanningIndicators: {
      scanCandidates,
      topPorts: topPortsForOutput,
      topSourceIp,
      topExternalPeerIp,
      sourceEntropy: Number(sourceEntropy.toFixed(3)),
      portEntropy: Number(portEntropy.toFixed(3)),
      authPortPressure,
      webPortPressure,
      dbPortPressure,

      // debug / sanity fields
      windowedEventCount: recentEvents.length,
      windowedTopPortsCount: topPortsWindowed.length,
      windowedMissingPortCount: missingPortCount,
      usingWindowedPorts: topPortsWindowed.length > 0,
      portDiversity,
    },

    severitySignals: {
      criticalTotal,
      highTotal,
      mediumTotal,
      criticalCount,
      highCount,
      mediumCount,
      impactScore0to100: impactScore,
    },

    attributionSignals: {
      topASN: topASN || null,
    },

    attackClassification: {
      attackTypeScores,
      attackTypeProbabilities,
      dominantAttack,
      c2Signals,
    },

    riskComponents: {
      volumeComponent,
      severityComponent,
      behaviorComponent,
      signalAmplifier,
      c2Bonus,
      impactBonus,
      couplingBonus,
    },

    riskScore0to100: riskScore,
    state,

    lifetimeContext: {
      topPorts: topPortsLifetime,
      authPortPressure: authPortPressureLifetime,
      webPortPressure: webPortPressureLifetime,
      dbPortPressure: dbPortPressureLifetime,
      portEntropy: Number(portEntropyLifetime.toFixed(3)),
      bytesMean,
      bytesStd,
    },
  };
}

module.exports = { buildCopilotCore };