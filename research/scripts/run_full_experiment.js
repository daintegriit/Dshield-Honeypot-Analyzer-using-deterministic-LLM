#!/usr/bin/env node

/**
 * FULL EXPERIMENT HARNESS (PHASE-CORRECT + INFECTION-AWARE OPTIONAL)
 * -----------------------------------------------------------------
 * Keeps your original design:
 *   baseline -> (optional pre_cooldown) -> injection -> cooldown
 *
 * Adds OPTIONAL infection-aware truth:
 *   If ATTACK_START_RAW_TS is provided, we watch /logs/recent and find the first
 *   ingested log whose raw contains TS >= ATTACK_START_RAW_TS.
 *   That ingestion timestamp becomes the effective attack start for truth labeling.
 *
 * Still runnable with NO ENV VARS:
 *   node research/scripts/run_full_experiment.js
 *
 * Optional:
 *   ATTACK_START_RAW_TS=1970-01-01T01:04:33.86657Z node research/scripts/run_full_experiment.js
 */

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");

// ---------------- CONFIG ----------------

const BASE_URL = process.env.BASE_URL || "http://localhost:5002";
const LIMIT = Number(process.env.LIMIT || 100000);

// Sliding windows (minutes)
const WINDOWS = (process.env.WINDOWS || "1") //1 min windows
//const WINDOWS = (process.env.WINDOWS || "2,5,15,30,60")
  .split(",")
  .map((x) => Number(x.trim()))
  .filter((n) => Number.isFinite(n) && n > 0);

// Experiment timing
const BASELINE_SECONDS = Number(process.env.BASELINE_SECONDS || 10 * 60); // baseline (evaluated)
const PRE_COOLDOWN_SECONDS = Number(process.env.PRE_COOLDOWN_SECONDS || 0); // optional buffer before injection
const INJECTION_MIN_SECONDS = Number(process.env.INJECTION_MIN_SECONDS || 0); // optional minimum injection duration (0 disables)

const COOLDOWN_SECONDS_RAW = process.env.COOLDOWN_SECONDS
  ? Number(process.env.COOLDOWN_SECONDS)
  : null;

// Evaluate every 30 seconds
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS || 30000);

// PCAP replay runner
const PYTHON = process.env.PYTHON || "python3";
const REPLAY_SCRIPT = process.env.REPLAY_SCRIPT || "replay_pcap_events.py";

// Optional: hard cap so you never run forever if replay hangs
const MAX_TOTAL_SECONDS = Number(process.env.MAX_TOTAL_SECONDS || 60 * 60 * 8); // 8 hours

// Infection-aware truth (OPTIONAL)
const ATTACK_START_RAW_TS = process.env.ATTACK_START_RAW_TS || null;
// Where to read recent ingested logs that include { raw, timestamp }
const RECENT_LOGS_URL = process.env.RECENT_LOGS_URL || `${BASE_URL}/logs/recent`;
// How long (seconds) we try to map raw TS -> ingestion time after injection starts
const MAP_TIMEOUT_SECONDS = Number(process.env.MAP_TIMEOUT_SECONDS || 500); // 3 minutes default
const MAP_POLL_MS = Number(process.env.MAP_POLL_MS || 2000);

const OUT_DIR = path.join(__dirname, "../outputs/full_experiment");
fs.mkdirSync(OUT_DIR, { recursive: true });

// ---------------- LOGGING ----------------
const logFilePath = path.join(OUT_DIR, "full_terminal_output.log");

const logStream = fs.createWriteStream(logFilePath, {
  flags: "a", // append mode (keeps previous runs)
});

function log(line) {
  const text = typeof line === "string" ? line : JSON.stringify(line);
  console.log(text);
  logStream.write(text + "\n");
}

function logError(line) {
  const text = typeof line === "string" ? line : JSON.stringify(line);
  console.error(text);
  logStream.write("[ERROR] " + text + "\n");
}

function logWarn(line) {
  const text = typeof line === "string" ? line : JSON.stringify(line);
  console.warn(text);
  logStream.write("[WARN] " + text + "\n");
}


// Auto-cooldown: if COOLDOWN_SECONDS not provided, make it exceed the largest window
const largestWindowMin = Math.max(...WINDOWS);
const defaultCooldownSeconds = largestWindowMin * 10 + 10 * 60; // +10m buffer
const COOLDOWN_SECONDS =
  COOLDOWN_SECONDS_RAW && Number.isFinite(COOLDOWN_SECONDS_RAW) && COOLDOWN_SECONDS_RAW > 0
    ? COOLDOWN_SECONDS_RAW
    : defaultCooldownSeconds;

// ---------------- STATE ----------------

let injectionStart = null;          // Date (replay start wall-clock)
let injectionEnd = null;            // Date (replay end wall-clock)
let attackStartEffective = null;    // Date (effective truth start; defaults to injectionStart)
let phase = "baseline";             // baseline | pre_cooldown | injection | cooldown

let experimentResults = [];
let stopEvaluation = false;

// ---------------- HELPERS ----------------

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function clampIso(d) {
  try {
    return d ? new Date(d).toISOString() : null;
  } catch {
    return null;
  }
}

async function countdown(label, totalSeconds) {
  for (let remaining = totalSeconds; remaining > 0; remaining--) {
    if (remaining % 30 === 0 || remaining <= 10) {
      const m = Math.floor(remaining / 60);
      const s = remaining % 60;
      log(`${label} remaining: ${m}m ${s}s`);
    }
    await sleep(1000);
  }
}

/**
 * Your original tactic classifier (kept).
 * Note: this expects "behavior.signals.*" which may not exist depending on your API.
 * We'll also derive tactic from core.attackClassification.dominantAttack below.
 */
function classifyTactic(core, behavior) {
  const burst = Number(behavior?.signals?.burstRatio ?? 0);
  const scan = Number(core?.scanFactor ?? 0);
  const focus = Number(behavior?.signals?.topSourceIpConcentration ?? 0);

  if (scan > 0.6 && burst < 1.5) return "scan";
  if (focus > 0.7 && burst > 1.2) return "brute-force";
  if (burst > 2.5) return "flood";
  if (scan > 0.3 && focus < 0.5) return "probing";

  return "undetermined";
}

/**
 * ✅ NEW: Derive the values you want to print from the ACTUAL copilotCore schema.
 * This is the key fix: we stop reading non-existent fields.
 */
function deriveSignalsFromCore(core) {
  const risk =
    typeof core?.riskScore0to100 === "number" ? core.riskScore0to100 : null;

  const state = core?.state ?? "stable";

  // burst ratio exists in your core at: attackMetrics.burstRatio5mOverHour
  const burst =
    typeof core?.attackMetrics?.burstRatio5mOverHour === "number"
      ? core.attackMetrics.burstRatio5mOverHour
      : null;

  // scan score exists at: attackClassification.attackTypeScores.scan (0..100)
  const scanScore =
    typeof core?.attackClassification?.attackTypeScores?.scan === "number"
      ? core.attackClassification.attackTypeScores.scan
      : null;

  const scan = scanScore === null ? null : Math.max(0, Math.min(1, scanScore / 100));

  // brute force score (optional)
  const bruteScore =
    typeof core?.attackClassification?.attackTypeScores?.brute_force === "number"
      ? core.attackClassification.attackTypeScores.brute_force
      : null;

  const brute = bruteScore === null ? null : Math.max(0, Math.min(1, bruteScore / 100));

  // topPort from scanningIndicators.topPorts[0]
  const topPort =
    Array.isArray(core?.scanningIndicators?.topPorts) && core.scanningIndicators.topPorts.length
      ? (core.scanningIndicators.topPorts[0]?.port ?? null)
      : null;

  // topIP is NOT in core; keep n/a unless your API exposes it elsewhere
  const topIP = core?.topIP ?? null;

  // dominant attack type is in core: attackClassification.dominantAttack.type
  const dominantType =
    core?.attackClassification?.dominantAttack?.type ?? "unknown";

  const scores = core?.attackClassification?.attackTypeScores ?? null;

  return {
    risk,
    state,
    burst,
    scan,
    brute,
    topPort,
    topIP,
    dominantType,
    scores,
  };
}

/**
 * Extracts TS=... from raw string (your replay format includes TS=...).
 * Returns Date or null.
 */
function extractRawTs(raw) {
  if (!raw || typeof raw !== "string") return null;
  const m = raw.match(/TS=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:\.]+Z)/);
  if (!m) return null;
  const d = new Date(m[1]);
  return Number.isFinite(d.getTime()) ? d : null;
}

/**
 * Try to map PCAP infection boundary (raw TS) -> ingestion timestamp
 * by watching /logs/recent until we see an ingested record whose raw TS >= boundary.
 *
 * Expected /logs/recent payload: array of objects with at least { raw, timestamp }
 */
async function mapInfectionBoundaryToIngestedStart() {
  if (!ATTACK_START_RAW_TS) return null;

  const boundary = new Date(ATTACK_START_RAW_TS);
  if (!Number.isFinite(boundary.getTime())) {
    logWarn(`⚠️ ATTACK_START_RAW_TS is not a valid ISO date: ${ATTACK_START_RAW_TS}`);
    return null;
  }

  log(`🧭 Infection-aware truth ON`);
  log(`   boundary_raw_ts = ${boundary.toISOString()}`);
  log(`   polling recent logs: ${RECENT_LOGS_URL}`);

  const deadline = Date.now() + MAP_TIMEOUT_SECONDS * 1000;

  while (Date.now() < deadline) {
    try {
      const res = await axios.get(RECENT_LOGS_URL, { timeout: 15000 });
      const rows = res.data;

      if (Array.isArray(rows)) {
        for (const row of rows) {
          const raw = row?.raw ?? row?.message ?? row?.line ?? "";
          const ingestedTs = row?.timestamp ?? row?.time ?? row?.createdAt ?? null;

          const rawTs = extractRawTs(raw);
          if (!rawTs) continue;

          if (rawTs.getTime() >= boundary.getTime()) {
            const mapped = new Date(ingestedTs);
            if (Number.isFinite(mapped.getTime())) {
              log(`✅ Mapped infection boundary -> ingested time: ${mapped.toISOString()}`);
              return mapped;
            }
          }
        }
      }
    } catch (err) {
      // keep trying (endpoint might be slow or temporarily empty)
    }

    await sleep(MAP_POLL_MS);
  }

  logWarn(`⚠️ Could not map infection boundary within ${MAP_TIMEOUT_SECONDS}s. Using replay start as truth.`);
  return null;
}

/**
 * Window-aware ground truth:
 * Attack iff the evaluated time window overlaps [attackStartEffective, injectionEndOrNow].
 */
function labelGroundTruth(windowEndTime, minutes) {
  if (!attackStartEffective) return "Normal";

  const endBound = injectionEnd ? injectionEnd : windowEndTime; // while injection running, end=now
  const windowStart = new Date(windowEndTime.getTime() - minutes * 60000);

  const overlaps = windowStart <= endBound && windowEndTime >= attackStartEffective;
  return overlaps ? "Attack" : "Normal";
}

/**
 * Simple debug truth: only "Attack" while replay is active (not for scoring).
 */
function labelTruthSimple() {
  return injectionStart && !injectionEnd ? "Attack" : "Normal";
}

// ---------------- METRICS ----------------

function computeConfusion(results) {
  let TP = 0, FP = 0, TN = 0, FN = 0;

  for (const r of results) {
    if (r.truth === "Attack" && r.predicted === "Attack") TP++;
    if (r.truth === "Normal" && r.predicted === "Attack") FP++;
    if (r.truth === "Normal" && r.predicted === "Normal") TN++;
    if (r.truth === "Attack" && r.predicted === "Normal") FN++;
  }

  return { TP, FP, TN, FN };
}

function computeRates({ TP, FP, TN, FN }) {
  const total = TP + FP + TN + FN;

  const precision = TP + FP === 0 ? 0 : TP / (TP + FP);
  const recall = TP + FN === 0 ? 0 : TP / (TP + FN);
  const specificity = TN + FP === 0 ? 0 : TN / (TN + FP);
  const fpr = FP + TN === 0 ? 0 : FP / (FP + TN);
  const fnr = FN + TP === 0 ? 0 : FN / (FN + TP);
  const accuracy = total === 0 ? 0 : (TP + TN) / total;
  const balancedAccuracy = (recall + specificity) / 2;
  const f1 = precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall);

  return {
    total_samples: total,
    precision,
    recall,
    specificity,
    fpr,
    fnr,
    accuracy,
    balanced_accuracy: balancedAccuracy,
    f1,
  };
}

function computeGlobalMetrics(results) {
  const confusion = computeConfusion(results);
  return { ...confusion, ...computeRates(confusion) };
}

function computePerWindowMetrics(results, windows) {
  const out = {};
  for (const w of windows) {
    const subset = results.filter((r) => r.window_minutes === w);
    out[String(w)] = computeGlobalMetrics(subset);
  }
  return out;
}

function computeLatencySeconds(results) {
  const byWindow = new Map();
  for (const r of results) {
    const w = r.window_minutes;
    if (!byWindow.has(w)) byWindow.set(w, []);
    byWindow.get(w).push(r);
  }

  const perWindow = {};
  const latencyValues = [];

  for (const [w, rows] of byWindow.entries()) {
    const attackTruthTimes = rows
      .filter((r) => r.truth === "Attack")
      .map((r) => new Date(r.timestamp).getTime())
      .filter(Number.isFinite);

    const detectTimes = rows
      .filter((r) => r.predicted === "Attack")
      .map((r) => new Date(r.timestamp).getTime())
      .filter(Number.isFinite);

    if (attackTruthTimes.length === 0 || detectTimes.length === 0) {
      perWindow[String(w)] = null;
      continue;
    }

    const firstAttack = Math.min(...attackTruthTimes);
    const firstDetect = Math.min(...detectTimes);

    const latency = (firstDetect - firstAttack) / 1000;
    perWindow[String(w)] = latency;

    if (Number.isFinite(latency)) latencyValues.push(latency);
  }

  const global =
    latencyValues.length === 0
      ? null
      : {
          min: Math.min(...latencyValues),
          max: Math.max(...latencyValues),
          mean: latencyValues.reduce((a, b) => a + b, 0) / latencyValues.length,
        };

  return { global, perWindow };
}

function computeStability(results, windows) {
  const out = {};
  for (const w of windows) {
    const rows = results
      .filter((r) => r.window_minutes === w)
      .slice()
      .sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));

    let flips = 0;
    let prev = null;

    for (const r of rows) {
      if (prev && r.predicted !== prev) flips++;
      prev = r.predicted;
    }

    const n = rows.length;
    out[String(w)] = {
      samples: n,
      flips,
      flip_rate: n <= 1 ? 0 : flips / (n - 1),
    };
  }
  return out;
}

function computeRiskSeparation(results) {
  const normal = [];
  const attack = [];

  for (const r of results) {
    const v = typeof r.riskScore === "number" ? r.riskScore : null;
    if (v === null) continue;
    if (r.truth === "Attack") attack.push(v);
    else normal.push(v);
  }

  function mean(arr) {
    if (!arr.length) return null;
    return arr.reduce((a, b) => a + b, 0) / arr.length;
  }

  const mA = mean(attack);
  const mN = mean(normal);

  return {
    normal_n: normal.length,
    attack_n: attack.length,
    normal_mean: mN,
    attack_mean: mA,
    separation_margin: mA === null || mN === null ? null : mA - mN,
  };
}

// ---------------- EVALUATION LOOP ----------------

async function evaluationLoop(startedAtMs) {
  log("🔄 Evaluation loop started");

  while (!stopEvaluation) {
    const elapsedSec = (Date.now() - startedAtMs) / 1000;
    if (elapsedSec > MAX_TOTAL_SECONDS) {
      log(`🛑 Max runtime reached (${MAX_TOTAL_SECONDS}s). Stopping evaluation.`);
      stopEvaluation = true;
      break;
    }

    const now = new Date();

    for (const minutes of WINDOWS) {
      try {
        const res = await axios.get(
          `${BASE_URL}/api/copilot/insight?minutes=${minutes}&limit=${LIMIT}`,
          { timeout: 120000 }
        );

        const summary = res.data || {};

        // NOTE: your API uses coreSummary
        const core = summary.coreSummary || {};
        const behavior = summary.behaviorSummary || {};

        const state = core.state ?? "stable";
        const predicted =
          state === "high" || state === "critical"
            ? "Attack"
            : "Normal";

        const truth = labelGroundTruth(now, minutes);

        // ✅ Pull signals from your actual core schema
        const derived = deriveSignalsFromCore(core);

        // Optional: keep your original classifier too (it might return undetermined if behavior.signals not present)
        const tacticFallback = classifyTactic(core, behavior);

        // Prefer core’s dominantAttack when available
        const tactic =
          derived.dominantType && derived.dominantType !== "unknown"
            ? derived.dominantType
            : tacticFallback;

        // ---- STORE RESULTS ----
        experimentResults.push({
          timestamp: now.toISOString(),
          phase,
          window_minutes: minutes,
          predicted,
          truth,

          riskScore: core?.riskScore0to100 ?? null,
          state: core?.state ?? "stable",


          attackScores: core?.attackClassification?.attackTypeScores ?? {},
          dominantAttack: core?.attackClassification?.dominantAttack ?? { type: "unknown", score: 0 },

          attackMetrics: core?.attackMetrics ?? {},
          scanningIndicators: core?.scanningIndicators ?? {},
          riskComponents: core?.riskComponents ?? {},

          truth_simple: labelTruthSimple(),
          attack_start_effective: attackStartEffective
            ? attackStartEffective.toISOString()
            : null,
        });

        const attackScores = core?.attackClassification?.attackTypeScores || {};
        const dominant = core?.attackClassification?.dominantAttack || {};
        const riskComp = core?.riskComponents || {};
        const scanIndicators = core?.scanningIndicators || {};
        const attackMetrics = core?.attackMetrics || {};

        log(
          `\n[${now.toISOString()}] phase=${phase} | window=${minutes}m\n` +
          `Prediction: ${predicted} | Truth: ${truth}\n` +
          `Risk: ${core.riskScore0to100 ?? "n/a"} | State: ${core.state ?? "stable"}\n` +

          `\n--- Attack Volume ---\n` +
          `5m=${attackMetrics.attacksLast5Min ?? "n/a"} | ` +
          `15m=${attackMetrics.attacksLast15Min ?? "n/a"} | ` +
          `1h=${attackMetrics.attacksLastHour ?? "n/a"} | ` +
          `burstRatio5mOverHour=${attackMetrics.burstRatio5mOverHour ?? "n/a"}\n` +

          `\n--- Attack Type Scores (0..100) ---\n` +
          `dos=${attackScores.dos ?? "n/a"} | ` +
          `scan=${attackScores.scan ?? "n/a"} | ` +
          `brute_force=${attackScores.brute_force ?? "n/a"} | ` +
          `web_probe=${attackScores.web_probe ?? "n/a"} | ` +
          `c2=${attackScores.c2 ?? "n/a"} | ` +
          `impact=${attackScores.impact ?? "n/a"}\n` +

          `Dominant: ${dominant.type ?? "unknown"} (${dominant.score ?? "n/a"})\n` +

          `\n--- Risk Components ---\n` +
          `volume=${riskComp.volumeComponent ?? "n/a"} | ` +
          `severity=${riskComp.severityComponent ?? "n/a"} | ` +
          `behavior=${riskComp.behaviorComponent ?? "n/a"} | ` +
          `signalAmplifier=${riskComp.signalAmplifier ?? "n/a"} | ` +
          `c2Bonus=${riskComp.c2Bonus ?? "n/a"} | ` +
          `impactBonus=${riskComp.impactBonus ?? "n/a"} | ` +
          `couplingBonus=${riskComp.couplingBonus ?? "n/a"}\n` +

          `\n--- Scanning Indicators ---\n` +
          `authPortPressure=${scanIndicators.authPortPressure ?? "n/a"} | ` +
          `webPortPressure=${scanIndicators.webPortPressure ?? "n/a"} | ` +
          `sourceEntropy=${scanIndicators.sourceEntropy ?? "n/a"} | ` +
          `portEntropy=${scanIndicators.portEntropy ?? "n/a"}\n`
        );

      } catch (err) {
        const msg = err?.response?.data
          ? JSON.stringify(err.response.data)
          : err.message;

        logError(`Evaluation error (${minutes}m): ${msg}`);
      }
    }

    await sleep(POLL_INTERVAL_MS);
  }

  log("🛑 Evaluation loop stopped");
}

// ---------------- MAIN ----------------

(async () => {
  const startedAtMs = Date.now();
  const runId = new Date().toISOString().replace(/[:.]/g, "-");

  log("\n🚀 STARTING FULL EXPERIMENT (PHASE-CORRECT)\n");
  log(`BASE_URL=${BASE_URL}`);
  log(`WINDOWS=${WINDOWS.join(",")} (largest=${largestWindowMin}m)`);
  log(
    `Baseline=${BASELINE_SECONDS}s | PreCooldown=${PRE_COOLDOWN_SECONDS}s | Cooldown=${COOLDOWN_SECONDS}s | Poll=${POLL_INTERVAL_MS}ms`
  );
  log(`Replay=${PYTHON} ${REPLAY_SCRIPT}`);
  log(`Max runtime cap=${MAX_TOTAL_SECONDS}s`);
  if (ATTACK_START_RAW_TS) {
    log(`Infection-aware boundary enabled: ATTACK_START_RAW_TS=${ATTACK_START_RAW_TS}`);
  }

  // Start evaluation FIRST so baseline is captured
  const evalPromise = evaluationLoop(startedAtMs);

  // ---------------- BASELINE ----------------
  phase = "baseline";
  log(`\n🧊 BASELINE PHASE: ${BASELINE_SECONDS}s (evaluating now)`);
  await countdown("Baseline", BASELINE_SECONDS);

  // ---------------- PRE-COOLDOWN (optional buffer) ----------------
  if (PRE_COOLDOWN_SECONDS > 0) {
    phase = "pre_cooldown";
    log(`\n❄️ PRE-COOLDOWN BUFFER: ${PRE_COOLDOWN_SECONDS}s (evaluating now)`);
    await countdown("Pre-Cooldown", PRE_COOLDOWN_SECONDS);
  }

  // ---------------- INJECTION ----------------
  phase = "injection";
  log("\n💉 Starting PCAP injection...");
  injectionStart = new Date();

  // Default truth start is replay start
  attackStartEffective = injectionStart;

  const replay = spawn(PYTHON, [REPLAY_SCRIPT], {
    stdio: "inherit",
    cwd: __dirname,
    env: process.env,
  });

  // If infection boundary specified, try to map it to ingestion time while replay is running.
  // If mapping succeeds, we shift truth start forward to that ingestion moment.
  let mappedStart = null;
  if (ATTACK_START_RAW_TS) {
    mappedStart = await mapInfectionBoundaryToIngestedStart();
    if (mappedStart) {
      attackStartEffective = mappedStart;
      log(`🎯 Using infection-aware truth start: ${attackStartEffective.toISOString()}`);
    }
  }

  const injectionStartedAt = Date.now();
  const replayExit = await new Promise((resolve) => {
    replay.on("exit", (code) => resolve(code));
    replay.on("error", () => resolve(1));
  });

  injectionEnd = new Date();

  const injDurSec = (Date.now() - injectionStartedAt) / 1000;
  if (INJECTION_MIN_SECONDS > 0 && injDurSec < INJECTION_MIN_SECONDS) {
    logWarn(
      `⚠️ Injection ran only ${injDurSec.toFixed(1)}s but INJECTION_MIN_SECONDS=${INJECTION_MIN_SECONDS}.`
    );
  }

  log(`\n💉 Injection complete (exit=${replayExit}) duration=${injDurSec.toFixed(1)}s`);

  // ---------------- COOLDOWN (post-injection) ----------------
  phase = "cooldown";
  log(
    `\n❄️ COOLDOWN PHASE: ${COOLDOWN_SECONDS}s (evaluating now) ` +
      `(note: must exceed largest window ${largestWindowMin}m to accumulate TN)`
  );
  await countdown("Cooldown", COOLDOWN_SECONDS);

  // Stop evaluation AFTER cooldown
  stopEvaluation = true;
  await evalPromise;

  // ---------------- METRICS ----------------

  const globalMetrics = computeGlobalMetrics(experimentResults);
  const perWindowMetrics = computePerWindowMetrics(experimentResults, WINDOWS);
  const latency = computeLatencySeconds(experimentResults);
  const stability = computeStability(experimentResults, WINDOWS);
  const riskSeparation = computeRiskSeparation(experimentResults);

  const output = {
    runId,
    capturedAt: new Date().toISOString(),

    injectionStart: clampIso(injectionStart),
    injectionEnd: clampIso(injectionEnd),

    // NEW: effective truth start (replay start OR infection-aware mapped ingestion time)
    attackStartEffective: clampIso(attackStartEffective),
    truthMode: ATTACK_START_RAW_TS && mappedStart ? "infection_boundary_mapped" : "replay_start",

    baselineSeconds: BASELINE_SECONDS,
    preCooldownSeconds: PRE_COOLDOWN_SECONDS,
    cooldownSeconds: COOLDOWN_SECONDS,
    pollIntervalMs: POLL_INTERVAL_MS,

    windowsEvaluated: WINDOWS,
    totalEvaluations: experimentResults.length,

    results: experimentResults,

    metrics_global_all_windows: globalMetrics,
    metrics_per_window: perWindowMetrics,
    latency_seconds: latency,
    stability,
    risk_separation: riskSeparation,

    replay: {
      python: PYTHON,
      script: REPLAY_SCRIPT,
      exitCode: replayExit,
    },

    infectionBoundary: ATTACK_START_RAW_TS
      ? {
          attack_start_raw_ts: ATTACK_START_RAW_TS,
          recent_logs_url: RECENT_LOGS_URL,
          map_timeout_seconds: MAP_TIMEOUT_SECONDS,
          map_poll_ms: MAP_POLL_MS,
        }
      : null,
  };

  const file = path.join(OUT_DIR, `full_experiment_results_${runId}.json`);
  fs.writeFileSync(file, JSON.stringify(output, null, 2));

  log("\n📊 GLOBAL Metrics (All Windows Combined):");
  log(globalMetrics);

  log(`\n✅ Experiment saved → ${file}`);
})();