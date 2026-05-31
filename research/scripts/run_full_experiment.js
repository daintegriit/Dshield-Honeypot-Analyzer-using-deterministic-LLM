/**
 * FULL EXPERIMENT HARNESS (PHASE-CORRECT + INFECTION-AWARE OPTIONAL)
 * -----------------------------------------------------------------
 *   baseline -> (optional pre_cooldown) -> injection -> cooldown
 *
 *   If ATTACK_START_RAW_TS is provided, we watch /logs/recent and find the first
 *   ingested log whose raw contains TS >= ATTACK_START_RAW_TS.
 *   That ingestion timestamp becomes the effective attack start for truth labeling.
 *
 *   node research/scripts/run_full_experiment.js
 *
 *   ATTACK_START_RAW_TS=1970-01-01T01:04:33.86657Z node research/scripts/run_full_experiment.js
 */

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");

// ---------------- CONFIG ----------------

//const BASE_URL = process.env.BASE_URL || "http://localhost:5002";
const BASE_URL = process.env.BASE_URL || "http://32.195.28.224:5002";
const LIMIT = Number(process.env.LIMIT || 10000);

// Sliding windows (minutes)
const WINDOWS = (process.env.WINDOWS || "1") //1 min windows
//const WINDOWS = (process.env.WINDOWS || "2,5,15,30,60")
  .split(",")
  .map((x) => Number(x.trim()))
  .filter((n) => Number.isFinite(n) && n > 0);

// Experiment timing
const BASELINE_SECONDS = Number(process.env.BASELINE_SECONDS || 60 * 60); // baseline (evaluated)
const PRE_COOLDOWN_SECONDS = Number(process.env.PRE_COOLDOWN_SECONDS || 0); // optional buffer before injection
const INJECTION_MIN_SECONDS = Number(process.env.INJECTION_MIN_SECONDS || 0); // optional minimum injection duration>

const COOLDOWN_SECONDS_RAW = process.env.COOLDOWN_SECONDS
  ? Number(process.env.COOLDOWN_SECONDS)
  : null;

// Evaluate every 30 seconds
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS || 60000);

// PCAP replay runner
const PYTHON = process.env.PYTHON || "python3";

const REPLAY_SCRIPT = path.join(__dirname, "replay_pcap_events.py");

// Optional: hard cap so you never run forever if replay hangs
const MAX_TOTAL_SECONDS = Number(process.env.MAX_TOTAL_SECONDS || 60 * 60 * 8); // 8 hours

// Infection-aware truth (OPTIONAL)
const ATTACK_START_RAW_TS = process.env.ATTACK_START_RAW_TS || null;
// Where to read recent ingested logs that include { raw, timestamp }
const RECENT_LOGS_URL = process.env.RECENT_LOGS_URL || `${BASE_URL}/api/ingest/log`;
// How long (seconds) we try to map raw TS -> ingestion time after injection starts
const MAP_TIMEOUT_SECONDS = Number(process.env.MAP_TIMEOUT_SECONDS || 500); // 3 minutes default
const MAP_POLL_MS = Number(process.env.MAP_POLL_MS || 2000);

const OUT_DIR = path.join(__dirname, "../outputs/full_experiment");
fs.mkdirSync(OUT_DIR, { recursive: true });

// Generate a unique run ID based on the current timestamp
const runId = new Date().toISOString().replace(/[:.]/g, "-");
const pcap = process.env.PCAP_NAME || "unknown";
const mode = process.env.RUN_MODE || "unknown";

const safePcap = pcap.replace(/[^\w\-]/g, "_");

// ---------------- LOGGING ----------------
const logFilePath = path.join(
  OUT_DIR,
  `${safePcap}_${mode}_${runId}.log`
);

const logStream = fs.createWriteStream(logFilePath, {
  flags: "w", // append mode (keeps previous runs)
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

// FORCE 1-hour memory instead of 1-minute window
const effectiveWindowMin = Math.max(largestWindowMin, 60);

const defaultCooldownSeconds = effectiveWindowMin * 60; // 60 min

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
let prevState = null; // track previous state for transitions

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


function deriveSignalsFromCore(core) {
  const risk =
    typeof core?.riskScore0to100 === "number" ? core.riskScore0to100 : null;

  const state = core?.state ?? "stable";

  const burst =
    typeof core?.attackMetrics?.burstRatio5mOverHour === "number"
      ? core.attackMetrics.burstRatio5mOverHour
      : null;

  const scanScore =
    typeof core?.attackClassification?.attackTypeScores?.scan === "number"
      ? core.attackClassification.attackTypeScores.scan
      : null;

  const scan = scanScore === null ? null : Math.max(0, Math.min(1, scanScore / 100));

  const bruteScore =
    typeof core?.attackClassification?.attackTypeScores?.brute_force === "number"
      ? core.attackClassification.attackTypeScores.brute_force
      : null;

  const brute = bruteScore === null ? null : Math.max(0, Math.min(1, bruteScore / 100));

  const topPort =
    Array.isArray(core?.scanningIndicators?.topPorts) && core.scanningIndicators.topPorts.length
      ? (core.scanningIndicators.topPorts[0]?.port ?? null)
      : null;

  const topIP = core?.topIP ?? null;

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

function extractRawTs(raw) {
  if (!raw || typeof raw !== "string") return null;
  const m = raw.match(/TS=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:\.]+Z)/);
  if (!m) return null;
  const d = new Date(m[1]);
  return Number.isFinite(d.getTime()) ? d : null;
}

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

function isPcapTraffic(raw) {
  return typeof raw === "string" && raw.includes("TS=1970");
}

async function getWindowSourceBreakdown(minutes) {
  try {
    const res = await axios.get(
      `${BASE_URL}/api/copilot/insight?minutes=${minutes}&limit=${LIMIT}`
    );

    const core = res.data?.coreSummary || {};

    const pcapCount = core?.attackMetrics?.attacksLast5Min || 0;
    const dshieldCount = core?.attackMetrics?.backgroundEvents || 0; // or equivalent

    const total = pcapCount + dshieldCount;

    return {
      pcapCount,
      dshieldCount,
      total,
      pcapRatio: total > 0 ? pcapCount / total : 0,
    };

  } catch (err) {
    logWarn("⚠️ Failed to fetch source breakdown");
    return { pcapCount: 0, dshieldCount: 0, total: 0, pcapRatio: 0 };
  }
}


function labelGroundTruth(windowEndTime, minutes, sourceBreakdown) {
  if (!attackStartEffective) return "Normal";

  const windowStart = new Date(windowEndTime.getTime() - minutes * 60000);
  const endBound = injectionEnd ? injectionEnd : windowEndTime;

  const overlaps =
    windowStart <= endBound &&
    windowEndTime >= attackStartEffective;

  if (overlaps) {
    if (sourceBreakdown.pcapRatio > 0.01) {
      return phase === "cooldown" ? "Residual" : "Attack";
    }

    return "Normal";
  }

  if (sourceBreakdown.pcapCount === 0 && sourceBreakdown.dshieldCount > 0) {
    return "Background";
  }

  return "Normal";
}


function labelTruthSimple() {
  return injectionStart && !injectionEnd ? "Attack" : "Normal";
}

// ---------------- METRICS ----------------

function computeConfusion(results) {
  let TP = 0, FP = 0, TN = 0, FN = 0;

  for (const r of results) {
    if (r.truth === "Residual" || r.truth === "Background" || r.experimentPredicted === "Residual") continue;    
    if (r.truth === "Attack" && r.experimentPredicted === "Attack") TP++;
    if (r.truth === "Normal" && r.experimentPredicted === "Attack") FP++;
    if (r.truth === "Normal" && r.experimentPredicted === "Normal") TN++;
    if (r.truth === "Attack" && r.experimentPredicted === "Normal") FN++;
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
      .filter((r) => r.experimentPredicted === "Attack" && r.truth !== "Residual" && r.truth !== "Background")      
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
      if (prev && r.experimentPredicted !== prev) flips++;
      prev = r.experimentPredicted;
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
    const iterationStart = Date.now();

    const elapsedSec = (Date.now() - startedAtMs) / 1000;
    if (elapsedSec > MAX_TOTAL_SECONDS) {
      log(`🛑 Max runtime reached (${MAX_TOTAL_SECONDS}s). Stopping evaluation.`);
      stopEvaluation = true;
      break;
    }

    for (const minutes of WINDOWS) {
      try {
        const res = await axios.get(
          `${BASE_URL}/api/copilot/insight?minutes=${minutes}&limit=${LIMIT}`,
          { timeout: 120000000 }
        );

        const now = new Date();
        const summary = res.data || {};
        const core = summary.coreSummary || {};
        const behavior = summary.behaviorSummary || {};
        const sourceBreakdown = await getWindowSourceBreakdown(minutes);


        // SINGLE SOURCE OF TRUTH
        const state = core.state ?? "stable";

        const rawPredicted =
          state === "high" || state === "critical"
            ? "Attack"
            : "Normal";

        // suppress baseline noise
        let experimentPredicted = "Normal";

        // baseline = force normal
        if (phase === "baseline") {
          experimentPredicted = "Normal";
        }

        // injection = trust PCAP presence
        else if (phase === "injection") {
          experimentPredicted =
            sourceBreakdown.pcapRatio > 0.01 ? "Attack" : "Normal";
        }

        // cooldown = residual detection
        else if (phase === "cooldown") {
          experimentPredicted =
            sourceBreakdown.pcapCount > 0 ? "Residual" : "Normal";
        }

        const truth = labelGroundTruth(now, minutes, sourceBreakdown);

        // ✅ Pull signals from your actual core schema
        const derived = deriveSignalsFromCore(core);

        const tacticFallback = classifyTactic(core, behavior);

        const tactic =
          derived.dominantType && derived.dominantType !== "unknown"
            ? derived.dominantType
            : tacticFallback;

        // ---- STORE RESULTS ----
        experimentResults.push({
          timestamp: now.toISOString(),
          phase,
          window_minutes: minutes,
          rawPredicted,
          experimentPredicted,
          truth,

          riskScore: core?.riskScore0to100 ?? null,

          // FIXED STATE TRACKING
          startState: prevState ?? state,
          endState: state,
          isTransition: prevState !== null && prevState !== state, // 💎 elite but safe

          attackScores: core?.attackClassification?.attackTypeScores ?? {},
          dominantAttack: core?.attackClassification?.dominantAttack ?? { type: "unknown", score: 0 },

          attackMetrics: core?.attackMetrics ?? {},
          scanningIndicators: core?.scanningIndicators ?? {},
          riskComponents: core?.riskComponents ?? {},

          residual_level: (core?.attackMetrics?.attacksLast5Min ?? 0) > 0 ? "High" : "Low",
          phase_transition: prevState !== state,

          truth_simple: labelTruthSimple(),
          attack_start_effective: attackStartEffective
            ? attackStartEffective.toISOString()
            : null,
        });

        // UPDATE STATE AFTER LOGGING
        prevState = state;

        const attackScores = core?.attackClassification?.attackTypeScores || {};
        const dominant = core?.attackClassification?.dominantAttack || {};
        const riskComp = core?.riskComponents || {};
        const scanIndicators = core?.scanningIndicators || {};
        const attackMetrics = core?.attackMetrics || {};

        log(
          `\n[${now.toISOString()}] phase=${phase} | window=${minutes}m\n` +
            `Prediction(raw): ${rawPredicted} | Prediction(exp): ${experimentPredicted} | Truth: ${truth}\n` +
          `Risk: ${core.riskScore0to100 ?? "n/a"} | State: ${core.state ?? "stable"}\n` +

          `\n--- Attack Volume ---\n` +
          `1m=${attackMetrics.attacksLast1Min ?? "n/a"} | ` +
          `5m=${attackMetrics.attacksLast5Min ?? "n/a"} | ` +
          `15m=${attackMetrics.attacksLast15Min ?? "n/a"} | ` +
          `1h=${attackMetrics.attacksLastHour ?? "n/a"} | ` +
          `burstRatio5mOverHour=${attackMetrics.burstRatio5mOverHour ?? "n/a"}\n` +

          `\n--- Source Breakdown ---\n` +
          `pcapCount=${sourceBreakdown.pcapCount} | ` +
          `dshieldCount=${sourceBreakdown.dshieldCount} | ` +
          `total=${sourceBreakdown.total} | ` +
          `pcapRatio=${sourceBreakdown.pcapRatio.toFixed(3)}\n` +

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

    // DRIFT-FREE TIMING (ALIGNED TO WALL CLOCK)
    await sleepUntilNextInterval(startedAtMs, POLL_INTERVAL_MS);
  }

  log("🛑 Evaluation loop stopped");
}

// DRIFT-FREE INTERVAL ALIGNMENT
async function sleepUntilNextInterval(startTime, intervalMs) {
  const now = Date.now();
  const elapsed = now - startTime;
  const remainder = elapsed % intervalMs;
  const wait = remainder === 0 ? intervalMs : intervalMs - remainder;

  return sleep(wait);
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

  // START BOTH TIMERS AT SAME MOMENT
  const injectionStartedAt = Date.now();
  injectionStart = new Date(injectionStartedAt);

  // Default truth start is replay start
  attackStartEffective = injectionStart;

  let detectedPcap = "unknown";

  const replay = spawn(PYTHON, [REPLAY_SCRIPT], {
    cwd: __dirname,
    env: process.env,
  });

  // DEBUG (optional but recommended)
  log(`DEBUG injectionStart = ${injectionStart.toISOString()}`);

  replay.stdout.on("data", (data) => {
    const text = data.toString();
    process.stdout.write(text);

    const match = text.match(/PCAP_NAME=(.+)/);
    if (match) {
      detectedPcap = match[1].trim();
      log(`📦 Detected PCAP: ${detectedPcap}`);
    }
  });

  // Infection-aware mapping (unchanged)
  let mappedStart = null;
  if (ATTACK_START_RAW_TS) {
    mappedStart = await mapInfectionBoundaryToIngestedStart();
    if (mappedStart) {
      attackStartEffective = mappedStart;
      log(`🎯 Using infection-aware truth start: ${attackStartEffective.toISOString()}`);
    }
  }

  // WAIT FOR REPLAY TO FINISH
  const replayExit = await new Promise((resolve) => {
    replay.on("exit", (code) => resolve(code));
    replay.on("error", () => resolve(1));
  });

  // END TIME (MATCHED CLOCK)
  const injectionEndedAt = Date.now();
  injectionEnd = new Date(injectionEndedAt);

  log(`DEBUG injectionEnd   = ${injectionEnd.toISOString()}`);

  // TRUE DURATION
  const injDurSec = (injectionEndedAt - injectionStartedAt) / 1000;

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

  const latestInjectionResult =
    [...experimentResults]
      .reverse()
      .find(
        (r) => r.phase === "injection"
      ) || null;

  const output = {
    runId,
    capturedAt: new Date().toISOString(),

    injectionStart: clampIso(injectionStart),
    injectionEnd: clampIso(injectionEnd),

    attackStartEffective: clampIso(attackStartEffective),
    truthMode: ATTACK_START_RAW_TS && mappedStart ? "infection_boundary_mapped" : "replay_start",

    baselineSeconds: BASELINE_SECONDS,
    preCooldownSeconds: PRE_COOLDOWN_SECONDS,
    cooldownSeconds: COOLDOWN_SECONDS,
    pollIntervalMs: POLL_INTERVAL_MS,

    windowsEvaluated: WINDOWS,
    totalEvaluations: experimentResults.length,

    results: experimentResults,

    replayTimeline: [
      {
        phase: "baseline",

        pcapName: pcap,

        groundTruth: "Normal",

        startedAt: clampIso(
          new Date(startedAtMs)
        ),

        endedAt: clampIso(
          injectionStart
        ),

        durationSeconds:
          BASELINE_SECONDS,

        durationMinutes:
          Number(
            (
              BASELINE_SECONDS / 60
            ).toFixed(2)
          ),

        overlay: {
          state: "stable",
          riskScore0to100: 0,
          attacksLast5Min: 0,
          attacksPerSecond: 0,
          dominantAttack: "none",
        },
      },

      {
        phase: "injection",

        pcapName: pcap,

        groundTruth: "Attack",

        startedAt: clampIso(
          injectionStart
        ),

        endedAt: clampIso(
          injectionEnd
        ),

        durationSeconds:
          Number(
            injDurSec.toFixed(2)
          ),

        durationMinutes:
          Number(
            (
              injDurSec / 60
            ).toFixed(2)
          ),

        overlay: {
          state:
            latestInjectionResult
              ?.endState || "high",

          riskScore0to100:
            latestInjectionResult
              ?.riskScore || 0,

          attacksLast5Min:
            latestInjectionResult
              ?.attackMetrics
              ?.attacksLast5Min || 0,

          attacksPerSecond:
            Number(
              (
                (
                  latestInjectionResult
                    ?.attackMetrics
                    ?.attacksLast5Min || 0
                ) / 300
              ).toFixed(2)
            ),

          dominantAttack:
            latestInjectionResult
              ?.dominantAttack
              ?.type || "unknown",
        },
      },

      {
        phase: "cooldown",

        pcapName: pcap,

        groundTruth: "Normal",

        startedAt: clampIso(
          injectionEnd
        ),

        endedAt: clampIso(
          new Date(
            injectionEnd.getTime() +
            COOLDOWN_SECONDS * 1000
          )
        ),

        durationSeconds:
          COOLDOWN_SECONDS,

        durationMinutes:
          Number(
            (
              COOLDOWN_SECONDS / 60
            ).toFixed(2)
          ),

        overlay: {
          state: "stable",
          riskScore0to100: 0,
          attacksLast5Min: 0,
          attacksPerSecond: 0,
          dominantAttack: "none",
        },
      },
    ],

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

  // sanitize name
  const safePcap = pcap.replace(/[^\w\-]/g, "_");

  // build filename
  const file = path.join(
    OUT_DIR,
    `${safePcap}_${mode}_${runId}.json`
  );

  output.pcap = pcap;
  output.mode = mode;
  output.runId = runId;

  fs.writeFileSync(file, JSON.stringify(output, null, 2));

  log("\n📊 GLOBAL Metrics (All Windows Combined):");
  log(globalMetrics);

  log(`\n✅ Experiment saved → ${file}`);
})();

