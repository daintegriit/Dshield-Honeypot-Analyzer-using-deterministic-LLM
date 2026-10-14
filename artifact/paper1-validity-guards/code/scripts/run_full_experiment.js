/**
 * FULL EXPERIMENT HARNESS (PHASE-CORRECT + TIME-BASED TRUTH + DETECTOR-SCORED)
 * ---------------------------------------------------------------------------
 * Design:
 *   baseline -> (optional pre_cooldown) -> injection -> cooldown
 *
 * WHAT CHANGED (Path B — honest metrics):
 *   1. PREDICTION is the ACTUAL detector output: state ∈ {high,critical} => Attack.
 *      (Previously it was phase/pcap-presence gated, which measured the harness,
 *       not the score.)
 *   2. GROUND TRUTH is TIME-BASED off wall-clock phase boundaries:
 *      Attack iff evaluation time ∈ [attackStartEffective, injectionEnd].
 *      attackStartEffective = injectionStart + INFECTION_OFFSET_REPLAY (seconds),
 *      read from the replay's stdout. No fragile TS= string matching.
 *   3. ISOLATION: the core is queried with ?source=replay so live honeypot
 *      background cannot contaminate the experiment.
 *
 * Runnable:
 *   PCAP_NAME=... RUN_MODE=clean INFECTION_OFFSET_SECONDS=... node run_full_experiment.js
 *   (INFECTION_OFFSET_SECONDS is consumed by the replay; the harness reads the
 *    scaled INFECTION_OFFSET_REPLAY the replay prints.)
 */

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");
const axios = require("axios");

// ---------------- CONFIG ----------------

const BASE_URL = process.env.BASE_URL || "http://localhost:5002";
const LIMIT = Number(process.env.LIMIT || 10000);

// Source scope for the experiment. Replay-only isolation by default.
const SOURCE_SCOPE = process.env.SOURCE_SCOPE || "replay";

// Sliding windows (minutes)
const WINDOWS = (process.env.WINDOWS || "1")
  .split(",")
  .map((x) => Number(x.trim()))
  .filter((n) => Number.isFinite(n) && n > 0);

// Experiment timing
const BASELINE_SECONDS = Number(process.env.BASELINE_SECONDS || 60 * 60);
const PRE_COOLDOWN_SECONDS = Number(process.env.PRE_COOLDOWN_SECONDS || 0);
const INJECTION_MIN_SECONDS = Number(process.env.INJECTION_MIN_SECONDS || 0);

const COOLDOWN_SECONDS_RAW = process.env.COOLDOWN_SECONDS
  ? Number(process.env.COOLDOWN_SECONDS)
  : null;

// Evaluate cadence
const POLL_INTERVAL_MS = Number(process.env.POLL_INTERVAL_MS || 60000);

// PCAP replay runner
const PYTHON = process.env.PYTHON || "python3";
const REPLAY_SCRIPT = path.join(__dirname, "replay_pcap_events.py");

// Hard cap so we never run forever if replay hangs
const MAX_TOTAL_SECONDS = Number(process.env.MAX_TOTAL_SECONDS || 60 * 60 * 8);

const OUT_DIR = path.join(__dirname, "../outputs/full_experiment");
fs.mkdirSync(OUT_DIR, { recursive: true });

const runId = new Date().toISOString().replace(/[:.]/g, "-");
const pcap = process.env.PCAP_NAME || "unknown";
const mode = process.env.RUN_MODE || "unknown";

const safePcap = pcap.replace(/[^\w\-]/g, "_");

// ---------------- LOGGING ----------------
const logFilePath = path.join(OUT_DIR, `${safePcap}_${mode}_${runId}.log`);
const logStream = fs.createWriteStream(logFilePath, { flags: "w" });

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

// Auto-cooldown: exceed the largest window so TN can accumulate
const largestWindowMin = Math.max(...WINDOWS);
const effectiveWindowMin = Math.max(largestWindowMin, 60);
const defaultCooldownSeconds = effectiveWindowMin * 60;

const COOLDOWN_SECONDS =
  COOLDOWN_SECONDS_RAW && Number.isFinite(COOLDOWN_SECONDS_RAW) && COOLDOWN_SECONDS_RAW > 0
    ? COOLDOWN_SECONDS_RAW
    : defaultCooldownSeconds;

// ---------------- STATE ----------------

let injectionStart = null;          // Date (replay start wall-clock)
let injectionEnd = null;            // Date (replay end wall-clock)
let attackStartEffective = null;    // Date (truth start = injectionStart + infection offset)
let infectionOffsetReplaySec = 0;   // parsed from replay stdout
let phase = "baseline";             // baseline | pre_cooldown | injection | cooldown

let experimentResults = [];
let stopEvaluation = false;
let prevState = null;

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

// ---------------- GROUND TRUTH (TIME-BASED) ----------------
/**
 * Attack iff the evaluation moment lies within
 *   [attackStartEffective, injectionEnd]
 * Everything else (baseline, pre-infection benign window, cooldown) is Normal.
 * Purely time-driven — no dependence on pcap-presence or phase heuristics.
 */
function labelGroundTruth(windowEndTime, windowMinutes) {
  if (!attackStartEffective) return "Normal";

  const t = windowEndTime.getTime();
  const start = attackStartEffective.getTime();
  const end = injectionEnd ? injectionEnd.getTime() : Date.now();

  // A scoring window covers [windowEnd - windowMinutes, windowEnd]. When the
  // infection boundary falls inside that span the window contains both pre-
  // and post-infection traffic, and neither label describes it. Labelling by
  // the window END alone assigns such a window to Attack, counting traffic
  // that predates the infection as evidence of it.
  //
  // At 1-minute windows this affects one window per run. At 5 minutes with
  // 1-minute polling it affects five, because consecutive windows overlap.
  // Such windows are returned as null and excluded from the confusion matrix;
  // the exclusion count is reported.
  const spanMs = (Number(windowMinutes) || 0) * 60000;
  if (spanMs > 0) {
    const windowStart = t - spanMs;
    if (windowStart < start && t >= start) return null;
    if (injectionEnd && windowStart < end && t > end) return null;
  }

  if (t >= start && t <= end) return "Attack";
  return "Normal";
}

// ---------------- METRICS ----------------

function computeConfusion(results) {
  let TP = 0, FP = 0, TN = 0, FN = 0;

  // Windows straddling the infection boundary carry truth === null and
  // fall through every branch below. Counted so the exclusion appears in
  // the output rather than silently reducing the sample.
  const excluded = results.filter((r) => r.truth === null).length;

  for (const r of results) {
    // Detector decision vs time-based truth. Both are honest.
    if (r.truth === "Attack" && r.detectorPredicted === "Attack") TP++;
    if (r.truth === "Normal" && r.detectorPredicted === "Attack") FP++;
    if (r.truth === "Normal" && r.detectorPredicted === "Normal") TN++;
    if (r.truth === "Attack" && r.detectorPredicted === "Normal") FN++;
  }

  return { TP, FP, TN, FN, excluded_straddling: excluded };
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
      .filter((r) => r.detectorPredicted === "Attack" && r.truth === "Attack")
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
      if (prev && r.detectorPredicted !== prev) flips++;
      prev = r.detectorPredicted;
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
    else if (r.truth === "Normal") normal.push(v);
  }

  function m(arr) {
    if (!arr.length) return null;
    return arr.reduce((a, b) => a + b, 0) / arr.length;
  }

  const mA = m(attack);
  const mN = m(normal);

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

    for (const minutes of WINDOWS) {
      try {
        // Query the core scoped to replay-only traffic (isolation).
        const res = await axios.get(
          `${BASE_URL}/api/copilot/insight?minutes=${minutes}&limit=${LIMIT}&source=${SOURCE_SCOPE}`,
          { timeout: 120000 }
        );

        const now = new Date();
        const summary = res.data || {};
        const core = summary.coreSummary || {};

        // The detector's ACTUAL decision.
        const state = core.state ?? "stable";
        const detectorPredicted =
          state === "high" || state === "critical" ? "Attack" : "Normal";

        // Time-based ground truth.
        const truth = labelGroundTruth(now, minutes);

        const attackScores = core?.attackClassification?.attackTypeScores || {};
        const dominant = core?.attackClassification?.dominantAttack || {};
        const riskComp = core?.riskComponents || {};
        const scanIndicators = core?.scanningIndicators || {};
        // The C2 component's five sub-signals. Without these, a window
        // scoring 75 on c2 cannot be attributed to periodicity, flow
        // persistence, or peer dominance after the fact.
        const c2Signals = core?.attackClassification?.c2Signals || {};
        const attackMetrics = core?.attackMetrics || {};

        experimentResults.push({
          timestamp: now.toISOString(),
          phase,
          window_minutes: minutes,

          detectorPredicted,
          truth,

          state,
          riskScore: core?.riskScore0to100 ?? null,

          startState: prevState ?? state,
          endState: state,
          isTransition: prevState !== null && prevState !== state,

          attackScores,
          dominantAttack: dominant,
          attackMetrics,
          scanningIndicators: scanIndicators,
          c2Signals,
          riskComponents: riskComp,

          sourceFilter: core?.sourceFilter ?? summary?.sourceFilter ?? "unknown",
          attack_start_effective: attackStartEffective
            ? attackStartEffective.toISOString()
            : null,
        });

        prevState = state;

        log(
          `\n[${now.toISOString()}] phase=${phase} | window=${minutes}m | scope=${SOURCE_SCOPE}\n` +
          `Detector: ${detectorPredicted} | Truth: ${truth} | ` +
          `Risk: ${core.riskScore0to100 ?? "n/a"} | State: ${state}\n` +
          `--- Attack Volume ---\n` +
          `1m=${attackMetrics.attacksLast1Min ?? "n/a"} | ` +
          `5m=${attackMetrics.attacksLast5Min ?? "n/a"} | ` +
          `15m=${attackMetrics.attacksLast15Min ?? "n/a"} | ` +
          `1h=${attackMetrics.attacksLastHour ?? "n/a"} | ` +
          `burst5m/h=${attackMetrics.burstRatio5mOverHour ?? "n/a"}\n` +
          `--- Attack Type Scores ---\n` +
          `dos=${attackScores.dos ?? "n/a"} | scan=${attackScores.scan ?? "n/a"} | ` +
          `brute=${attackScores.brute_force ?? "n/a"} | web=${attackScores.web_probe ?? "n/a"} | ` +
          `c2=${attackScores.c2 ?? "n/a"} | impact=${attackScores.impact ?? "n/a"}\n` +
          `Dominant: ${dominant.type ?? "unknown"} (${dominant.score ?? "n/a"})\n` +
          `--- Risk Components ---\n` +
          `vol=${riskComp.volumeComponent ?? "n/a"} | sev=${riskComp.severityComponent ?? "n/a"} | ` +
          `beh=${riskComp.behaviorComponent ?? "n/a"} | amp=${riskComp.signalAmplifier ?? "n/a"} | ` +
          `c2B=${riskComp.c2Bonus ?? "n/a"} | impB=${riskComp.impactBonus ?? "n/a"} | ` +
          `cplB=${riskComp.couplingBonus ?? "n/a"}\n`
        );
      } catch (err) {
        const msg = err?.response?.data
          ? JSON.stringify(err.response.data)
          : err.message;
        logError(`Evaluation error (${minutes}m): ${msg}`);
      }
    }

    await sleepUntilNextInterval(startedAtMs, POLL_INTERVAL_MS);
  }

  log("🛑 Evaluation loop stopped");
}

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

  log("\n🚀 STARTING FULL EXPERIMENT (TIME-BASED TRUTH + DETECTOR-SCORED)\n");
  log(`BASE_URL=${BASE_URL}`);
  log(`SOURCE_SCOPE=${SOURCE_SCOPE}`);
  log(`WINDOWS=${WINDOWS.join(",")} (largest=${largestWindowMin}m)`);
  log(
    `Baseline=${BASELINE_SECONDS}s | PreCooldown=${PRE_COOLDOWN_SECONDS}s | ` +
    `Cooldown=${COOLDOWN_SECONDS}s | Poll=${POLL_INTERVAL_MS}ms`
  );
  log(`Replay=${PYTHON} ${REPLAY_SCRIPT}`);
  log(`Max runtime cap=${MAX_TOTAL_SECONDS}s`);

  // Start evaluation FIRST so baseline is captured
  const evalPromise = evaluationLoop(startedAtMs);

  // ---------------- BASELINE ----------------
  phase = "baseline";
  log(`\n🧊 BASELINE PHASE: ${BASELINE_SECONDS}s (evaluating now)`);
  await countdown("Baseline", BASELINE_SECONDS);

  // ---------------- PRE-COOLDOWN (optional) ----------------
  if (PRE_COOLDOWN_SECONDS > 0) {
    phase = "pre_cooldown";
    log(`\n❄️ PRE-COOLDOWN BUFFER: ${PRE_COOLDOWN_SECONDS}s`);
    await countdown("Pre-Cooldown", PRE_COOLDOWN_SECONDS);
  }

  // ---------------- INJECTION ----------------
  phase = "injection";
  log("\n💉 Starting PCAP injection...");

  const injectionStartedAt = Date.now();
  injectionStart = new Date(injectionStartedAt);

  // Provisional truth start = injection start; refined once we read the offset.
  attackStartEffective = injectionStart;

  const replay = spawn(PYTHON, [REPLAY_SCRIPT], {
    cwd: __dirname,
    env: process.env,
  });

  log(`DEBUG injectionStart = ${injectionStart.toISOString()}`);

  replay.stdout.on("data", (data) => {
    const text = data.toString();
    process.stdout.write(text);

    const m1 = text.match(/PCAP_NAME=(.+)/);
    if (m1) log(`📦 Detected PCAP: ${m1[1].trim()}`);

    const m2 = text.match(/INFECTION_OFFSET_REPLAY=([0-9.]+)/);
    if (m2) {
      infectionOffsetReplaySec = Number(m2[1]);
      attackStartEffective = new Date(
        injectionStart.getTime() + infectionOffsetReplaySec * 1000
      );
      log(
        `🎯 Infection offset (replay-time) = ${infectionOffsetReplaySec}s → ` +
        `Attack truth starts at ${attackStartEffective.toISOString()}`
      );
    }
  });

  replay.stderr.on("data", (data) => {
    process.stderr.write(data.toString());
  });

  // Wait for replay to finish
  const replayExit = await new Promise((resolve) => {
    replay.on("exit", (code) => resolve(code));
    replay.on("error", () => resolve(1));
  });

  const injectionEndedAt = Date.now();
  injectionEnd = new Date(injectionEndedAt);
  log(`DEBUG injectionEnd   = ${injectionEnd.toISOString()}`);

  const injDurSec = (injectionEndedAt - injectionStartedAt) / 1000;
  log(`\n💉 Injection complete (exit=${replayExit}) duration=${injDurSec.toFixed(1)}s`);

  // ---------------- COOLDOWN ----------------
  phase = "cooldown";
  log(
    `\n❄️ COOLDOWN PHASE: ${COOLDOWN_SECONDS}s ` +
    `(must exceed largest window ${largestWindowMin}m to accumulate TN)`
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
    [...experimentResults].reverse().find((r) => r.phase === "injection") || null;

  // Detector configuration as reported by the backend itself, rather than as
  // assumed by this harness. The core publishes its risk budget, profile and
  // normalisation state; the C2 gate values are read from the environment the
  // backend was started with, which this harness cannot see directly and so
  // records as "unknown" unless supplied.
  let detectorConfig = { captured: false };
  try {
    const probeRes = await axios.get(
      // Unscoped and cached: riskBudget is a property of the backend
      // configuration, not of the scope, so the 2 ms cached response carries
      // the same profile and normalisation state. A scoped request would
      // bypass the cache and add up to 80 s to every run.
      `${BASE_URL}/api/copilot/insight`,
      { timeout: 30000 }
    );
    const probe = probeRes.data;
    const budget = probe?.coreSummary?.riskBudget || {};
    detectorConfig = {
      captured: true,
      capturedAt: new Date().toISOString(),
      coreVersion: probe?.coreSummary?.coreVersion || null,
      riskProfile: budget.profile || null,
      normalised: budget.normalised ?? null,
      reachableBudget: budget.reachableBudget ?? null,
      referenceBudget: budget.referenceBudget ?? null,
      reachable: budget.reachable || null,
      stateThresholds: { elevated: 45, high: 60, critical: 85 },
      // Supplied by the caller when running an ablation; absent means the
      // backend defaults were in effect, which this harness cannot verify.
      // Read from the backend's own report rather than from this process's
      // environment, which does not describe the backend.
      c2Gates: probe?.coreSummary?.detectorGates || "not reported by backend",
      replay: {
        mode: process.env.REPLAY_MODE || "scaled_ts",
        sourceWindowPre: Number(process.env.SOURCE_WINDOW_PRE || 0),
        sourceWindowPost: Number(process.env.SOURCE_WINDOW_POST || 0),
        targetDurationSeconds: Number(process.env.TARGET_DURATION_SECONDS || 5400),
      },
      note:
        "c2Gates values marked 'backend default' were not set by this harness. " +
        "The backend is a separate long-running process and may have been " +
        "started with overrides this run cannot observe.",
    };
  } catch (e) {
    detectorConfig = { captured: false, error: e.message };
  }

  const output = {
    runId,
    detectorConfig,
    capturedAt: new Date().toISOString(),

    pcap,
    mode,
    sourceScope: SOURCE_SCOPE,

    injectionStart: clampIso(injectionStart),
    injectionEnd: clampIso(injectionEnd),
    attackStartEffective: clampIso(attackStartEffective),
    infectionOffsetReplaySeconds: infectionOffsetReplaySec,
    truthMode: "time_based_infection_offset",

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
        startedAt: clampIso(new Date(startedAtMs)),
        endedAt: clampIso(injectionStart),
        durationSeconds: BASELINE_SECONDS,
        durationMinutes: Number((BASELINE_SECONDS / 60).toFixed(2)),
      },
      {
        phase: "injection",
        pcapName: pcap,
        groundTruth: "Attack",
        startedAt: clampIso(injectionStart),
        endedAt: clampIso(injectionEnd),
        attackTruthStart: clampIso(attackStartEffective),
        durationSeconds: Number(injDurSec.toFixed(2)),
        durationMinutes: Number((injDurSec / 60).toFixed(2)),
        overlay: {
          state: latestInjectionResult?.endState || "stable",
          riskScore0to100: latestInjectionResult?.riskScore || 0,
          dominantAttack: latestInjectionResult?.dominantAttack?.type || "unknown",
        },
      },
      {
        phase: "cooldown",
        pcapName: pcap,
        groundTruth: "Normal",
        startedAt: clampIso(injectionEnd),
        endedAt: clampIso(
          injectionEnd ? new Date(injectionEnd.getTime() + COOLDOWN_SECONDS * 1000) : null
        ),
        durationSeconds: COOLDOWN_SECONDS,
        durationMinutes: Number((COOLDOWN_SECONDS / 60).toFixed(2)),
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
  };

  const file = path.join(OUT_DIR, `${safePcap}_${mode}_${runId}.json`);
  fs.writeFileSync(file, JSON.stringify(output, null, 2));

  log("\n📊 GLOBAL Metrics (All Windows Combined):");
  log(globalMetrics);
  log("\n📊 RISK SEPARATION (honest headline):");
  log(riskSeparation);

  log(`\n✅ Experiment saved → ${file}`);
})();
