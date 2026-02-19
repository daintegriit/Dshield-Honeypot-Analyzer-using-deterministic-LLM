require("dotenv").config();
const mongoose = require("mongoose");
const Attack = require("../../models/AttackModel");

// ------------------------------------
// CONFIG
// ------------------------------------
const WINDOWS = {
  "15m": 15 * 60 * 1000,
  "60m": 60 * 60 * 1000,
  "24h": 24 * 60 * 60 * 1000,
};

const SLIDE = 60 * 60 * 1000; // 1 hour step

// ------------------------------------
// Helpers
// ------------------------------------
function logSection(title) {
  console.log("\n" + "─".repeat(70));
  console.log(`🔹 ${title}`);
  console.log("─".repeat(70));
}

// ---- Progress Bar ----
function renderProgress(current, total, meta = "") {
  const width = 30;
  const ratio = current / total;
  const filled = Math.round(ratio * width);
  const empty = width - filled;
  const percent = Math.round(ratio * 100);

  const bar = "█".repeat(filled) + "░".repeat(empty);
  process.stdout.write(
    `\r[${bar}] ${percent}% | ${current}/${total} ${meta}`
  );
}

function endProgress() {
  process.stdout.write("\n");
}

// ---- Metrics ----
function computeMetrics(attacks) {
  if (!attacks.length) {
    return {
      total: 0,
      ips: 0,
      asns: 0,
      concentration: 0,
    };
  }

  const ips = new Set(attacks.map(a => a.source_ip)).size;
  const asns = new Set(attacks.map(a => a.asn).filter(Boolean)).size;

  const ports = {};
  for (const a of attacks) {
    if (!a.target_port) continue;
    ports[a.target_port] = (ports[a.target_port] || 0) + 1;
  }

  const topPort = Object.values(ports).length
    ? Math.max(...Object.values(ports))
    : 0;

  return {
    total: attacks.length,
    ips,
    asns,
    concentration: Number((topPort / attacks.length).toFixed(3)),
  };
}

function summarize(values) {
  if (!values.length) return { mean: 0, variance: 0 };

  const mean = values.reduce((a, b) => a + b, 0) / values.length;
  const variance =
    values.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / values.length;

  return {
    mean: Number(mean.toFixed(3)),
    variance: Number(variance.toFixed(6)),
  };
}

// ------------------------------------
// Main
// ------------------------------------
async function run() {
  logSection("FULL DATASET BEHAVIOR STABILITY");

  await mongoose.connect(process.env.MONGO_URI);
  console.log("✅ Connected to MongoDB");

  // ------------------------------------
  // Dataset bounds (FULL DATASET)
  // ------------------------------------
  const earliest = await Attack.findOne({}, { timestamp: 1 })
    .sort({ timestamp: 1 })
    .lean();

  const latest = await Attack.findOne({}, { timestamp: 1 })
    .sort({ timestamp: -1 })
    .lean();

  if (!earliest?.timestamp || !latest?.timestamp) {
    throw new Error("Dataset timestamps missing");
  }

  const start = new Date(earliest.timestamp);
  const end = new Date(latest.timestamp);

  console.log("📅 Dataset range:");
  console.log("   From:", start.toISOString());
  console.log("   To:  ", end.toISOString());

  const results = {
    "15m": [],
    "60m": [],
    "24h": [],
  };

  // ------------------------------------
  // Sliding windows across ENTIRE dataset
  // ------------------------------------
  logSection("Sliding Window Analysis");

  const totalSteps = Math.ceil((end.getTime() - start.getTime()) / SLIDE);
  let step = 0;

  for (let t = start.getTime(); t <= end.getTime(); t += SLIDE) {
    step++;
    const anchor = new Date(t);

    renderProgress(
      step,
      totalSteps,
      `| ${anchor.toISOString()}`
    );

    for (const [label, size] of Object.entries(WINDOWS)) {
      const since = new Date(anchor.getTime() - size);

      const attacks = await Attack.find(
        {
          timestamp: { $gte: since, $lte: anchor },
        },
        {
          source_ip: 1,
          asn: 1,
          target_port: 1,
        }
      ).lean();

      results[label].push(computeMetrics(attacks));
    }
  }

  endProgress();

  // ------------------------------------
  // Aggregate Stability
  // ------------------------------------
  logSection("Stability Results");

  const report = {};
  for (const label of Object.keys(results)) {
    report[label] = {
      total_attacks: summarize(results[label].map(r => r.total)),
      unique_ips: summarize(results[label].map(r => r.ips)),
      unique_asns: summarize(results[label].map(r => r.asns)),
      port_concentration: summarize(
        results[label].map(r => r.concentration)
      ),
      windows_analyzed: results[label].length,
    };
  }

  console.log(JSON.stringify(report, null, 2));

  // ------------------------------------
  // Deterministic Interpretation
  // ------------------------------------
  logSection("Interpretation");

  console.log({
    conclusion:
      report["24h"].port_concentration.variance < 0.02
        ? "BEHAVIOR IS TEMPORALLY STABLE"
        : "BEHAVIOR VARIES OVER TIME",
    justification: [
      "Analysis spans full dataset (2025–2026)",
      "Rolling temporal windows across entire timeline",
      "Stability measured via variance, not raw volume",
      "Deterministic, explainable, no ML assumptions",
    ],
  });

  await mongoose.disconnect();
  console.log("✅ Complete");
  process.exit(0);
}

// ------------------------------------
run().catch(err => {
  console.error("❌ Experiment failed:", err);
  process.exit(1);
});