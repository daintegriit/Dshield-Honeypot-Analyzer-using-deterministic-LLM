require("dotenv").config();
const mongoose = require("mongoose");
const Attack = require("../../models/AttackModel");
const { last15m, last60m, last24h } = require("../utils/timeWindows");

// ------------------------------------
// Helpers
// ------------------------------------
function logSection(title) {
  console.log("\n" + "─".repeat(60));
  console.log(`🔹 ${title}`);
  console.log("─".repeat(60));
}

// ------------------------------------
// Main
// ------------------------------------
async function run() {
  logSection("Behavior Stability Experiment");

  await mongoose.connect(process.env.MONGO_URI);
  console.log("✅ Connected to MongoDB");

  // ------------------------------------
  // Anchor to LAST OBSERVED EVENT (not now)
  // ------------------------------------
  const latest = await Attack
    .findOne({}, { timestamp: 1 })
    .sort({ timestamp: -1 })
    .lean();

  if (!latest?.timestamp) {
    throw new Error("No attacks found in database");
  }

  const anchorTime = new Date(latest.timestamp);
  console.log("🧭 Anchor time (last observed attack):", anchorTime.toISOString());

  // ------------------------------------
  // Define windows (event-time)
  // ------------------------------------
  const windows = {
    "15m": last15m(anchorTime),
    "60m": last60m(anchorTime),
    "24h": last24h(anchorTime),
  };

  const results = {};

  // ------------------------------------
  // Process each window
  // ------------------------------------
  for (const [label, since] of Object.entries(windows)) {
    logSection(`Processing ${label} window`);
    console.log(`⏱  From: ${since.toISOString()}`);
    console.log(`⏱  To:   ${anchorTime.toISOString()}`);

    const attacks = await Attack.find(
      {
        timestamp: {
          $gte: since,
          $lte: anchorTime, // ✅ CRITICAL FIX
        },
      },
      {
        source_ip: 1,
        asn: 1,
        target_port: 1,
        timestamp: 1,
      }
    ).lean();

    console.log(`📊 Retrieved ${attacks.length.toLocaleString()} records`);

    // ------------------------------------
    // Metrics
    // ------------------------------------
    const uniqueIPs = new Set(attacks.map(a => a.source_ip)).size;
    const uniqueASNs = new Set(attacks.map(a => a.asn).filter(Boolean)).size;

    const portCounts = {};
    for (const a of attacks) {
      if (!a.target_port) continue;
      portCounts[a.target_port] = (portCounts[a.target_port] || 0) + 1;
    }

    const topPortCount =
      Object.keys(portCounts).length > 0
        ? Math.max(...Object.values(portCounts))
        : 0;

    const concentration =
      attacks.length > 0 ? topPortCount / attacks.length : 0;

    results[label] = {
      total_attacks: attacks.length,
      unique_ips: uniqueIPs,
      unique_asns: uniqueASNs,
      port_concentration: Number(concentration.toFixed(3)),
    };

    console.log("✅ Window complete");
  }

  // ------------------------------------
  // Output metrics
  // ------------------------------------
  logSection("Behavior Stability Metrics");
  console.table(results);

  // ------------------------------------
  // Deterministic Reasoning Layer
  // ------------------------------------
  logSection("Deterministic Assessment");

  const trend =
    results["15m"].total_attacks >
    results["60m"].total_attacks * 0.4
      ? "ESCALATING"
      : "STABLE_OR_DECLINING";

  const assessment = {
    verdict: trend,
    reasoning: [
      "Compared short-term activity to baseline window",
      "Measured source diversity and port concentration",
      "Used deterministic thresholds (no ML)",
    ],
    assumptions: [
      "Attack volume reflects activity intensity",
      "Port concentration indicates behavioral focus",
      "Short-term deviation implies escalation",
    ],
    uncertainty: [
      "Recent inactivity limits escalation confidence",
      "Long-term behavior may differ from short-term windows",
    ],
    evidence: {
      anchor_time: anchorTime.toISOString(),
      windows: results,
    },
  };

  console.log(JSON.stringify(assessment, null, 2));

  await mongoose.disconnect();
  console.log("\n🔌 MongoDB disconnected");
  console.log("✅ Experiment complete\n");

  process.exit(0);
}

// ------------------------------------
run().catch(err => {
  console.error("❌ Experiment failed:", err);
  process.exit(1);
});