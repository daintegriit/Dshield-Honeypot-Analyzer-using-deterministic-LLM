require("dotenv").config();
const mongoose = require("mongoose");
const fs = require("fs");
const path = require("path");
const Attack = require("../../models/AttackModel");

// ------------------------------------
// CONFIG
// ------------------------------------
const WINDOWS = {
  "15m": 15 * 60 * 1000,
  "60m": 60 * 60 * 1000,
};

const SLIDE = 60 * 60 * 1000; // 1 hour stride
const TARGET_WINDOWS = 300;

const HUMAN_LABEL_COLUMNS = [
  "label_volume_trend",
  "label_ip_concentration",
  "label_asn_concentration",
  "label_port_pattern",
  "label_behavior_type",
  "label_confidence",
  "label_notes",
];

// ------------------------------------
// Helpers
// ------------------------------------
function logSection(title) {
  console.log("\n" + "─".repeat(70));
  console.log(`🔹 ${title}`);
  console.log("─".repeat(70));
}

function computeWindowStats(attacks) {
  if (!attacks.length) {
    return {
      total: 0,
      top_ip: null,
      top_ip_share: 0,
      top_asn: null,
      top_asn_share: 0,
      top_port: null,
      top_port_share: 0,
    };
  }

  const countBy = (key) => {
    const map = {};
    for (const a of attacks) {
      if (!a[key]) continue;
      map[a[key]] = (map[a[key]] || 0) + 1;
    }
    return map;
  };

  const top = (map) => {
    let maxK = null;
    let maxV = 0;
    for (const [k, v] of Object.entries(map)) {
      if (v > maxV) {
        maxV = v;
        maxK = k;
      }
    }
    return { key: maxK, share: maxV / attacks.length };
  };

  const ipTop = top(countBy("source_ip"));
  const asnTop = top(countBy("asn"));
  const portTop = top(countBy("target_port"));

  return {
    total: attacks.length,
    top_ip: ipTop.key,
    top_ip_share: Number(ipTop.share.toFixed(3)),
    top_asn: asnTop.key,
    top_asn_share: Number(asnTop.share.toFixed(3)),
    top_port: portTop.key,
    top_port_share: Number(portTop.share.toFixed(3)),
  };
}

// ------------------------------------
// Main
// ------------------------------------
async function run() {
  logSection("GENERATE LABELED WINDOWS (GROUND TRUTH)");

  await mongoose.connect(process.env.MONGO_URI);
  console.log("✅ Connected to MongoDB");

  const earliest = await Attack.findOne({}, { timestamp: 1 })
    .sort({ timestamp: 1 })
    .lean();

  const latest = await Attack.findOne({}, { timestamp: 1 })
    .sort({ timestamp: -1 })
    .lean();

  const start = new Date(earliest.timestamp);
  const end = new Date(latest.timestamp);

  console.log("📅 Dataset range:");
  console.log("   From:", start.toISOString());
  console.log("   To:  ", end.toISOString());

  const rows = [];

  logSection("Sliding Window Scan");

  let scanned = 0;
  const totalSteps = Math.floor((end - start) / SLIDE);

  for (let t = start.getTime(); t <= end.getTime(); t += SLIDE) {
    const anchor = new Date(t);

    for (const [label, size] of Object.entries(WINDOWS)) {
      const since = new Date(anchor.getTime() - size);

      const attacks = await Attack.find(
        { timestamp: { $gte: since, $lte: anchor } },
        { source_ip: 1, asn: 1, target_port: 1 }
      ).lean();

      const stats = computeWindowStats(attacks);

      rows.push({
        window_start: since.toISOString(),
        window_end: anchor.toISOString(),
        window_size: label,
        total_attacks: stats.total,
        top_ip: stats.top_ip,
        top_ip_share: stats.top_ip_share,
        top_asn: stats.top_asn,
        top_asn_share: stats.top_asn_share,
        top_port: stats.top_port,
        top_port_share: stats.top_port_share,
      });
    }

    scanned++;
    if (scanned % 25 === 0) {
      process.stdout.write(
        `\r🔄 ${Math.min(100, Math.round((scanned / totalSteps) * 100))}%`
      );
    }
  }

  console.log("\n📊 Total raw windows:", rows.length);

  // ------------------------------------
  // POST-PROCESSING
  // ------------------------------------
  logSection("Post-Processing Windows");

  const nonZero = rows.filter(r => r.total_attacks > 0);

  console.log("🧹 Removed zero-activity windows:", rows.length - nonZero.length);
  console.log("📈 Windows with behavior:", nonZero.length);

  // Stratified sampling
  nonZero.sort((a, b) => a.total_attacks - b.total_attacks);

  const third = Math.floor(nonZero.length / 3);
  const low = nonZero.slice(0, third);
  const mid = nonZero.slice(third, third * 2);
  const high = nonZero.slice(third * 2);

  function sample(arr, n) {
    const out = [];
    const copy = [...arr];
    for (let i = 0; i < n && copy.length; i++) {
      out.push(copy.splice(Math.floor(Math.random() * copy.length), 1)[0]);
    }
    return out;
  }

  const perBucket = Math.floor(TARGET_WINDOWS / 3);
  const sampled = [
    ...sample(low, perBucket),
    ...sample(mid, perBucket),
    ...sample(high, perBucket),
  ];

  // ------------------------------------
  // EXPORT FILES
  // ------------------------------------
  logSection("Exporting CSVs");

  const outputDir = path.join(__dirname, "outputs");
  fs.mkdirSync(outputDir, { recursive: true });

  // ---- 1. Raw sampled file
  const toLabelPath = path.join(outputDir, "windows_to_label.csv");

  const baseHeader = Object.keys(sampled[0]);
  const baseLines = sampled.map(r =>
    baseHeader.map(h => `"${r[h] ?? ""}"`).join(",")
  );

  fs.writeFileSync(toLabelPath, [baseHeader.join(","), ...baseLines].join("\n"));
  console.log("✅ Saved:", toLabelPath);

  // ---- 2. Human labeling file (sorted + empty label columns)
  const labeledHumanPath = path.join(outputDir, "windows_labeled_human.csv");

  const sorted = [...sampled].sort(
    (a, b) => new Date(a.window_start) - new Date(b.window_start)
  );

  const humanHeader = [...baseHeader, ...HUMAN_LABEL_COLUMNS];
  const humanLines = sorted.map(r =>
    humanHeader.map(h => `"${r[h] ?? ""}"`).join(",")
  );

  fs.writeFileSync(
    labeledHumanPath,
    [humanHeader.join(","), ...humanLines].join("\n")
  );

  console.log("🧠 Saved (chronological, ready for labeling):", labeledHumanPath);
  console.log("📌 Windows to label:", sorted.length);

  await mongoose.disconnect();
  console.log("🔌 MongoDB disconnected");
}

// ------------------------------------
run().catch(err => {
  console.error("❌ Failed:", err);
  process.exit(1);
});