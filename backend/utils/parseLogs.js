const fs = require("fs");
const Attack = require("../models/AttackModel");

const FILE_PATH = "/var/log/dshield.log";

/**
 * Hybrid log parser:
 * 1) Try reading from local dshield.log
 * 2) Fallback to MongoDB attacks collection
 */
async function parseLogs() {

  // =====================================================
  // 🔥 OPTION 1: FILE-BASED (REAL HONEYPOT)
  // =====================================================
  if (fs.existsSync(FILE_PATH)) {
    console.log("📄 Using dshield.log file source");

    const lines = fs.readFileSync(FILE_PATH, "utf-8").split("\n");

    return lines
      .filter(line => line.includes("DSHIELDINPUT"))
      .map(line => ({
        source_ip: line.match(/SRC=([0-9.:]+)/)?.[1] || null,
        target_ip: line.match(/DST=([0-9.:]+)/)?.[1] || null,
        source_port: Number(line.match(/SPT=([0-9]+)/)?.[1]) || null,
        target_port: Number(line.match(/DPT=([0-9]+)/)?.[1]) || null,
        protocol: line.match(/PROTO=([A-Za-z0-9]+)/)?.[1] || "UNKNOWN",
        timestamp: new Date(),
        raw: line,
      }))
      .filter(e => e.source_ip);
  }

  // =====================================================
  // 🔥 OPTION 2: MONGO FALLBACK (YOUR CURRENT SYSTEM)
  // =====================================================
  console.warn("⚠️ dshield.log missing → using Mongo fallback");

  const logs = await Attack.find({})
    .sort({ timestamp: -1 })
    .limit(500)
    .lean();

  return logs.map(a => ({
    source_ip: a.source_ip,
    target_ip: a.target_ip,
    source_port: a.source_port,
    target_port: a.target_port,
    protocol: a.protocol,
    timestamp: a.timestamp,
    raw: a.raw,
  })).filter(e => e.source_ip);
}

module.exports = parseLogs;
