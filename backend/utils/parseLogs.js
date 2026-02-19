// utils/parseLogs.js
const fs = require("fs");
const path = "/var/log/dshield.log";

/**
 * Parse local DShield honeypot logs
 * Extracts:
 *  - source_ip (SRC)
 *  - target_ip (DST)
 *  - source_port (SPT)
 *  - target_port (DPT)
 *  - protocol (PROTO)
 *  - timestamp (parsed from kernel[] or NOW fallback)
 *  - raw line
 */
function parseLogs() {
  if (!fs.existsSync(path)) {
    console.warn("⚠️ dshield.log does not exist:", path);
    return [];
  }

  const lines = fs.readFileSync(path, "utf-8").split("\n");

  const entries = lines
    .filter(line => line.includes("DSHIELDINPUT"))
    .map(line => {
      const source_ip   = line.match(/SRC=([0-9.:]+)/)?.[1] || null;
      const target_ip   = line.match(/DST=([0-9.:]+)/)?.[1] || null;
      const source_port = line.match(/SPT=([0-9]+)/)?.[1] || null;
      const target_port = line.match(/DPT=([0-9]+)/)?.[1] || null;
      const protocol    = line.match(/PROTO=([A-Za-z0-9]+)/)?.[1] || "UNKNOWN";

      // Extract kernel timestamp: [44618.552681] → seconds since boot
      const kernelTime = line.match(/\[([0-9]+\.[0-9]+)\]/);
      const timestamp = kernelTime ? new Date(Date.now()) : new Date();

      return {
        source_ip,
        target_ip,
        source_port: source_port ? Number(source_port) : null,
        target_port: target_port ? Number(target_port) : null,
        protocol,
        timestamp,
        raw: line,
      };
    })
    .filter(entry => entry.source_ip); // only valid logs

  return entries;
}

module.exports = parseLogs;