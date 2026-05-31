/**
 * ATTACK CONTROLLER (Dual Mode)
 * --------------------------------------------
 * USE_MONGO = true  → Use MongoDB collections
 * USE_MONGO = false → Parse /var/log/dshield.log directly
 */

const mongoose = require("mongoose");
const Attack = require("../models/AttackModel");
const parseLogs = require("../utils/parseLogs");
const fetchGeoInfo = require("../utils/fetchGeoInfo");

const USE_MONGO = process.env.USE_MONGO === "true";


// -------------------------------
// Helper: attack type classification
// -------------------------------
function determineAttackType(port) {
  if (port === 22) return "SSH Scan";
  if (port === 23) return "Telnet Scan";
  if (port < 1024) return "Low Port Scan";
  return "General Scan";
}



// -------------------------------
// Top 10 Countries by Attack Count
// -------------------------------
exports.getTopCountries = async (req, res) => {
  try {
    if (USE_MONGO) {
      const result = await Attack.aggregate([
        { $match: { country: { $exists: true, $ne: "" } } },
        { $group: { _id: "$country", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]);
      return res.json(result);
    }

    // Fallback
    const logs = parseLogs();
    const counts = {};

    for (const e of logs) {
      const geo = await fetchGeoInfo(e.src);
      const country = geo?.country_name || "Unknown";
      counts[country] = (counts[country] || 0) + 1;
    }

    const formatted = Object.entries(counts)
      .map(([country, count]) => ({ country, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    res.json(formatted);

  } catch (err) {
    console.error("Top countries error:", err);
    res.status(500).json({ message: "Error fetching top countries", err });
  }
};


// -------------------------------
// Top 10 Attack Types
// -------------------------------
exports.getTopAttackTypes = async (req, res) => {
  try {
    if (USE_MONGO) {
      const result = await Attack.aggregate([
        { $group: { _id: "$attack_category", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 10 }
      ]);
      return res.json(result);
    }

    // Fallback
    const logs = parseLogs();
    const counts = {};

    for (const e of logs) {
      const type = determineAttackType(e.dpt);
      counts[type] = (counts[type] || 0) + 1;
    }

    const formatted = Object.entries(counts)
      .map(([attackType, count]) => ({ attackType, count }))
      .sort((a, b) => b.count - a.count);

    res.json(formatted);

  } catch (err) {
    console.error("Attack types error:", err);
    res.status(500).json({ message: "Error fetching attack types", err });
  }
};



// -------------------------------
// Top 25 Source IPs
// -------------------------------
exports.getTopSourceIPs = async (req, res) => {
  try {
    if (USE_MONGO) {
      const result = await Attack.aggregate([
        { $group: { _id: "$source_ip", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 25 }
      ]);
      return res.json(result);
    }

    // Fallback
    const logs = parseLogs();
    const ipCounts = {};

    for (const e of logs) {
      ipCounts[e.src] = (ipCounts[e.src] || 0) + 1;
    }

    const formatted = Object.entries(ipCounts)
      .map(([sourceIP, count]) => ({ sourceIP, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 25);

    res.json(formatted);

  } catch (err) {
    console.error("Source IPs error:", err);
    res.status(500).json({ message: "Error fetching top source IPs", err });
  }
};



// -------------------------------
// Attack Trends Over Time
// -------------------------------
exports.getAttackTrends = async (req, res) => {
  try {
    if (USE_MONGO) {
      const result = await Attack.aggregate([
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$timestamp" }},
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } }
      ]);
      return res.json(result);
    }

    // Fallback
    const logs = parseLogs();
    const dayCount = {};

    for (const e of logs) {
      const day = e.timestamp.split(" ")[0];
      dayCount[day] = (dayCount[day] || 0) + 1;
    }

    const formatted = Object.entries(dayCount)
      .map(([day, count]) => ({ day, count }))
      .sort((a, b) => day.localeCompare(b.day));

    res.json(formatted);

  } catch (err) {
    console.error("Attack trends error:", err);
    res.status(500).json({ message: "Error fetching attack trends", err });
  }
};



// -------------------------------
// Protocol Breakdown
// -------------------------------
exports.getProtocolBreakdown = async (req, res) => {
  try {
    if (USE_MONGO) {
      const result = await Attack.aggregate([
        { $group: { _id: "$protocol", count: { $sum: 1 } } },
        { $sort: { count: -1 } }
      ]);
      return res.json(result);
    }

    const logs = parseLogs();
    const protoCounts = {};

    for (const e of logs) {
      protoCounts[e.proto] = (protoCounts[e.proto] || 0) + 1;
    }

    const formatted = Object.entries(protoCounts)
      .map(([protocol, count]) => ({ protocol, count }))
      .sort((a, b) => b.count - a.count);

    res.json(formatted);

  } catch (err) {
    console.error("Protocol breakdown error:", err);
    res.status(500).json({ message: "Error fetching protocol breakdown", err });
  }
};



// -------------------------------
// Severity Distribution
// -------------------------------
exports.getSeverityDistribution = async (req, res) => {

  try {

    console.log(
      "🚀 /api/charts/severity-distribution HIT"
    );

    // ============================================
    // WINDOW
    // ============================================

    const rawWindow =
      req.query.minutes || "60";

    const isAllTime =
      String(rawWindow)
        .toLowerCase() === "all";

    const windowMinutes =
      isAllTime
        ? "all"
        : Number(rawWindow);

    // ============================================
    // SINCE
    // ============================================

    const since =
      !isAllTime
        ? new Date(
            Date.now() -
            windowMinutes *
              60 *
              1000
          )
        : null;

    // ============================================
    // ORDER
    // ============================================

    const severityOrder = {
      critical: 0,
      high: 1,
      medium: 2,
      low: 3,
    };

    // ============================================
    // MONGO MODE
    // ============================================

    if (USE_MONGO) {

      let normalized = [];

      // ==========================================
      // ALL-TIME MODE
      // ==========================================

      if (isAllTime) {

        console.log(
          "📚 Using cumulative severity collection"
        );

        const result =
          await mongoose.connection
            .collection("severity")
            .find({})
            .toArray();

        normalized =
          result.map((r) => ({

            severity:
              String(
                r.level || ""
              ).toLowerCase(),

            count:
              Number(
                r.count || 0
              ),

            first_seen:
              r.first_seen || null,

            last_updated:
              r.last_updated || null,

          }));

      } else {

        // ========================================
        // LIVE WINDOW MODE
        // ========================================

        console.log(
          `⚡ Using rolling Attack aggregation (${windowMinutes}m)`
        );

        const aggregation =
          await Attack.aggregate([

            // ====================================
            // TIME WINDOW
            // ====================================

            {
              $match: {
                timestamp: {
                  $gte: since,
                },
              },
            },

            // ====================================
            // GROUP
            // ====================================

            {
              $group: {

                _id: {
                  $toLower:
                    "$severity",
                },

                count: {
                  $sum: 1,
                },

                latest: {
                  $max:
                    "$timestamp",
                },

                earliest: {
                  $min:
                    "$timestamp",
                },
              },
            },
          ]);

        normalized =
          aggregation.map((r) => ({

            severity:
              r._id || "unknown",

            count:
              Number(
                r.count || 0
              ),

            first_seen:
              r.earliest || null,

            last_updated:
              r.latest || null,

          }));
      }

      // ==========================================
      // ENSURE ALL LEVELS EXIST
      // ==========================================

      const existingLevels =
        new Set(
          normalized.map(
            (n) => n.severity
          )
        );

      const allLevels = [
        "critical",
        "high",
        "medium",
        "low",
      ];

      for (const level of allLevels) {

        if (
          !existingLevels.has(level)
        ) {

          normalized.push({

            severity: level,

            count: 0,

            first_seen: null,

            last_updated: null,

          });
        }
      }

      // ==========================================
      // SORT
      // ==========================================

      normalized.sort(
        (a, b) =>
          severityOrder[a.severity] -
          severityOrder[b.severity]
      );

      // ==========================================
      // TOTAL
      // ==========================================

      const total =
        normalized.reduce(
          (sum, s) =>
            sum + s.count,
          0
        );

      // ==========================================
      // DOMINANT
      // ==========================================

      const dominant =
        [...normalized]
          .sort(
            (a, b) =>
              b.count - a.count
          )[0]?.severity ||
        "none";

      console.log(
        `✅ Severity telemetry returned | window=${windowMinutes} | total=${total} | dominant=${dominant}`
      );

      return res.json({

        windowMinutes,

        total,

        dominantSeverity:
          dominant,

        generatedAt:
          new Date(),

        severities:
          normalized,

      });
    }

    // ============================================
    // FALLBACK MODE
    // ============================================

    console.warn(
      "⚠️ Using fallback severity heuristics"
    );

    const logs =
      parseLogs();

    const dist = {

      critical: 0,
      high: 0,
      medium: 0,
      low: 0,

    };

    for (const e of logs) {

      if (e.dpt <= 1024) {

        dist.critical++;

      } else if (
        e.dpt <= 5000
      ) {

        dist.high++;

      } else if (
        e.dpt <= 20000
      ) {

        dist.medium++;

      } else {

        dist.low++;
      }
    }

    const fallback = [

      {
        severity: "critical",
        count: dist.critical,
      },

      {
        severity: "high",
        count: dist.high,
      },

      {
        severity: "medium",
        count: dist.medium,
      },

      {
        severity: "low",
        count: dist.low,
      },

    ];

    const total =
      fallback.reduce(
        (sum, s) =>
          sum + s.count,
        0
      );

    return res.json({

      windowMinutes,

      total,

      dominantSeverity:
        [...fallback]
          .sort(
            (a, b) =>
              b.count - a.count
          )[0]?.severity ||
        "none",

      generatedAt:
        new Date(),

      severities:
        fallback,

    });

  } catch (err) {

    console.error(
      "❌ Severity error:",
      err
    );

    return res
      .status(500)
      .json({

        message:
          "Error fetching severity distribution",

        error:
          err.message || err,

        severities: [],

      });
  }
};


// -------------------------------
// Port Scanning
// -------------------------------
exports.getPortScanning = async (req, res) => {
  try {
    if (USE_MONGO) {
      const result = await Attack.aggregate([
        { $group: { _id: "$target_port", count: { $sum: 1 } } },
        { $sort: { count: -1 } },
        { $limit: 50 }
      ]);
      return res.json(result);
    }

    // Fallback
    const logs = parseLogs();
    const portCounts = {};

    for (const e of logs) {
      portCounts[e.dpt] = (portCounts[e.dpt] || 0) + 1;
    }

    const formatted = Object.entries(portCounts)
      .map(([port, count]) => ({ port: parseInt(port), count }))
      .sort((a, b) => b.count - a.count);

    res.json(formatted);

  } catch (err) {
    console.error("Port scanning error:", err);
    res.status(500).json({ message: "Error fetching port scanning data", err });
  }
};



// -------------------------------
// Source ASN
// -------------------------------
exports.getSourceASNAnalysis = async (req, res) => {
  try {
    if (!USE_MONGO) return res.json([]);

    const result = await Attack.aggregate([
      { $group: { _id: "$asn", count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    res.json(result);

  } catch (err) {
    console.error("ASN error:", err);
    res.status(500).json({ message: "Error fetching ASN data", err });
  }
};



// -------------------------------
// Comparative Traffic Analysis
// -------------------------------
exports.getComparativeTrafficAnalysis = async (req, res) => {
  try {
    if (USE_MONGO) {
      const events = await Attack.find({}).lean();

      const result = {
        totalEvents: events.length,
        uniqueIPs: new Set(events.map(e => e.source_ip)).size,
        lowPorts: events.filter(e => e.target_port <= 1024).length,
        highPorts: events.filter(e => e.target_port > 1024).length,
        tcp: events.filter(e => e.protocol === "TCP").length,
        udp: events.filter(e => e.protocol === "UDP").length,
      };

      return res.json(result);
    }

    // Fallback
    const logs = parseLogs();
    const result = {
      totalEvents: logs.length,
      uniqueIPs: new Set(logs.map(l => l.src)).size,
      lowPorts: logs.filter(l => l.dpt <= 1024).length,
      highPorts: logs.filter(l => l.dpt > 1024).length,
      tcp: logs.filter(l => l.proto === "TCP").length,
      udp: logs.filter(l => l.proto === "UDP").length
    };

    res.json(result);

  } catch (err) {
    console.error("Comparative traffic error:", err);
    res.status(500).json({ message: "Error generating comparative traffic analysis", err });
  }
};



// -------------------------------
// Global Threat Feed
// -------------------------------
exports.getGlobalThreats = async (req, res) => {
  try {
    if (USE_MONGO) {
      // ONLY USE ATTACK MODEL — your system uses this
      const attacks = await Attack.find({})
        .sort({ timestamp: -1 })
        .limit(100)
        .lean();

      const normalized = attacks.map(t => ({
        id: t._id,
        timestamp: t.timestamp,
        sourceIP: t.source_ip,
        attackType: t.attack_category,
        targetPort: t.target_port,
        severity: t.severity,
        country: t.country
      }));

      return res.json(normalized);
    }

    // Fallback
    const logs = parseLogs().slice(-100);

    const formatted = logs.map(l => ({
      id: l.timestamp + l.src,
      timestamp: l.timestamp,
      sourceIP: l.src,
      attackType: determineAttackType(l.dpt),
      targetPort: l.dpt,
      severity: l.dpt < 1024 ? "High" : "Low",
      country: "Unknown"
    }));

    res.json(formatted);

  } catch (err) {
    console.error("Global threats error:", err);
    res.status(500).json({ message: "Error fetching global threats", err });
  }
};









