/**
 * CHART CONTROLLER (Dual Mode: MongoDB + Log-Based)
 * -------------------------------------------------
 * USE_MONGO=false → Read /var/log/dshield.log (live honeypot data)
 * USE_MONGO=true  → Use MongoDB collections (future expansion)
 */

const mongoose = require("mongoose");
const { Parser } = require("json2csv");
const parseLogs = require("../utils/parseLogs");     // reads /var/log/dshield.log
const fetchGeoInfo = require("../utils/fetchGeoInfo"); // resolves IP → country
const DShieldLog = require("../models/DShieldLogModel");
const ASN = require("../models/ASNModel");   // <-- ADD THIS
const GeolocationCache = require("../models/GeolocationCacheModel");

const USE_MONGO = process.env.USE_MONGO === "true";   // 🔥 toggle in .env


// =========================================================
// 🔥 Helper: determine attack type from port (temporary logic)
// =========================================================
function determineAttackType(port) {
  if ([22].includes(port)) return "SSH Scan";
  if ([23].includes(port)) return "Telnet Scan";
  if (port >= 0 && port <= 1024) return "Low Port Scan";
  return "General Scan";
}



// =========================================================
// 🌍 TOP 10 COUNTRIES
// =========================================================
exports.getTopCountries = async (req, res) => {
  try {
    // ---------------- MongoDB MODE ----------------
    if (USE_MONGO) {
      const results = await mongoose.connection
        .collection("countries")
        .aggregate([
          { $match: { country: { $exists: true, $ne: "" } } },
          { $sort: { attackCount: -1 } },
          { $limit: 10 }
        ])
        .toArray();

      return res.json(
        results.map(item => ({
          country: item.country,
          attacks: item.attackCount
        }))
      );
    }

    // ---------------- LOG FILE MODE ----------------
    const entries = parseLogs();
    const countryCount = {};

    for (const entry of entries) {
      const geo = await fetchGeoInfo(entry.src);
      const country = geo?.country_name || "Unknown";

      if (!countryCount[country]) countryCount[country] = 0;
      countryCount[country]++;
    }

    const formatted = Object.entries(countryCount)
      .map(([country, attacks]) => ({ country, attacks }))
      .sort((a, b) => b.attacks - a.attacks)
      .slice(0, 10);

    return res.json(formatted);

  } catch (err) {
    console.error("Error Top Countries:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};




// =========================================================
// 🌍 TOP COUNTRIES CSV DOWNLOAD
// =========================================================
exports.downloadTopCountries = async (req, res) => {
  try {
    const response = await exports.getTopCountries(req, {
      json: (data) => data
    });

    const csv = new Parser().parse(response);
    res.header("Content-Type", "text/csv");
    res.attachment("top_countries.csv");
    res.send(csv);

  } catch (err) {
    console.error("Error downloading countries CSV:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};




// =========================================================
// 🔥 TOP 25 SOURCE IPs
// =========================================================
exports.getTopIPs = async (req, res) => {
  try {
    const limit = parseInt(req.query.limit) || 25;

    // ---------------- MongoDB MODE ----------------
    if (USE_MONGO) {
      const results = await mongoose.connection
        .collection("attacks")
        .aggregate([
          { $match: { source_ip: { $exists: true, $ne: "" } } },
          { $group: { _id: "$source_ip", count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: limit }
        ])
        .toArray();

      return res.json(results.map(ip => ({
        sourceIP: ip._id,
        count: ip.count
      })));
    }

    // ---------------- LOG FILE MODE ----------------
    const entries = parseLogs();
    const ipCount = {};

    for (const e of entries) {
      if (!ipCount[e.src]) ipCount[e.src] = 0;
      ipCount[e.src]++;
    }

    const formatted = Object.entries(ipCount)
      .map(([sourceIP, count]) => ({ sourceIP, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, limit);

    res.json(formatted);

  } catch (err) {
    console.error("Error Top IPs:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};




// =========================================================
// 🔥 TOP ATTACK TYPES
// =========================================================
exports.getTopAttackTypes = async (req, res) => {
  try {
    // ---------------- MongoDB MODE ----------------
    if (USE_MONGO) {
      const results = await mongoose.connection
        .collection("attacks")
        .aggregate([
          { $match: { attack_type: { $exists: true, $ne: "" } } },
          { $group: { _id: "$attack_type", count: { $sum: 1 } } },
          { $sort: { count: -1 } },
          { $limit: 10 }
        ])
        .toArray();

      return res.json(results.map(entry => ({
        attackType: entry._id,
        count: entry.count
      })));
    }

    // ---------------- LOG FILE MODE ----------------
    const entries = parseLogs();
    const typeCount = {};

    for (const e of entries) {
      const type = determineAttackType(e.dpt);

      if (!typeCount[type]) typeCount[type] = 0;
      typeCount[type]++;
    }

    const formatted = Object.entries(typeCount)
      .map(([attackType, count]) => ({ attackType, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    res.json(formatted);

  } catch (err) {
    console.error("Error Attack Types:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};




// =========================================================
// 🔥 PORT SCANNING ANALYSIS
// =========================================================
exports.getPortScanning = async (req, res) => {
  try {
    if (USE_MONGO) {
      // 🔥 Use the aggregated ports collection
      const results = await mongoose.connection
        .collection("ports")
        .aggregate([
          {
            $match: {
              port: { $exists: true },
              count: { $gt: 0 } // only ports that actually saw traffic
            }
          },
          {
            $group: {
              _id: "$port",
              totalCount: { $sum: "$count" } // ✅ sum the stored count field
            }
          },
          { $sort: { totalCount: -1 } },
          { $limit: 15 }
        ])
        .toArray();

      const formatted = results.map(r => ({
        port: r._id,
        count: r.totalCount
      }));

      console.log("[PortScanning] Top ports (ports collection):", formatted.slice(0, 5));
      return res.json(formatted);
    }

    // ---------------- LOG FILE MODE ----------------
    const entries = parseLogs();
    const portCount = {};

    for (const e of entries) {
      const p = e.dpt || e.port || e.target_port;
      if (!p) continue;
      if (!portCount[p]) portCount[p] = 0;
      portCount[p]++;
    }

    const formatted = Object.entries(portCount)
      .map(([port, count]) => ({ port: parseInt(port, 10), count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 15);

    console.log("[PortScanning] Top ports (log mode):", formatted.slice(0, 5));
    res.json(formatted);

  } catch (err) {
    console.error("Error Port Scan:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};




// =========================================================
// 🔥 PROTOCOL BREAKDOWN
// =========================================================
exports.getProtocolBreakdown = async (req, res) => {
  try {
    // ---------------- MONGO MODE ----------------
    if (USE_MONGO) {
      const results = await mongoose.connection
        .collection("protocols")
        .aggregate([
          { $match: { protocol: { $exists: true } } },

          // Use the stored count field instead of counting documents
          {
            $project: {
              _id: 0,
              protocol: "$protocol",
              count: "$count"   // <-- THIS IS THE REAL VALUE
            }
          },

          { $sort: { count: -1 } }
        ])
        .toArray();

      return res.json(results);
    }

    // ---------------- LOG MODE ----------------
    const entries = parseLogs();
    const protoCount = {};

    for (const e of entries) {
      if (!protoCount[e.proto]) protoCount[e.proto] = 0;
      protoCount[e.proto]++;
    }

    const formatted = Object.entries(protoCount)
      .map(([protocol, count]) => ({ protocol, count }))
      .sort((a, b) => b.count - a.count);

    res.json(formatted);

  } catch (err) {
    console.error("Error Protocol Breakdown:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};




// =========================================================
// 🔥 SEVERITY DISTRIBUTION (temporary placeholder)
// =========================================================
exports.getSeverityDistribution = async (req, res) => {
  try {
    // ---------------- MongoDB MODE ----------------
    if (USE_MONGO) {
      const results = await mongoose.connection
        .collection("severity")
        .aggregate([
          {
            $project: {
              _id: 0,
              severity: "$level",
              count: "$count"
            }
          },
          { $sort: { count: -1 } }
        ])
        .toArray();

      return res.json(results);
    }

    // ---------------- LOG FILE MODE ----------------
    // DShield does not include severity → fake based on port ranges
    const entries = parseLogs();
    const sevCount = { Low: 0, Medium: 0, High: 0 };

    for (const e of entries) {
      if (e.dpt <= 1024) sevCount.High++;
      else if (e.dpt <= 5000) sevCount.Medium++;
      else sevCount.Low++;
    }

    res.json([
      { severity: "High", count: sevCount.High },
      { severity: "Medium", count: sevCount.Medium },
      { severity: "Low", count: sevCount.Low }
    ]);

  } catch (err) {
    console.error("Error Severity Dist:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};



// ------------------------------
// 🆕 Live Attack Trends Controller
// ------------------------------
exports.getAttackTrends = async (req, res) => {
  try {
    const results = await DShieldLog.aggregate([
      {
        $group: {
          _id: {
            $dateToString: { 
              format: "%Y-%m-%d %H:%M",
              date: "$timestamp"
            }
          },
          count: { $sum: 1 }
        }
      },
      // Sort newest first so limit returns the latest 100 minutes
      { $sort: { "_id": -1 } },

      { $limit: 100 },  

      // Sort back to ascending order for chart readability
      { $sort: { "_id": 1 } }
    ]);

    const formatted = results.map(r => ({
      time: r._id,
      count: r.count
    }));

    res.json(formatted);

  } catch (err) {
    console.error("❌ Error in getAttackTrends:", err);
    res.status(500).json({ error: "Failed to fetch attack trends" });
  }
};

exports.getHeatmapData = async (req, res) => {
  try {
    const view = req.query.view || "daily"; // daily | weekly | monthly

    // Convert timestamps per mode
    let groupStage;

    if (view === "daily") {
      // Group by HOUR + DAY
      groupStage = {
        _id: {
          hour: { $hour: "$timestamp" },
          day: { $dayOfMonth: "$timestamp" }
        },
        count: { $sum: 1 }
      };
    } else if (view === "weekly") {
      // Group by hour + DAY OF WEEK (0–6)
      groupStage = {
        _id: {
          hour: { $hour: "$timestamp" },
          day: { $dayOfWeek: "$timestamp" }
        },
        count: { $sum: 1 }
      };
    } else if (view === "monthly") {
      // Group by hour + DAY OF MONTH
      groupStage = {
        _id: {
          hour: { $hour: "$timestamp" },
          day: { $dayOfMonth: "$timestamp" }
        },
        count: { $sum: 1 }
      };
    }

    const results = await DShieldLog.aggregate([
      { $match: { timestamp: { $exists: true } } },
      { $group: groupStage },
      { $sort: { "_id.day": 1, "_id.hour": 1 } }
    ]);

    // Convert results into ECharts heatmap-friendly format:
    // [dayIndex, hourIndex, count]
    const data = results.map(r => [
      r._id.day,
      r._id.hour,
      r.count
    ]);

    res.json(data);

  } catch (err) {
    console.error("❌ Error in getHeatmapData:", err);
    res.status(500).json({ error: "Failed to generate heatmap data." });
  }
};

// =========================================================
// 🔥 TOP ATTACKING ASNs
// =========================================================
exports.getTopASNs = async (req, res) => {
  try {
    if (!USE_MONGO) {
      return res.status(400).json({
        error: "ASN data only available in MongoDB mode."
      });
    }

    const results = await mongoose.connection
      .collection("asns")
      .aggregate([
        { $match: { asn: { $exists: true } } },
        { $sort: { count: -1 } },
        { $limit: 20 }
      ])
      .toArray();

    const formatted = results.map(item => ({
      asn: item.asn,
      org: item.asn_org,          // 🔥 CORRECT FIELD
      provider: item.provider,    // 🔥 OPTIONAL but you have this in Mongo
      count: item.count
    }));

    res.json(formatted);

  } catch (err) {
    console.error("Error in getTopASNs:", err);
    res.status(500).json({ error: "Internal Server Error" });
  }
};

// ================================
// Recent Honeypot Logs (Raw + Parsed)
// ================================
exports.getRecentLogs = async (req, res) => {
  try {
    const logs = await DShieldLog.find(
      {},
      {
        raw: 1,
        timestamp: 1,
        source_ip: 1,
        target_ip: 1,
        source_port: 1,
        target_port: 1,
      }
    )
      .sort({ timestamp: -1 })
      .limit(50);   // Optimal for real-time terminal

    res.json(logs);
  } catch (err) {
    console.error("Error fetching recent logs:", err);
    res.status(500).json({ error: "Failed to load logs" });
  }
};

// ================================
// THREAT SUMMARY FOR COPILOT
// ================================
// ================================
// THREAT SUMMARY FOR COPILOT
// ================================
exports.getThreatSummary = async (req, res) => {
  try {
    // Top attacking IP
    const topIP = await DShieldLog.aggregate([
      { $group: { _id: "$source_ip", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 1 }
    ]);

    // Most targeted port
    const topPort = await DShieldLog.aggregate([
      { $group: { _id: "$target_port", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 1 }
    ]);

    // 🟩 FIXED — Pull ASN summary from the ASN collection (correct!)
    const topASN = await ASN.aggregate([
      { $sort: { count: -1 } },
      { $limit: 1 },
      {
        $project: {
          _id: 0,
          asn: "$asn",
          org: "$asn_org",
          provider: "$provider",
          count: 1
        }
      }
    ]);

    // Recent attack rate (5 minutes)
    const recentAttackRate = await DShieldLog.countDocuments({
      timestamp: { $gte: new Date(Date.now() - 5 * 60 * 1000) }
    });

    // Return combined intelligence summary
    res.json({
      topIP: topIP[0] || null,
      topPort: topPort[0] || null,
      topASN: topASN[0] || null,  // <── Correct data now!
      recentAttackRate
    });

  } catch (err) {
    console.error("Threat Summary Error:", err);
    res.status(500).json({ error: "Failed to compute summary" });
  }
};

// ======================================
// GEO + ASN ENRICHED INTELLIGENCE LOOKUP
// ======================================
exports.getGeolocation = async (req, res) => {
  try {
    // 1️⃣ Aggregate attack counts by IP
    const attackCounts = await DShieldLog.aggregate([
      { $group: { _id: "$source_ip", count: { $sum: 1 } } },
      { $sort: { count: -1 } },
      { $limit: 50 }   // top 50 attacking IPs
    ]);

    const enriched = [];

    // 2️⃣ For each IP, lookup the GEO + ASN info
    for (const entry of attackCounts) {
      const ip = entry._id;
      const count = entry.count;

      // lookup in geolocation_cache collection
      const geo = await GeolocationCache.findOne({ ip });

      enriched.push({
        ip,
        count,
        country: geo?.country || "Unknown",
        region: geo?.region || "Unknown",
        city: geo?.city || "Unknown",
        latitude: geo?.latitude || null,
        longitude: geo?.longitude || null,
        asn: geo?.asn || "N/A",
        org: geo?.org || "Unknown Org",
        provider: geo?.provider || "Unknown Provider"
      });
    }

    // 3️⃣ Respond with enriched dataset
    res.json({ results: enriched });

  } catch (err) {
    console.error("❌ Geolocation Error:", err);
    res.status(500).json({ error: "Failed to fetch enriched geolocation data" });
  }
};