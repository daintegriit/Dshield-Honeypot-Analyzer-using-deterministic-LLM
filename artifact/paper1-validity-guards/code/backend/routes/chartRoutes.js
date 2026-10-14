const express = require("express");
const router = express.Router();

const {

  getTopCountries,
  downloadTopCountries,

  getTopIPs,
  getTopAttackTypes,

  getPortScanning,
  getProtocolBreakdown,
  getSeverityDistribution,

  getAttackTrends,
  getHeatmapData,
  getComparativeAnalysis,

  getTopASNs,
  getRecentLogs,
  getThreatSummary,
  getGeolocation

} = require("../controllers/chartController");

// =========================================================
// 🔥 RESPONSE CACHE HEADERS
// =========================================================

const telemetryHeaders = (
  req,
  res,
  next
) => {

  // -------------------------------------------------------
  // SHORT-LIVED DASHBOARD CACHE
  // -------------------------------------------------------

  res.set({

    // browser cache
    "Cache-Control":
      "public, max-age=5, stale-while-revalidate=30",

    // observability
    "X-Chiron-Service":
      "telemetry-engine",

    "X-Chiron-Version":
      "2.0.0",

    // compression hint
    "Vary":
      "Accept-Encoding"
  });

  next();
};

// =========================================================
// 🔥 ROUTER MIDDLEWARE
// =========================================================

router.use(
  telemetryHeaders
);

// =========================================================
// 🌍 COUNTRIES
// =========================================================

router.get(
  "/top-countries",
  getTopCountries
);

router.get(
  "/download/top-countries",
  downloadTopCountries
);

// =========================================================
// 🔥 TOP IPS
// =========================================================

router.get(
  "/top-ips",
  getTopIPs
);

// =========================================================
// 🔥 ATTACK TYPES
// =========================================================

router.get(
  "/top-attack-types",
  getTopAttackTypes
);

// =========================================================
// 🔥 PORT SCANNING
// =========================================================

router.get(
  "/port-scanning",
  getPortScanning
);

// =========================================================
// 🔥 PROTOCOL BREAKDOWN
// =========================================================

router.get(
  "/protocol-breakdown",
  getProtocolBreakdown
);

// =========================================================
// 🔥 SEVERITY DISTRIBUTION
// =========================================================

router.get(
  "/severity-distribution",
  getSeverityDistribution
);

// =========================================================
// 🔥 ATTACK TRENDS
// =========================================================

router.get(
  "/attack-trends",
  getAttackTrends
);

// =========================================================
// 🔥 HEATMAP
// =========================================================

router.get(
  "/heatmap",
  getHeatmapData
);

// =========================================================
// 🔥 COMPARATIVE ANALYSIS
// =========================================================

router.get(
  "/comparative-analysis",
  getComparativeAnalysis
);

// =========================================================
// 🔥 ASN ANALYSIS
// =========================================================

router.get(
  "/top-asns",
  getTopASNs
);

// =========================================================
// 🔥 RECENT LOGS
// =========================================================

router.get(
  "/recent-logs",
  getRecentLogs
);

// =========================================================
// 🔥 THREAT SUMMARY
// =========================================================

router.get(
  "/threat-summary",
  getThreatSummary
);

// =========================================================
// 🔥 GEOLOCATION
// =========================================================

router.get(
  "/geolocation",
  getGeolocation
);

// =========================================================
// 🔥 EXPORT
// =========================================================

module.exports = router;
