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
  getTopASNs,
  getRecentLogs,
  getThreatSummary,
  getGeolocation
} = require("../controllers/chartController");

console.log({
  getTopCountries,
  downloadTopCountries,
  getTopIPs,
  getTopAttackTypes,
  getPortScanning,
  getProtocolBreakdown,
  getSeverityDistribution,
  getAttackTrends,
  getHeatmapData,
  getTopASNs,
  getRecentLogs,
  getThreatSummary,
  getGeolocation
});

// Routes
router.get("/top-countries", getTopCountries); // Route for top countries
router.get("/download/top-countries", downloadTopCountries); // Route for downloading CSV
router.get("/top-ips", getTopIPs); // Route for top IPs
router.get("/top-attack-types", getTopAttackTypes); // Route for top attack types
router.get("/port-scanning", getPortScanning); // Implement similar for Port Scanning
router.get("/protocol-breakdown", getProtocolBreakdown); // Implement similar for Protocol Breakdown
router.get("/severity-distribution", getSeverityDistribution); // Implement similar for Severity Distribution
router.get('/attack-trends', getAttackTrends); // Route for attack trends
router.get("/heatmap", getHeatmapData); // Route for heatmap data
router.get("/top-asns", getTopASNs); // Route for top ASNs
router.get("/recent-logs", getRecentLogs); // Route for recent logs
router.get("/threat-summary", getThreatSummary); // Route for threat summary
router.get("/geolocation", getGeolocation); // Route for geolocation data

module.exports = router;
