const express = require("express");
const router = express.Router();
const {
  getTopCountries,
  getTopAttackTypes,
  getTopSourceIPs,
  getAttackTrends,
  getProtocolBreakdown,
  getSeverityDistribution,
  getPortScanning,
  getSourceASNAnalysis,
  getComparativeTrafficAnalysis,
  getGlobalThreats,
} = require("../controllers/attackController");

// Route to fetch Top 10 Countries by Attacks
router.get("/top-countries", getTopCountries);

// Route to fetch Top 10 Attack Types
router.get("/top-attack-types", getTopAttackTypes);

// Route to fetch Top 25 Source IPs
router.get("/top-ips", getTopSourceIPs);

// Route to fetch Attack Trends Over Time
router.get("/attack-trends", getAttackTrends);

// Route to fetch Protocol Breakdown
router.get("/protocol-breakdown", getProtocolBreakdown);

// Route to fetch Severity Distribution
router.get("/severity-distribution", getSeverityDistribution);

// Route to fetch Port Scanning Analysis
router.get("/port-scanning", getPortScanning);

// Route to fetch Source ASN Analysis
router.get("/source-asn", getSourceASNAnalysis);

// Route to fetch Comparative Traffic Analysis
router.get("/comparative-traffic", getComparativeTrafficAnalysis);

// Route to fetch Global Threats
router.get("/global-threats", getGlobalThreats);


module.exports = router;
