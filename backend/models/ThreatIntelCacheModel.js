// models/ThreatIntelCacheModel.js
const mongoose = require("mongoose");

/**
 * ThreatIntelCache
 * --------------------------------------------------------
 * Stores threat intelligence ONLY:
 *   - AbuseIPDB-style threat scores
 *   - TOR flag
 *   - Report counts
 *   - Last time threat intel was retrieved
 *
 * TTL:
 *   - Expires after 12 hours (adjustable)
 */

const ThreatIntelCacheSchema = new mongoose.Schema({
  ip: { 
    type: String, 
    required: true, 
    unique: true, 
    index: true 
  },

  // --------------------------
  // THREAT INTEL FIELDS
  // --------------------------
  abuseConfidenceScore: { type: Number, default: null },
  isTor:                { type: Boolean, default: null },
  totalReports:         { type: Number, default: null },
  lastReportedAt:       { type: Date, default: null },

  // --------------------------
  // CACHE TIMESTAMP (TTL)
  // --------------------------
  createdAt: { 
    type: Date, 
    default: Date.now 
  }
});

// Auto-expire after 12 hours
ThreatIntelCacheSchema.index(
  { createdAt: 1 },
  { expireAfterSeconds: 60 * 60 * 12 }
);

module.exports = mongoose.model(
  "ThreatIntelCache", 
  ThreatIntelCacheSchema, 
  "threatintelcache"
);