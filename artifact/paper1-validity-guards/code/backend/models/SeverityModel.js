// models/SeverityModel.js
const mongoose = require("mongoose");

const SeveritySchema = new mongoose.Schema({
  // Severity level: "normal", "low", "medium", "high", "critical"
  level: { 
    type: String, 
    required: true, 
    index: true 
  },

  // Total number of attacks for this severity
  count: { 
    type: Number, 
    default: 1 
  },

  // ---------------------------------------
  // TIMELINE SUPPORT
  // ---------------------------------------

  // First time we saw this severity
  first_seen: { 
    type: Date, 
    default: Date.now 
  },

  // Last time we updated this severity bucket
  last_updated: { 
    type: Date, 
    default: Date.now 
  },

  // ---------------------------------------
  // FUTURE-PROOF: Per-day stats for charts
  // ---------------------------------------
  daily_counts: {
    type: Map,
    of: Number,
    default: {}
    // Example:
    // { "2025-11-28": 3, "2025-11-29": 5 }
  }
});

// Keep the EXACT collection name YOU requested:
module.exports = mongoose.model("Severity", SeveritySchema, "severity");