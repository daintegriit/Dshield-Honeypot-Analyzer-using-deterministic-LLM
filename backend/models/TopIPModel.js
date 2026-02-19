// models/TopIPModel.js
const mongoose = require("mongoose");

const TopIPSchema = new mongoose.Schema({
  // ---------------------------------------
  // ATTACKER IP
  // ---------------------------------------
  source_ip: {
    type: String,
    required: true,
    index: true,
  },

  // Total number of attacks seen from this IP
  count: {
    type: Number,
    default: 1,
  },

  // ---------------------------------------
  // TIMESTAMPS
  // ---------------------------------------
  first_seen: {
    type: Date,
    default: Date.now,
  },

  last_seen: {
    type: Date,
    default: Date.now,
  },

  // ---------------------------------------
  // SEVERITY BREAKDOWN
  // ---------------------------------------
  critical_count: { type: Number, default: 0 },
  high_count:     { type: Number, default: 0 },
  medium_count:   { type: Number, default: 0 },
  low_count:      { type: Number, default: 0 },

  // ---------------------------------------
  // GEOLOCATION (MATCHES WORKER)
  // ---------------------------------------
  country:   { type: String, default: null },
  region:    { type: String, default: null },
  city:      { type: String, default: null },
  latitude:  { type: Number, default: null },
  longitude: { type: Number, default: null },

  // ---------------------------------------
  // ASN & PROVIDER (MATCHES WORKER)
  // ---------------------------------------
  asn:     { type: String, default: null },
  asn_org: { type: String, default: null },
  provider:{ type: String, default: null },

  // ---------------------------------------
  // THREAT INTEL (MATCHES WORKER)
  // ---------------------------------------
  threat_score: { type: Number, default: null },
  threat_name:  { type: String, default: null },
});

// Use collection "topIPs"
module.exports = mongoose.model("TopIP", TopIPSchema, "topIPs");