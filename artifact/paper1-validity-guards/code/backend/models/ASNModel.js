// models/ASNModel.js
const mongoose = require("mongoose");

const ASNSchema = new mongoose.Schema({
  // "AS15169"
  asn: {
    type: String,
    required: true,
    index: true,
  },

  // "Google LLC"
  asn_org: {
    type: String,
    default: null,
  },

  // Cloud provider detection (AWS, Azure, GCP, OVH, Hetzner...)
  provider: {
    type: String,
    default: "Unknown",
  },

  // Total attacks seen from this ASN
  count: {
    type: Number,
    default: 1,
  },

  // Last updated timestamp (helps future trend charts)
  last_updated: {
    type: Date,
    default: Date.now,
  },
});

// Explicit collection name "asns"
module.exports = mongoose.model("ASN", ASNSchema, "asns");