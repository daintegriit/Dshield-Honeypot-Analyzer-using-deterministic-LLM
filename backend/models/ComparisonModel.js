const mongoose = require("mongoose");

const ComparisonSchema = new mongoose.Schema({
  day: { type: String, required: true, index: true },

  total_attacks: { type: Number, default: 0 },

  unique_ips: { type: Number, default: 0 },
  unique_ports: { type: Number, default: 0 },
  unique_countries: { type: Number, default: 0 },

  critical_count: { type: Number, default: 0 },
  high_count:    { type: Number, default: 0 },
  medium_count:  { type: Number, default: 0 },
  low_count:     { type: Number, default: 0 },

  last_updated: { type: Date, default: Date.now }
});

module.exports = mongoose.model("Comparison", ComparisonSchema, "comparisons");