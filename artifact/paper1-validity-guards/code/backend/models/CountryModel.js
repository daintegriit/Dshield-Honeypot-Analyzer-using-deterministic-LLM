// models/CountryModel.js

const mongoose = require("mongoose");

const CountrySchema = new mongoose.Schema(
  {
    // Country name (e.g. "United States")
    country: { type: String, required: true, index: true },

    // Total attacks seen
    attackCount: { type: Number, default: 1 },

    // Region from GeoIP (e.g. "North America")
    region: { type: String, default: null },

    // For heatmaps / geospatial charts
    latitude: { type: Number, default: null },
    longitude: { type: Number, default: null },

    // Updated each time enrichment hits this entry
    last_updated: { type: Date, default: Date.now },

    // Severity distribution – future heatmaps & comparison charts
    critical_count: { type: Number, default: 0 },
    high_count:     { type: Number, default: 0 },
    medium_count:   { type: Number, default: 0 },
    low_count:      { type: Number, default: 0 },
  },
  {
    // Auto-add createdAt + updatedAt timestamps
    timestamps: true,
  }
);

// Auto-update last_updated anytime document is modified
CountrySchema.pre("save", function (next) {
  this.last_updated = new Date();
  next();
});

module.exports = mongoose.model("Country", CountrySchema, "countries");