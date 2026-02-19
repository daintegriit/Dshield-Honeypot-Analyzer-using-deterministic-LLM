// models/GeoCacheModel.js
const mongoose = require("mongoose");

/**
 * GeoCache Model (GEO ONLY)
 * --------------------------------------------------------
 * Caches:
 *   - GeoIP information (country, region, city, coords)
 *   - ASN + Provider
 *
 * TTL:
 *   - Auto-expires after 90 days to keep data fresh
 *
 * Used by enrichmentWorker.js only
 */

const GeoCacheSchema = new mongoose.Schema({
  ip: { 
    type: String, 
    required: true, 
    unique: true, 
    index: true 
  },

  // --------------------------
  // GEO FIELDS
  // --------------------------
  country:   { type: String, default: null },
  region:    { type: String, default: null },
  city:      { type: String, default: null },
  latitude:  { type: Number, default: null },
  longitude: { type: Number, default: null },

  // --------------------------
  // ASN / PROVIDER
  // --------------------------
  asn:       { type: String, default: null },
  asn_org:   { type: String, default: null },
  provider:  { type: String, default: null },

  // --------------------------
  // TTL EXPIRATION
  // --------------------------
  createdAt: {
    type: Date,
    default: Date.now,
    index: { expires: "90d" }  // Auto-delete stale cache
  }
});

// ⚡ Export — consistent collection name
module.exports = mongoose.model("GeoCache", GeoCacheSchema, "geolocation_cache");