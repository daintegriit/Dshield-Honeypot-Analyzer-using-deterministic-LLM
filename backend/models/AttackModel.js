// models/AttackModel.js

const mongoose = require("mongoose");

const AttackSchema = new mongoose.Schema({
    // ---------------------------------------
    // RAW INGESTION LINE
    // ---------------------------------------
    raw: { type: String },

    // ---------------------------------------
    // PARSED FIELDS
    // ---------------------------------------
    source_ip:   { type: String, required: true },
    target_ip:   { type: String, default: null },

    source_port: { type: Number, default: null },
    target_port: { type: Number, default: null },

    port:        { type: Number, default: null },

    protocol:        { type: String, default: "UNKNOWN", index: true },
    protocol_number: { type: Number, default: null },

    // ---------------------------------------
    // ATTACK TYPE / CATEGORY
    // ---------------------------------------
    attack_type:     { type: String, default: "Unknown", index: true },
    attack_category: { type: String, default: "Unknown" },

    // ---------------------------------------
    // SEVERITY
    // ---------------------------------------
    numericSeverity: { type: Number, default: 0 },
    severity:        { type: String, default: "normal", index: true },

    // ---------------------------------------
    // TIMESTAMP
    // ---------------------------------------
    timestamp: { type: Date, default: Date.now, index: true },

    // ---------------------------------------
    // GEO + ASN ENRICHMENT
    // ---------------------------------------
    country:    { type: String, default: null, index: true },
    region:     { type: String, default: null },
    city:       { type: String, default: null },
    latitude:   { type: Number, default: null },
    longitude:  { type: Number, default: null },

    asn:        { type: String, default: null, index: true },
    asn_org:    { type: String, default: null },
    provider:   { type: String, default: null },

    // ---------------------------------------
    // THREAT INTEL
    // ---------------------------------------
    threat_score: { type: Number, default: null },
    threat_name:  { type: String, default: null },

    // ---------------------------------------
    // ENRICHMENT FLAG
    // ---------------------------------------
    needs_enrichment: { type: Boolean, default: true }
},
{
    collection: "attacks" 
});

module.exports = mongoose.model("Attack", AttackSchema);