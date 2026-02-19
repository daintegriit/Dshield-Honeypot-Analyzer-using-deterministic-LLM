// backend/controllers/ingestController.js
const dotenv = require("dotenv");
dotenv.config();

const mongoose = require("mongoose");
const Attack = require("../models/AttackModel");

const INGEST_SHARED_KEY = process.env.INGEST_SHARED_KEY;

exports.ingestLog = async (req, res) => {
  try {
    // -------------------------------
    // AUTH CHECK
    // -------------------------------
    const authHeader = req.headers["authorization"] || "";
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice("Bearer ".length)
      : null;

    if (!INGEST_SHARED_KEY || token !== INGEST_SHARED_KEY) {
      return res.status(401).json({ message: "Unauthorized ingest request" });
    }

    // Normalize to array
    let events = Array.isArray(req.body) ? req.body : [req.body];

    // -------------------------------
    // PROCESS EACH EVENT
    // -------------------------------
    const attacksToInsert = [];

    for (const e of events) {
      if (!e || (!e.raw && !e.parsed)) continue;

      const p = e.parsed || {};

      attacksToInsert.push({
        raw: e.raw || null,

        // Parsed DShield fields
        source_ip:   p.source_ip ?? null,
        target_ip:   p.target_ip ?? null,

        source_port: p.source_port ?? null,
        target_port: p.target_port ?? null,

        protocol:        p.protocol ?? "UNKNOWN",
        protocol_number: p.protocol_number ?? null,

        // Attack classification starts here
        attack_type:     "Unknown",
        attack_category: "Unknown",

        numericSeverity: 1,
        severity:        "low",

        timestamp: p.timestamp ? new Date(p.timestamp) : new Date(),

        // Geo empty → enrichmentWorker will fill
        country:   null,
        region:    null,
        city:      null,
        latitude:  null,
        longitude: null,

        asn:       null,
        asn_org:   null,
        provider:  null,

        threat_score: null,
        threat_name:  null,

        needs_enrichment: true
      });
    }

    if (!attacksToInsert.length) {
      return res.status(400).json({ message: "No valid events found in payload" });
    }

    // -------------------------------
    // INSERT INTO ATTACKS COLLECTION
    // -------------------------------
    const result = await Attack.insertMany(attacksToInsert);

    return res.status(201).json({
      message: "Ingest successful",
      inserted: result.length
    });

  } catch (err) {
    console.error("Ingest error:", err);
    return res.status(500).json({ message: "Error ingesting logs", error: err.message });
  }
};