// models/PortModel.js
const mongoose = require("mongoose");

const PortSchema = new mongoose.Schema({
  // The attacked port (22, 80, 3389, etc.)
  port: { 
    type: Number, 
    required: true, 
    index: true 
  },

  // Total attacks seen on this port
  count: { 
    type: Number, 
    default: 1 
  },

  // Optional protocol grouping (TCP/UDP/ICMP)
  protocol: { 
    type: String, 
    default: "TCP" 
  },

  // When this port record was last updated
  last_updated: { 
    type: Date, 
    default: Date.now 
  },

  // Future-proof: breakdown of severities hitting this port
  critical_count: { type: Number, default: 0 },
  high_count:     { type: Number, default: 0 },
  medium_count:   { type: Number, default: 0 },
  low_count:      { type: Number, default: 0 },
});

module.exports = mongoose.model("Port", PortSchema, "ports");