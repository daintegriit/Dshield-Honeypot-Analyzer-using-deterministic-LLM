// models/ProtocolModel.js
const mongoose = require("mongoose");

const ProtocolSchema = new mongoose.Schema({
  // Protocol name (TCP, UDP, ICMP, Other)
  protocol: { 
    type: String, 
    required: true, 
    index: true 
  },

  // Optional: numeric protocol ID (6 = TCP, 17 = UDP, 1 = ICMP)
  protocol_number: { 
    type: Number, 
    default: null 
  },

  // Total attacks counted for this protocol
  count: { 
    type: Number, 
    default: 1 
  },

  // Track last time this protocol bucket was updated
  last_updated: { 
    type: Date, 
    default: Date.now 
  },

  // Severity breakdown (future trend analytics)
  critical_count: { type: Number, default: 0 },
  high_count:     { type: Number, default: 0 },
  medium_count:   { type: Number, default: 0 },
  low_count:      { type: Number, default: 0 },
});

module.exports = mongoose.model("Protocol", ProtocolSchema, "protocols");