const mongoose = require("mongoose");

const DShieldLogSchema = new mongoose.Schema({
    // raw log line from the firewall/honeypot
    raw: { type: String, required: true, index: true },

    // When the log was ingested
    timestamp: { type: Date, default: Date.now },

    source_ip:   { type: String, default: null },
    target_ip:   { type: String, default: null },
    source_port: { type: Number, default: null },
    target_port: { type: Number, default: null },
    protocol:    { type: String, default: null },


});

module.exports = mongoose.model("DShieldLog", DShieldLogSchema, "DShieldLogs");