const mongoose = require("mongoose");

const DShieldLogSchema = new mongoose.Schema({
    // raw log line from the firewall/honeypot
    raw: { type: String, required: true, index: true },

    // `timestamp` = ingest-arrival time
    timestamp: { type: Date, default: Date.now },

    // `event_time` = true event time (TS= for replay, epoch prefix for live honeypot)
    event_time: { type: Date, default: null, index: true },

    source_ip:   { type: String, default: null },
    target_ip:   { type: String, default: null },
    source_port: { type: Number, default: null },
    target_port: { type: Number, default: null },
    protocol:    { type: String, default: null },

    // ---------------------------------------
    // SOURCE TAGGING (experiment isolation)
    // ---------------------------------------
    source:      { type: String, default: "honeypot", index: true },
    replay_pcap: { type: String, default: null },
});

module.exports = mongoose.model("DShieldLog", DShieldLogSchema, "DShieldLogs");
