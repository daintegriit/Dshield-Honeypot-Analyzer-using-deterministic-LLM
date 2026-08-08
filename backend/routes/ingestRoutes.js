const express = require("express");
const router = express.Router();

const Attack = require("../models/AttackModel");
const DShieldLog = require("../models/DShieldLogModel");
const Protocol = require("../models/ProtocolModel");
const Port = require("../models/PortModel");
const TopIP = require("../models/TopIPModel");

// ----------------------------------------------------
// PARSE LOG
// ----------------------------------------------------
function parseDShieldLog(rawline) {
    const source_ip   = rawline.match(/SRC=([\d.]+)/)?.[1] || null;
    const target_ip   = rawline.match(/DST=([\d.]+)/)?.[1] || null;
    const source_port = Number(rawline.match(/SPT=(\d+)/)?.[1]) || null;
    const target_port = Number(rawline.match(/DPT=(\d+)/)?.[1]) || null;

    const protocol = rawline.match(/PROTO=([A-Z0-9]+)/)?.[1] || "UNKNOWN";
    const protocolMap = { TCP: 6, UDP: 17, ICMP: 1 };
    const protocol_number = protocolMap[protocol] || null;

    // ------------------------------------------------------------
    // event_time: the REAL event time, from two possible formats.
    //   1) REPLAY / PCAP lines:  TS=2026-07-14T18:10:00.123Z SRC=...
    //   2) LIVE HONEYPOT lines:  leading Unix epoch seconds, e.g.
    //      1784053225 ip-172-31-21-59 kernel: DSHIELDINPUT ... SRC=...
    // Try TS= first, then the leading epoch, else null.
    // (The route still sets `timestamp` = ingest-arrival time separately.)
    // ------------------------------------------------------------
    let event_time = null;

    const tsMatch = rawline.match(/TS=([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.\-]+Z)/);
    if (tsMatch) {
        const p = new Date(tsMatch[1]);
        if (Number.isFinite(p.getTime())) event_time = p;
    }

    if (!event_time) {
        const epochMatch = rawline.match(/^\s*(\d{9,10})(?:\.\d+)?\s/);
        if (epochMatch) {
            const d = new Date(Number(epochMatch[1]) * 1000);
            if (Number.isFinite(d.getTime())) event_time = d;
        }
    }

    let numericSeverity = 1;
    if (protocol === "TCP" && target_port === 22) numericSeverity = 4;
    else if (target_port === 23) numericSeverity = 3;
    else if ([445, 3389].includes(target_port)) numericSeverity = 4;
    else if (target_port && target_port < 1024) numericSeverity = 2;
    else if (source_port === 0) numericSeverity = 3;

    const severityMap = ["normal", "low", "medium", "high", "critical"];
    const severity = severityMap[numericSeverity];

    let attack_category = "General Network Scan";
    if (target_port === 22) attack_category = "SSH Brute Force";
    else if (target_port === 23) attack_category = "Telnet Attack";
    else if (target_port === 3389) attack_category = "RDP Scan";
    else if (target_port === 445) attack_category = "SMB Probe";

    return {
        source_ip,
        target_ip,
        source_port,
        target_port,
        port: target_port,
        protocol,
        protocol_number,
        event_time,
        numericSeverity,
        severity,
        attack_type: attack_category,
        attack_category,
        needs_enrichment: true
    };
}

// ----------------------------------------------------
// INGEST ENDPOINT (REAL-TIME STREAMING VERSION)
// ----------------------------------------------------
router.post("/log", async (req, res) => {
    try {
        let payload = req.body;

        // Normalize to array
        if (!Array.isArray(payload)) {
            payload = [payload];
        }

        // -------------------------------
        // PARSE (carry per-item source tag)
        // -------------------------------
        // Live honeypot forwarder sends { raw } (no source)  -> "honeypot"
        // PCAP replay sends { raw, source:"replay", replay_pcap } -> "replay"
        const parsedDocs = [];
        for (let item of payload) {
            const raw = item && item.raw;
            if (!raw) continue;

            const parsed = parseDShieldLog(raw);
            if (!parsed.source_ip) continue;

            const isReplay = item.source === "replay";

            parsedDocs.push({
                raw,
                ...parsed,
                source: isReplay ? "replay" : "honeypot",
                replay_pcap: isReplay ? (item.replay_pcap || null) : null,

                // CTU-13 per-flow ground truth (only present on labeled replays)
                ctu_label:    item.ctu_label    || null,
                ctu_class:    item.ctu_class    || null,
                ctu_subclass: item.ctu_subclass || null
            });
        }

        if (parsedDocs.length === 0) {
            return res.status(400).json({ message: "No valid raw logs" });
        }

        // ============================================================
        // ELITE TIMESTAMP FIX
        // ============================================================
        // `timestamp` = ingest-arrival time, monotonically increasing within a
        // batch to preserve ordering. `event_time` (set in parse) holds the true
        // event time. Both are stored.
        const baseTime = Date.now();
        for (let i = 0; i < parsedDocs.length; i++) {
            parsedDocs[i].timestamp = new Date(baseTime + i);
        }

        // ============================================================
        // STEP 1 — REAL-TIME INGEST (ONLY THING WE AWAIT)
        // ============================================================
        await DShieldLog.insertMany(parsedDocs, { ordered: false });

        // RESPOND IMMEDIATELY (REAL-TIME GUARANTEE)
        res.json({
            ok: true,
            ingested: parsedDocs.length,
            mode: payload.length > 1 ? "batch" : "single"
        });

        // ============================================================
        // STEP 2 — ASYNC PIPELINE (NON-BLOCKING)
        // ============================================================
        setImmediate(async () => {
            try {
                const now = new Date();

                // -------------------------------
                // ATTACK COLLECTION
                // -------------------------------
                await Attack.insertMany(parsedDocs, { ordered: false });

                // -------------------------------
                // BULK OPS PREP
                // -------------------------------
                const topIPOps = [];
                const portOps = [];
                const protocolOps = [];

                for (let doc of parsedDocs) {
                    // Do NOT let replayed pcap traffic pollute lifetime dashboard
                    // counters. Replay is measured via the `attacks` collection
                    // (filtered by source) in the experiment.
                    if (doc.source === "replay") continue;

                    const sevField = {
                        1: "low_count",
                        2: "medium_count",
                        3: "high_count",
                        4: "critical_count"
                    }[doc.numericSeverity];

                    // TopIP
                    topIPOps.push({
                        updateOne: {
                            filter: { source_ip: doc.source_ip },
                            update: {
                                $inc: { count: 1, [sevField]: 1 },
                                $set: { last_seen: now },
                                $setOnInsert: { first_seen: now }
                            },
                            upsert: true
                        }
                    });

                    // Port
                    if (doc.target_port) {
                        portOps.push({
                            updateOne: {
                                filter: { port: doc.target_port },
                                update: {
                                    $inc: { count: 1, [sevField]: 1 },
                                    $set: { last_updated: now }
                                },
                                upsert: true
                            }
                        });
                    }

                    // Protocol
                    if (doc.protocol) {
                        protocolOps.push({
                            updateOne: {
                                filter: { protocol: doc.protocol },
                                update: {
                                    $inc: { count: 1, [doc.severity + "_count"]: 1 },
                                    $set: {
                                        last_updated: now,
                                        protocol_number: doc.protocol_number
                                    }
                                },
                                upsert: true
                            }
                        });
                    }
                }

                // -------------------------------
                // BULK EXECUTION
                // -------------------------------
                if (topIPOps.length) await TopIP.bulkWrite(topIPOps);
                if (portOps.length) await Port.bulkWrite(portOps);
                if (protocolOps.length) await Protocol.bulkWrite(protocolOps);

            } catch (err) {
                console.error("ASYNC PIPELINE ERROR:", err);
            }
        });

    } catch (err) {
        console.error("INGEST ERROR:", err);
        res.status(500).json({ message: "Ingest failed", error: err.message });
    }
});

module.exports = router;
