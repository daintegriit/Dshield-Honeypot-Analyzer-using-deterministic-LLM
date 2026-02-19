const express = require("express");
const router = express.Router();

const Attack = require("../models/AttackModel");
const DShieldLog = require("../models/DShieldLogModel");
const Protocol = require("../models/ProtocolModel");
const Port = require("../models/PortModel");
const TopIP = require("../models/TopIPModel");

// ----------------------------------------------------
// PARSE LOG (DShield format)
// ----------------------------------------------------
function parseDShieldLog(rawline) {
    const source_ip   = rawline.match(/SRC=([\d.]+)/)?.[1] || null;
    const target_ip   = rawline.match(/DST=([\d.]+)/)?.[1] || null;
    const source_port = Number(rawline.match(/SPT=(\d+)/)?.[1]) || null;
    const target_port = Number(rawline.match(/DPT=(\d+)/)?.[1]) || null;

    const protocol = rawline.match(/PROTO=([A-Z0-9]+)/)?.[1] || "UNKNOWN";
    const protocolMap = { TCP: 6, UDP: 17, ICMP: 1 };
    const protocol_number = protocolMap[protocol] || null;

    const timestamp = new Date();

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
        raw: rawline,
        timestamp,
        source_ip,
        target_ip,
        source_port,
        target_port,
        port: target_port,
        protocol,
        protocol_number,
        numericSeverity,
        severity,
        attack_type: attack_category,
        attack_category,
        needs_enrichment: true
    };
}


// ----------------------------------------------------
// INGEST ENDPOINT
// ----------------------------------------------------
router.post("/log", async (req, res) => {
    try {
        const { raw } = req.body;
        if (!raw) return res.status(400).json({ message: "Missing raw log" });

        // Ignore duplicate raw logs
        //const existing = await DShieldLog.findOne({ raw });
        //if (existing) {
        //    return res.json({ ok: true, message: "Duplicate raw log ignored" });
        //}

        // Parse the log
        const parsed = parseDShieldLog(raw);
        if (!parsed.source_ip)
            return res.status(400).json({ message: "Invalid log format" });

        // Store raw line
        const rawDoc = await DShieldLog.create({
            raw,
            ...parsed
        });

        // Store parsed attack (WORKER handles enrichment)
        const attackDoc = await Attack.create(parsed);

        // -------------------------------
        // COUNTERS ONLY (NO ENRICHMENT)
        // -------------------------------
        const now = new Date();

        const sevField = {
            1: "low_count",
            2: "medium_count",
            3: "high_count",
            4: "critical_count"
        }[parsed.numericSeverity];

        await TopIP.updateOne(
            { source_ip: parsed.source_ip },
            {
                $inc: { count: 1, [sevField]: 1 },
                $set: { last_seen: now },
                $setOnInsert: { first_seen: now }
            },
            { upsert: true }
        );

        if (parsed.target_port) {
            await Port.updateOne(
                { port: parsed.target_port },
                {
                    $inc: { count: 1, [sevField]: 1 },
                    $set: { last_updated: now }
                },
                { upsert: true }
            );
        }

        if (parsed.protocol) {
            await Protocol.updateOne(
                { protocol: parsed.protocol },
                {
                    $inc: { count: 1, [parsed.severity + "_count"]: 1 },
                    $set: { last_updated: now, protocol_number: parsed.protocol_number }
                },
                { upsert: true }
            );
        }

        res.json({
            ok: true,
            message: "Ingest successful — enrichment queued",
            raw: rawDoc,
            parsed: attackDoc
        });

    } catch (err) {
        console.error("INGEST ERROR:", err);
        res.status(500).json({ message: "Ingest failed", error: err.message });
    }
});

module.exports = router;