/**
 * enrichmentWorker.js – Background worker to enrich new attacks with geo and threat intel
 *
 * This worker continuously polls for new attacks that need enrichment, performs geo lookups and threat intelligence queries, and updates the attack records and dashboard stats accordingly.
 * ------------------------------------------------------------
 */

/**
 * enrichmentWorker.js
 * ------------------------------------------------------------
 * Near-real-time enrichment worker for new attacks.
 *
 * Goals:
 * - atomic claim to avoid duplicate work across multiple workers
 * - bounded concurrency to prevent heap blowups
 * - timeout-safe external lookups
 * - cache-first geo + threat intel enrichment
 * - resilient retry behavior
 * - dashboard aggregate maintenance
 * - graceful shutdown
 *
 * Notes:
 * - This is near-real-time polling, not Kafka/Redis streaming.
 * - It is production-grade for a single-node / Mongo-backed system.
 * ------------------------------------------------------------
 */

require("dotenv").config();

const mongoose = require("mongoose");
const axios = require("axios");
const http = require("http");
const https = require("https");

// MAIN MODELS
const Attack = require("../models/AttackModel");

// DASHBOARD MODELS
const Port = require("../models/PortModel");
const Protocol = require("../models/ProtocolModel");
const Severity = require("../models/SeverityModel");
const TopIP = require("../models/TopIPModel");
const Country = require("../models/CountryModel");
const ASN = require("../models/ASNModel");
const GeoCache = require("../models/GeolocationCacheModel");
const Comparison = require("../models/ComparisonModel");

// THREAT INTEL CACHE
const ThreatIntelCache = require("../models/ThreatIntelCacheModel");

// UTIL
const fetchThreatIntel = require("../utils/fetchThreatIntel");

/* -----------------------------------------------------------
   CONFIG
----------------------------------------------------------- */
const mongoUri = process.env.MONGO_URI;

if (!mongoUri) {
  console.error("❌ Missing MONGO_URI");
  process.exit(1);
}

const CONFIG = {
  IDLE_POLL_MS: Number(process.env.ENRICH_IDLE_POLL_MS || 1500),
  ERROR_BACKOFF_MS: Number(process.env.ENRICH_ERROR_BACKOFF_MS || 4000),
  EMPTY_BATCH_BACKOFF_MS: Number(process.env.ENRICH_EMPTY_BATCH_BACKOFF_MS || 1200),

  MAX_BATCH_SIZE: Number(process.env.ENRICH_BATCH_SIZE || 100),
  MAX_CONCURRENCY: Number(process.env.ENRICH_MAX_CONCURRENCY || 20),

  AXIOS_TIMEOUT_MS: Number(process.env.ENRICH_HTTP_TIMEOUT_MS || 8000),
  THREAT_CACHE_TTL_MS: Number(
    process.env.ENRICH_THREAT_CACHE_TTL_MS || 1000 * 60 * 60 * 12
  ), // 12h

  LOG_HEARTBEAT_EVERY_IDLE_CYCLES: Number(
    process.env.ENRICH_HEARTBEAT_IDLE_CYCLES || 20
  ),
};

let shuttingDown = false;
let idleCycles = 0;

/* -----------------------------------------------------------
   HTTP CLIENT
----------------------------------------------------------- */
const httpClient = axios.create({
  timeout: CONFIG.AXIOS_TIMEOUT_MS,
  httpAgent: new http.Agent({
    keepAlive: true,
    maxSockets: 50,
  }),
  httpsAgent: new https.Agent({
    keepAlive: true,
    maxSockets: 50,
  }),
  validateStatus: (status) => status >= 200 && status < 500,
});

/* -----------------------------------------------------------
   HELPERS
----------------------------------------------------------- */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function nowIso() {
  return new Date().toISOString();
}

function parseAsnString(str) {
  if (!str) return { asn: null, asn_org: null };
  const parts = String(str).trim().split(/\s+/);
  return {
    asn: parts[0] || null,
    asn_org: parts.slice(1).join(" ") || null,
  };
}

function normalizeCountry(country) {
  if (!country) return null;
  const value = String(country).trim();

  const map = {
    "United States": "US",
    USA: "US",
    "U.S.": "US",
    "United Kingdom": "GB",
    "U.K.": "GB",
    "Great Britain": "GB",
    Russia: "RU",
    "Russian Federation": "RU",
  };

  return map[value] || value;
}

function normalizeProtocol(protocol) {
  if (!protocol) return null;
  return String(protocol).trim().toUpperCase();
}

function severityField(level) {
  const sev = String(level || "low").toLowerCase();
  const map = {
    critical: "critical_count",
    high: "high_count",
    medium: "medium_count",
    low: "low_count",
  };
  return map[sev] || "low_count";
}

function mapThreatName(intel) {
  if (!intel) return null;

  if (intel.isTor) return "Tor exit node";

  if (typeof intel.abuseConfidenceScore === "number") {
    if (intel.abuseConfidenceScore >= 80) return "High risk IP";
    if (intel.abuseConfidenceScore >= 40) return "Suspicious IP";
    return "Low risk / reported";
  }

  return null;
}

async function runWithConcurrency(items, limit, worker) {
  const results = [];
  let index = 0;

  async function runner() {
    while (!shuttingDown) {
      const current = index++;
      if (current >= items.length) break;
      results[current] = await worker(items[current], current);
    }
  }

  const runners = Array.from(
    { length: Math.min(limit, items.length) },
    () => runner()
  );

  await Promise.all(runners);
  return results;
}

/* -----------------------------------------------------------
   MONGO CONNECT
----------------------------------------------------------- */
async function connectMongo() {
  await mongoose.connect(mongoUri, {
    maxPoolSize: Number(process.env.MONGO_MAX_POOL_SIZE || 20),
  });

  console.log("✅ Enrichment Worker Connected");

  // 🔥 ADD THESE LINES
  console.log("🔥 DB NAME:", mongoose.connection.name);
  console.log("🔥 COLLECTION:", Attack.collection.name);
}
/* -----------------------------------------------------------
   GEO LOOKUP WITH CACHE + FALLBACKS
----------------------------------------------------------- */
async function lookupGeo(ip) {
  if (!ip) return null;

  const cached = await GeoCache.findOne({ ip }).lean();
  if (cached) return cached;

  const upsertOpts = { upsert: true, new: true, setDefaultsOnInsert: true };
  let geo = null;

  try {
    const info = await httpClient.get(
      `https://ipinfo.io/${ip}?token=${process.env.IPINFO_TOKEN || ""}`
    );

    if (info.status >= 200 && info.status < 300) {
      const loc = info.data?.loc?.split(",") || [null, null];

      geo = {
        ip,
        country: normalizeCountry(info.data?.country),
        region: info.data?.region || null,
        city: info.data?.city || null,
        latitude: loc[0] ? parseFloat(loc[0]) : null,
        longitude: loc[1] ? parseFloat(loc[1]) : null,
        asn: info.data?.org ? info.data.org.split(" ")[0] : null,
        asn_org: info.data?.org
          ? info.data.org.split(" ").slice(1).join(" ")
          : null,
        provider: info.data?.org || null,
        createdAt: new Date(),
      };

      return await GeoCache.findOneAndUpdate(
        { ip },
        { $setOnInsert: geo },
        upsertOpts
      ).lean();
    }
  } catch (e) {
    console.log(`IPINFO failed for ${ip}: ${e.message}`);
  }

  try {
    const resp = await httpClient.get(
      `http://ip-api.com/json/${ip}?fields=status,country,regionName,city,lat,lon,as,query`
    );

    if (resp.status >= 200 && resp.status < 300 && resp.data?.status === "success") {
      const d = resp.data;
      const { asn, asn_org } = parseAsnString(d.as);

      geo = {
        ip,
        country: normalizeCountry(d.country),
        region: d.regionName || null,
        city: d.city || null,
        latitude: d.lat ?? null,
        longitude: d.lon ?? null,
        asn,
        asn_org,
        provider: asn_org,
        createdAt: new Date(),
      };

      return await GeoCache.findOneAndUpdate(
        { ip },
        { $setOnInsert: geo },
        upsertOpts
      ).lean();
    }
  } catch (e) {
    console.log(`IP-API failed for ${ip}: ${e.message}`);
  }

  geo = {
    ip,
    country: null,
    region: null,
    city: null,
    latitude: null,
    longitude: null,
    asn: null,
    asn_org: null,
    provider: null,
    createdAt: new Date(),
  };

  return await GeoCache.findOneAndUpdate(
    { ip },
    { $setOnInsert: geo },
    upsertOpts
  ).lean();
}

/* -----------------------------------------------------------
   THREAT INTEL CACHE + TTL
----------------------------------------------------------- */
async function lookupThreatIntelCached(ip) {
  if (!ip) return null;

  const cached = await ThreatIntelCache.findOne({ ip }).lean();

  if (
    cached?.createdAt &&
    Date.now() - new Date(cached.createdAt).getTime() < CONFIG.THREAT_CACHE_TTL_MS
  ) {
    return {
      abuseConfidenceScore: cached.abuseConfidenceScore ?? null,
      isTor: cached.isTor ?? null,
      totalReports: cached.totalReports ?? null,
      lastReportedAt: cached.lastReportedAt ?? null,
    };
  }

  let rawIntel = null;

  try {
    rawIntel = await fetchThreatIntel(ip);
  } catch (err) {
    console.error(`⚠️ fetchThreatIntel error for ${ip}:`, err.message);
  }

  const intel = rawIntel
    ? {
        abuseConfidenceScore:
          rawIntel.abuseConfidenceScore ??
          rawIntel.data?.abuseConfidenceScore ??
          null,
        isTor: rawIntel.isTor ?? rawIntel.data?.isTor ?? null,
        totalReports:
          rawIntel.totalReports ?? rawIntel.data?.totalReports ?? null,
        lastReportedAt:
          rawIntel.lastReportedAt ?? rawIntel.data?.lastReportedAt ?? null,
      }
    : {
        abuseConfidenceScore: null,
        isTor: null,
        totalReports: null,
        lastReportedAt: null,
      };

  await ThreatIntelCache.findOneAndUpdate(
    { ip },
    {
      $set: {
        ip,
        abuseConfidenceScore: intel.abuseConfidenceScore,
        isTor: intel.isTor,
        totalReports: intel.totalReports,
        lastReportedAt: intel.lastReportedAt,
        createdAt: new Date(),
      },
    },
    { upsert: true, new: true }
  );

  return intel;
}

/* -----------------------------------------------------------
   DASHBOARD AGGREGATES
----------------------------------------------------------- */
async function updateDailyComparison(attack, geo) {
  const day = new Date().toISOString().split("T")[0];
  const sevField = severityField(attack.severity);

  await Comparison.updateOne(
    { day },
    {
      $setOnInsert: {
        day,
        createdAt: new Date(),
      },
      $inc: {
        total_attacks: 1,
        [sevField]: 1,
      },
      $addToSet: {
        ips_seen: attack.source_ip || null,
        ports_seen: attack.target_port || null,
        countries_seen: geo?.country || null,
      },
      $set: {
        last_updated: new Date(),
      },
    },
    { upsert: true }
  );

  // Keep numeric counters in sync if your schema uses them in charts
  const comparison = await Comparison.findOne({ day }).lean();

  if (comparison) {
    await Comparison.updateOne(
      { day },
      {
        $set: {
          unique_ips: Array.isArray(comparison.ips_seen)
            ? comparison.ips_seen.filter(Boolean).length
            : 0,
          unique_ports: Array.isArray(comparison.ports_seen)
            ? comparison.ports_seen.filter((v) => v !== null && v !== undefined).length
            : 0,
          unique_countries: Array.isArray(comparison.countries_seen)
            ? comparison.countries_seen.filter(Boolean).length
            : 0,
        },
      }
    );
  }
}

async function updateDashboardStats(attack, geo) {
  const sevField = severityField(attack.severity);
  const protocol = normalizeProtocol(attack.protocol);

  const operations = [];

  if (attack.target_port) {
    operations.push(
      Port.updateOne(
        { port: attack.target_port },
        {
          $inc: { count: 1, [sevField]: 1 },
          $set: {
            protocol: protocol || "TCP",
            last_updated: new Date(),
          },
          $setOnInsert: {
            createdAt: new Date(),
          },
        },
        { upsert: true }
      )
    );
  }

  operations.push(
    Severity.updateOne(
      { level: String(attack.severity || "low").toLowerCase() },
      {
        $inc: { count: 1 },
        $setOnInsert: { createdAt: new Date() },
        $set: { last_updated: new Date() },
      },
      { upsert: true }
    )
  );

  if (protocol) {
    operations.push(
      Protocol.updateOne(
        { protocol },
        {
          $inc: { count: 1 },
          $setOnInsert: { createdAt: new Date() },
          $set: { last_updated: new Date() },
        },
        { upsert: true }
      )
    );
  }

  operations.push(
    TopIP.updateOne(
      { source_ip: attack.source_ip },
      {
        $inc: { count: 1 },
        $setOnInsert: {
          country: geo?.country || null,
          region: geo?.region || null,
          city: geo?.city || null,
          latitude: geo?.latitude || null,
          longitude: geo?.longitude || null,
          asn: geo?.asn || null,
          asn_org: geo?.asn_org || null,
          provider: geo?.provider || null,
          threat_score: attack.threat_score ?? null,
          threat_name: attack.threat_name ?? null,
          createdAt: new Date(),
        },
        $set: {
          last_updated: new Date(),
        },
      },
      { upsert: true }
    )
  );

  if (geo?.country) {
    operations.push(
      Country.updateOne(
        { country: geo.country },
        {
          $inc: { attackCount: 1, [sevField]: 1 },
          $setOnInsert: {
            country: geo.country,
            region: geo.region,
            latitude: geo.latitude,
            longitude: geo.longitude,
            createdAt: new Date(),
          },
          $set: {
            region: geo.region,
            latitude: geo.latitude,
            longitude: geo.longitude,
            last_updated: new Date(),
          },
        },
        { upsert: true }
      )
    );
  }

  if (geo?.asn) {
    operations.push(
      ASN.updateOne(
        { asn: geo.asn },
        {
          $inc: { count: 1 },
          $setOnInsert: {
            asn_org: geo.asn_org,
            provider: geo.provider,
            createdAt: new Date(),
          },
          $set: {
            last_updated: new Date(),
          },
        },
        { upsert: true }
      )
    );
  }

  await Promise.all(operations);
  await updateDailyComparison(attack, geo);
}

/* -----------------------------------------------------------
   ATOMIC CLAIMING
----------------------------------------------------------- */
/**
 * Claim a batch atomically by flipping needs_enrichment:false immediately.
 * This avoids multiple workers claiming the same attack.
 *
 * On failure, we explicitly re-queue that attack by setting needs_enrichment:true.
 * This design works with your current schema without requiring new fields.
 */
async function claimNextBatch(limit) {
  const claimedBatch = [];

  for (let i = 0; i < limit; i++) {

    // 🔥 ATOMIC CLAIM (single query, no separate find)
    const claimed = await Attack.findOneAndUpdate(
      { needs_enrichment: true },
      {
        $set: {
          needs_enrichment: false,
          enrichment_claimed_at: new Date(),
          enrichment_claimed_by: process.pid
        }
      },
      {
        sort: { timestamp: -1 }, // 🔥 NEWEST FIRST (real-time priority)
        new: true
      }
    );

    // ❌ Nothing left to process
    if (!claimed) {
      await sleep(CONFIG.EMPTY_BATCH_BACKOFF_MS);
      break;
    }

    // ✅ Add to batch
    claimedBatch.push(claimed);
  }

  return claimedBatch;
}



/* -----------------------------------------------------------
   PROCESS ONE ATTACK
----------------------------------------------------------- */
async function processClaimedAttack(attack) {
  const attackId = attack._id;

  try {
    console.log(`[${nowIso()}] Enriching attack from IP: ${attack.source_ip}`);

    const [geo, intel] = await Promise.all([
      lookupGeo(attack.source_ip),
      lookupThreatIntelCached(attack.source_ip),
    ]);

    attack.country = geo?.country || null;
    attack.region = geo?.region || null;
    attack.city = geo?.city || null;
    attack.latitude = geo?.latitude || null;
    attack.longitude = geo?.longitude || null;
    attack.asn = geo?.asn || null;
    attack.asn_org = geo?.asn_org || null;
    attack.provider = geo?.provider || null;

    attack.threat_score = intel?.abuseConfidenceScore ?? null;
    attack.threat_name = mapThreatName(intel);

    attack.enriched_at = new Date();
    attack.last_enrichment_error = null;

    await attack.save();

    await TopIP.updateOne(
      { source_ip: attack.source_ip },
      {
        $set: {
          country: attack.country,
          region: attack.region,
          city: attack.city,
          latitude: attack.latitude,
          longitude: attack.longitude,
          asn: attack.asn,
          asn_org: attack.asn_org,
          provider: attack.provider,
          threat_score: attack.threat_score,
          threat_name: attack.threat_name,
          last_updated: new Date(),
        },
        $setOnInsert: {
          createdAt: new Date(),
        },
      },
      { upsert: true }
    );

    await updateDashboardStats(attack, geo);

    console.log(`[${nowIso()}] ✅ Enriched attack ${attackId}`);
    return { ok: true, attackId };
  } catch (err) {
    console.error(`[${nowIso()}] ❌ Error enriching ${attackId}:`, err.message);

    // Re-queue on failure so the attack is not lost.
    await Attack.updateOne(
      { _id: attackId },
      {
        $set: {
          needs_enrichment: true,
          last_enrichment_error: err.message,
          last_enrichment_failed_at: new Date(),
        },
      }
    );

    return { ok: false, attackId, error: err.message };
  }
}

/* -----------------------------------------------------------
   WORKER LOOP
----------------------------------------------------------- */
async function workerLoop() {
  console.log(
    `⚡ Enrichment Worker Started | batch=${CONFIG.MAX_BATCH_SIZE} concurrency=${CONFIG.MAX_CONCURRENCY}`
  );

  while (!shuttingDown) {
    try {

      console.log("🔍 Claim attempt...");

      const claimedBatch = await claimNextBatch(CONFIG.MAX_BATCH_SIZE);

      console.log("📦 Claimed batch size:", claimedBatch.length);


      if (!claimedBatch.length) {
        idleCycles += 1;

        if (idleCycles % CONFIG.LOG_HEARTBEAT_EVERY_IDLE_CYCLES === 0) {
          console.log(`[${nowIso()}] idle... waiting for new attacks`);
        }

        await sleep(CONFIG.EMPTY_BATCH_BACKOFF_MS);
        continue;
      }

      idleCycles = 0;

      const results = await runWithConcurrency(
        claimedBatch,
        CONFIG.MAX_CONCURRENCY,
        processClaimedAttack
      );

      const okCount = results.filter((r) => r?.ok).length;
      const failCount = results.filter((r) => r && !r.ok).length;

      console.log(
        `[${nowIso()}] batch complete | claimed=${claimedBatch.length} ok=${okCount} failed=${failCount}`
      );

      // Small yield so the loop stays responsive under sustained load.
      await sleep(25);
    } catch (err) {
      console.error(`[${nowIso()}] ❌ Worker loop error:`, err);
      await sleep(CONFIG.ERROR_BACKOFF_MS);
    }
  }

  console.log(`[${nowIso()}] Worker loop exiting cleanly`);
}

/* -----------------------------------------------------------
   STARTUP / SHUTDOWN
----------------------------------------------------------- */
async function start() {
  try {
    await connectMongo();
    await workerLoop();
  } catch (err) {
    console.error("❌ Startup Error:", err.message);
    process.exit(1);
  }
}

async function gracefulShutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;

  console.log(`[${nowIso()}] ${signal} received. Shutting down worker...`);

  try {
    await mongoose.disconnect();
    console.log(`[${nowIso()}] Mongo disconnected`);
  } catch (err) {
    console.error(`[${nowIso()}] Error during shutdown:`, err.message);
  } finally {
    process.exit(0);
  }
}

process.on("SIGINT", () => {
  gracefulShutdown("SIGINT");
});

process.on("SIGTERM", () => {
  gracefulShutdown("SIGTERM");
});

start();
