
require("dotenv").config();
const mongoose = require("mongoose");
const axios = require("axios");

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

// UTIL – wrapper for AbuseIPDB or equivalent
const fetchThreatIntel = require("../utils/fetchThreatIntel");

/* -----------------------------------------------------------
   MONGO CONNECT
----------------------------------------------------------- */
const mongoUri = process.env.MONGO_URI;

if (!mongoUri) {
  console.error("❌ Missing MONGO_URI");
  process.exit(1);
}

mongoose
  .connect(mongoUri)
  .then(() => console.log("✅ Enrichment Worker Connected"))
  .catch((err) => {
    console.error("❌ MongoDB Error:", err.message);
    process.exit(1);
  });

console.log("⚡ Enrichment Worker Started");

/* -----------------------------------------------------------
   UTILS
----------------------------------------------------------- */
function parseAsnString(str) {
  if (!str) return { asn: null, asn_org: null };
  const parts = str.split(" ");
  return { asn: parts[0], asn_org: parts.slice(1).join(" ") || null };
}

/* -----------------------------------------------------------
   COUNTRY NORMALIZATION
----------------------------------------------------------- */
function normalizeCountry(country) {
  if (!country) return null;
  country = country.trim();

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

  return map[country] || country;
}

/* -----------------------------------------------------------
   GEO LOOKUP WITH CACHING + FALLBACKS
----------------------------------------------------------- */
async function lookupGeo(ip) {
  if (!ip) return null;

  const cached = await GeoCache.findOne({ ip });
  if (cached) return cached;

  const upsertOpts = { upsert: true, new: true, setDefaultsOnInsert: true };
  let geo = {};

  /** PRIMARY PROVIDER — IPINFO */
  try {
    const info = await axios.get(
      `https://ipinfo.io/${ip}?token=${process.env.IPINFO_TOKEN}`
    );

    const loc = info.data.loc?.split(",") || [null, null];

    geo = {
      ip,
      country: normalizeCountry(info.data.country),
      region: info.data.region || null,
      city: info.data.city || null,
      latitude: loc[0] ? parseFloat(loc[0]) : null,
      longitude: loc[1] ? parseFloat(loc[1]) : null,
      asn: info.data.org ? info.data.org.split(" ")[0] : null,
      asn_org: info.data.org
        ? info.data.org.split(" ").slice(1).join(" ")
        : null,
      provider: info.data.org || null,
      createdAt: new Date(),
    };

    return await GeoCache.findOneAndUpdate(
      { ip },
      { $setOnInsert: geo },
      upsertOpts
    );
  } catch (e) {
    console.log(" IPINFO failed:", e.message);
  }

  /** FALLBACK — IP-API */
  try {
    const resp = await axios.get(
      `http://ip-api.com/json/${ip}?fields=status,country,regionName,city,lat,lon,as,query`
    );

    if (resp.data.status === "success") {
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
      );
    }
  } catch (e) {
    console.log(" IP-API failed:", e.message);
  }

  /** LAST RESORT — store null geo to prevent infinite re-tries */
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
  );
}

/* -----------------------------------------------------------
   COUNTRY CREATE
----------------------------------------------------------- */
async function findOrCreateCountry(geo) {
  if (!geo?.country) return null;

  return await Country.findOneAndUpdate(
    { country: geo.country },
    {
      $setOnInsert: {
        country: geo.country,
        region: geo.region,
        latitude: geo.latitude,
        longitude: geo.longitude,
        attackCount: 0,
        critical_count: 0,
        high_count: 0,
        medium_count: 0,
        low_count: 0,
        createdAt: new Date(),
      },
    },
    { new: true, upsert: true }
  );
}

/* -----------------------------------------------------------
   DAILY COMPARISON
----------------------------------------------------------- */
async function updateDailyComparison(attack, geo) {
  const today = new Date().toISOString().split("T")[0];

  const sev = (attack.severity || "low").toLowerCase();
  const map = {
    critical: "critical_count",
    high: "high_count",
    medium: "medium_count",
    low: "low_count",
  };

  await Comparison.updateOne(
    { day: today },
    {
      $inc: {
        total_attacks: 1,
        [map[sev]]: 1,
        unique_ips: 1,
        unique_ports: 1,
        unique_countries: geo?.country ? 1 : 0,
      },
    },
    { upsert: true }
  );
}

/* -----------------------------------------------------------
   DASHBOARD STATS
----------------------------------------------------------- */
async function updateDashboardStats(attack, geo) {
  await findOrCreateCountry(geo);

  const sev = (attack.severity || "low").toLowerCase();
  const map = {
    critical: "critical_count",
    high: "high_count",
    medium: "medium_count",
    low: "low_count",
  };

  /** PORT */
  if (attack.target_port) {
    await Port.updateOne(
      { port: attack.target_port },
      {
        $inc: { count: 1, [map[sev]]: 1 },
        $set: {
          protocol: attack.protocol || "TCP",
          last_updated: new Date(),
        },
      },
      { upsert: true }
    );
  }

  /** SEVERITY */
  await Severity.updateOne(
    { level: attack.severity || "low" },
    { $inc: { count: 1 } },
    { upsert: true }
  );

  /** TOP IP COUNTS (geo+threat handled after attack enrichment) */
  await TopIP.updateOne(
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
        threat_score: null,
        threat_name: null,
      }
    },
    { upsert: true }
  );

  /** COUNTRY STATS */
  if (geo?.country) {
    await Country.updateOne(
      { country: geo.country },
      {
        $inc: { attackCount: 1, [map[sev]]: 1 },
        $set: {
          region: geo.region,
          latitude: geo.latitude,
          longitude: geo.longitude,
          last_updated: new Date(),
        },
      }
    );
  }

  /** ASN STATS */
  if (geo?.asn) {
    await ASN.updateOne(
      { asn: geo.asn },
      {
        $inc: { count: 1 },
        $setOnInsert: { asn_org: geo.asn_org, provider: geo.provider },
      },
      { upsert: true }
    );
  }

  await updateDailyComparison(attack, geo);
}

/* -----------------------------------------------------------
   THREAT INTEL — TTL + caching
----------------------------------------------------------- */
async function lookupThreatIntelCached(ip) {
  if (!ip) return null;

  const TTL = 1000 * 60 * 60 * 12; // 12 hours
  const cached = await ThreatIntelCache.findOne({ ip });

  if (cached && Date.now() - cached.createdAt.getTime() < TTL) {
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
    console.error("⚠️ fetchThreatIntel error:", err.message);
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
      ip,
      abuseConfidenceScore: intel.abuseConfidenceScore,
      isTor: intel.isTor,
      totalReports: intel.totalReports,
      lastReportedAt: intel.lastReportedAt,
      createdAt: new Date(),
    },
    { upsert: true }
  );

  return intel;
}

/* -----------------------------------------------------------
   MAIN LOOP
----------------------------------------------------------- */
async function processQueue() {
  try {
    const attack = await Attack.findOne({ needs_enrichment: true });

    if (!attack) {
      process.stdout.write(".");
      await new Promise((r) => setTimeout(r, 1500));
      return processQueue();
    }

    console.log("\n Enriching attack from IP:", attack.source_ip);

    /** 1) GEO */
    const geo = await lookupGeo(attack.source_ip);

    /** 2) THREAT INTEL */
    const intel = await lookupThreatIntelCached(attack.source_ip);

    /** 3) MAP THREAT */
    let threatScore = intel?.abuseConfidenceScore ?? null;
    let threatName = null;

    if (intel) {
      if (intel.isTor) {
        threatName = "Tor exit node";
      } else if (typeof intel.abuseConfidenceScore === "number") {
        if (intel.abuseConfidenceScore >= 80) threatName = "High risk IP";
        else if (intel.abuseConfidenceScore >= 40)
          threatName = "Suspicious IP";
        else threatName = "Low risk / reported";
      }
    }

    /** 4) UPDATE ATTACK */
    attack.country = geo?.country || null;
    attack.region = geo?.region || null;
    attack.city = geo?.city || null;
    attack.latitude = geo?.latitude || null;
    attack.longitude = geo?.longitude || null;
    attack.asn = geo?.asn || null;
    attack.asn_org = geo?.asn_org || null;
    attack.provider = geo?.provider || null;

    attack.threat_score = threatScore;
    attack.threat_name = threatName;

    attack.needs_enrichment = false;
    await attack.save();

    /** 5) UPDATE TOP IP — AFTER attack enrichment (FINAL VALUES) */
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
        },
      },
      { upsert: true }
    );

    /** 6) UPDATE DASHBOARD STATS */
    await updateDashboardStats(attack, geo);

    console.log(` Enriched attack ${attack._id}`);
  } catch (err) {
    console.error("❌ Worker Error:", err);
  }

  return processQueue();
}

processQueue();