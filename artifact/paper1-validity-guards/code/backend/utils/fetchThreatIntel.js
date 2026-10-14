// utils/fetchThreatIntel.js
require("dotenv").config();
const axios = require("axios");
const ThreatIntelCache = require("../models/ThreatIntelCacheModel");

// ------------------------------------------------------------
// 🔐 MULTI-KEY SUPPORT (comma-separated in .env)
// Example:
// ABUSEIPDB_KEYS=key1,key2,key3
// ------------------------------------------------------------
const abuseKeys = process.env.ABUSEIPDB_KEYS
  ? process.env.ABUSEIPDB_KEYS.split(",").map(k => k.trim())
  : process.env.ABUSEIPDB_KEY
    ? [process.env.ABUSEIPDB_KEY]
    : [];

if (abuseKeys.length === 0) {
  console.warn("⚠️ No AbuseIPDB keys found — intel lookups disabled.");
}

let keyIndex = 0;
function getNextKey() {
  if (abuseKeys.length === 0) return null;
  const key = abuseKeys[keyIndex];
  keyIndex = (keyIndex + 1) % abuseKeys.length;
  return key;
}

// ------------------------------------------------------------
// 🛑 GLOBAL DAILY RATE LIMIT SAFETY
// AbuseIPDB daily limit = 1000 calls per key
// We enforce a safer internal cap = 850 calls per key
// ------------------------------------------------------------
const DAILY_LIMIT = 850;

let callsToday = 0;
let lastReset = new Date().toISOString().split("T")[0];

function resetCounterIfNeeded() {
  const today = new Date().toISOString().split("T")[0];
  if (today !== lastReset) {
    callsToday = 0;
    lastReset = today;
  }
}

// ------------------------------------------------------------
// ⭐ MAIN FUNCTION
// ------------------------------------------------------------
async function fetchThreatIntel(ip) {
  resetCounterIfNeeded();

  if (callsToday >= DAILY_LIMIT) {
    console.log("⛔ AbuseIPDB limit reached — returning cached intel only");
  }

  // ------------------------------------------------------------
  // 1️⃣ CHECK TTL CACHE BEFORE API CALL
  // TTL is handled in ThreatIntelCacheModel (12h auto-expire)
  // ------------------------------------------------------------
  const cached = await ThreatIntelCache.findOne({ ip });

  if (cached) {
    return {
      abuseConfidenceScore: cached.abuseConfidenceScore || null,
      isTor: cached.isTor || null,
      totalReports: cached.totalReports || null,
      lastReportedAt: cached.lastReportedAt || null
    };
  }

  // If no keys OR rate limit reached → return nothing
  if (abuseKeys.length === 0 || callsToday >= DAILY_LIMIT) {
    return null;
  }

  // ------------------------------------------------------------
  // 2️⃣ SELECT NEXT API KEY (rotating)
  // ------------------------------------------------------------
  const KEY = getNextKey();
  if (!KEY) return null;

  try {
    const resp = await axios.get("https://api.abuseipdb.com/api/v2/check", {
      params: { ipAddress: ip, maxAgeInDays: 90 },
      headers: {
        Key: KEY,
        Accept: "application/json",
      },
      timeout: 8000,
    });

    callsToday++;

    const data = resp.data.data;
    if (!data) return null;

    const threat_score = typeof data.abuseConfidenceScore === "number"
      ? data.abuseConfidenceScore
      : null;

    let threat_name = null;
    if (Array.isArray(data.categories) && data.categories.length > 0) {
      threat_name = data.categories.join(", ");
    } else if (data.usageType) {
      threat_name = data.usageType;
    }

    // ------------------------------------------------------------
    // 3️⃣ SAVE INTO THREAT INTEL CACHE
    // TTL auto-expire is applied at DB level
    // ------------------------------------------------------------
    await ThreatIntelCache.updateOne(
      { ip },
      {
        $set: {
          abuseConfidenceScore: threat_score,
          isTor: false, // AbuseIPDB doesn't return this, so false/null
          totalReports: data.totalReports ?? null,
          lastReportedAt: data.lastReportedAt ?? null,
          createdAt: new Date()
        }
      },
      { upsert: true }
    );

    return {
      abuseConfidenceScore: threat_score,
      isTor: false,
      totalReports: data.totalReports ?? null,
      lastReportedAt: data.lastReportedAt ?? null
    };

  } catch (err) {
    console.error(`[AbuseIPDB] Error checking ${ip}:`, err.message);
    return null;
  }
}

module.exports = fetchThreatIntel;