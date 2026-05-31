// utils/fetchGeoInfo.js
const axios = require("axios");
const GeoCache = require("../models/GeolocationCacheModel");

// ----------------------------------
// Parse "AS15169 Google LLC"
// ----------------------------------
function parseAsn(asString) {
    if (!asString) return { asn: null, asn_org: null };

    const parts = asString.split(" ");
    return {
        asn: parts[0] || null,
        asn_org: parts.slice(1).join(" ") || null
    };
}

// ----------------------------------
// Provider mapping (same as worker)
// ----------------------------------
function detectProvider(asn_org) {
    if (!asn_org) return "Unknown";

    const t = asn_org.toLowerCase();
    if (t.includes("amazon") || t.includes("aws")) return "AWS";
    if (t.includes("google")) return "Google Cloud";
    if (t.includes("microsoft") || t.includes("azure")) return "Azure";
    if (t.includes("digitalocean")) return "DigitalOcean";
    if (t.includes("ovh")) return "OVH";
    if (t.includes("hetzner")) return "Hetzner";
    if (t.includes("linode")) return "Linode";

    return "Unknown";
}

// ----------------------------------
// MAIN GEO LOOKUP
// ----------------------------------
async function fetchGeoInfo(ip) {
    if (!ip) return null;

    // Try cache first (same as enrichment worker)
    const cached = await GeoCache.findOne({ ip });
    if (cached) {
        return {
            country: cached.country,
            region: cached.region,
            city: cached.city,
            latitude: cached.latitude,
            longitude: cached.longitude,
            asn: cached.asn,
            asn_org: cached.asn_org,
            provider: cached.provider,
        };
    }

    // Fetch from ip-api.com (same as worker)
    try {
        const resp = await axios.get(
            `http://ip-api.com/json/${ip}?fields=status,country,regionName,city,lat,lon,as,query`
        );

        const d = resp.data;
        if (d.status !== "success") return null;

        const { asn, asn_org } = parseAsn(d.as);
        const provider = detectProvider(asn_org);

        const payload = {
            ip,
            country: d.country || null,
            region: d.regionName || null,
            city: d.city || null,
            latitude: typeof d.lat === "number" ? d.lat : null,
            longitude: typeof d.lon === "number" ? d.lon : null,
            asn,
            asn_org,
            provider,
            createdAt: new Date()
        };

        // Save into cache
        await GeoCache.create(payload);

        return payload;
    } catch (err) {
        console.error("Geo lookup failed:", err.message);
        return null;
    }
}

module.exports = fetchGeoInfo;