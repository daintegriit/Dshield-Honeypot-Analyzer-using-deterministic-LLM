require("dotenv").config();
const mongoose = require("mongoose");
const Attack = require("./models/AttackModel");
const GeoCache = require("./models/GeolocationCacheModel");
const ThreatIntelCache = require("./models/ThreatIntelCacheModel");

(async () => {
  await mongoose.connect(process.env.MONGO_URI, { socketTimeoutMS: 0 });

  const geoCached = await GeoCache.estimatedDocumentCount();
  const threatCached = await ThreatIntelCache.estimatedDocumentCount();
  console.log("GeoCache entries:", geoCached);
  console.log("ThreatIntelCache entries:", threatCached);

  // How many UNIQUE source_ips are in the pending backlog? (this may take a while)
  console.log("\nCounting distinct pending IPs (may take a minute)...");
  const distinctPending = await Attack.distinct("source_ip", { needs_enrichment: true });
  console.log("Unique pending IPs:", distinctPending.length);

  // How many of those are ALREADY cached? -> free enrichment
  const cachedHits = await GeoCache.countDocuments({ ip: { $in: distinctPending.slice(0, 100000) } });
  console.log("Of those, already in GeoCache:", cachedHits);

  await mongoose.disconnect();
  process.exit(0);
})();
