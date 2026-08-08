const { MongoClient } = require("mongodb");
require("dotenv").config();

const fetchGeoInfo = require("./fetchGeoInfo"); // Ensure this uses only the IPinfo API

const dbUri = process.env.MONGO_URI;
const dbName = "IntegriSecure";

// Enrichment Logic (Temporarily Disabled)
const enrichGeoInfo = async () => {
  console.log("Enrichment is currently disabled. Only bulk CSV data will be used for now.");

  // You can replace the logic below with CSV enrichment when needed
  // Placeholder for future re-enablement of enrichment
  return;

  /*
  const client = new MongoClient(dbUri, { useNewUrlParser: true, useUnifiedTopology: true });
  try {
    await client.connect();
    console.log("Connected to MongoDB.");

    const db = client.db(dbName);

    // Fetch records that need enrichment
    const unenrichedIPs = await db.collection("DShieldLogs").find({
      $or: [
        { "geo_info.enriched": { $exists: false } },
        { "geo_info.enriched": false },
        { "geo_info.country": null },
        { "geo_info.country": "Unknown" },
      ],
    }).limit(500).toArray();

    console.log(`Processing ${unenrichedIPs.length} entries...`);

    for (const record of unenrichedIPs) {
      const ip = record.source_ip;

      try {
        // Fetch geo-info using IPinfo API
        const enrichedGeoInfo = await fetchGeoInfo(ip);

        if (enrichedGeoInfo) {
          await db.collection("DShieldLogs").updateOne(
            { _id: record._id },
            {
              $set: { geo_info: { ...enrichedGeoInfo, enriched: true } },
              $setOnInsert: { updatedAt: new Date() },
            }
          );
          console.log(`Geo-info updated for IP: ${ip}`);
        } else {
          console.log(`No geo-info found for IP: ${ip}`);
        }
      } catch (error) {
        console.error(`Error enriching geo-info for IP ${ip}:`, error.message);
      }
    }

    console.log("Geo-info enrichment completed.");
  } catch (err) {
    console.error("Error during enrichment:", err);
  } finally {
    await client.close();
  }
  */
};

module.exports = enrichGeoInfo;
