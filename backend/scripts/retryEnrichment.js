const { MongoClient } = require("mongodb");
const fs = require("fs");
const path = require("path");
const csvParser = require("csv-parser");
require("dotenv").config();

const dbUri = process.env.MONGO_URI;
const dbName = "IntegriSecure";
const csvFilePath = path.join(__dirname, "..", "csv", "country_asn.csv");

const retryFailedEnrichment = async () => {
  const client = new MongoClient(dbUri, { maxPoolSize: 10 });

  try {
    await client.connect();
    console.log("Connected to MongoDB.");
    const db = client.db(dbName);
    const logsCollection = db.collection("DShieldLogs");

    const failedRecords = await logsCollection
      .find({
        $or: [
          { "geo_info.enriched": { $exists: false } },
          { "geo_info.enriched": false },
        ],
      })
      .limit(500)
      .toArray();

    console.log(`Retrying enrichment for ${failedRecords.length} records...`);

    const csvData = [];
    await new Promise((resolve, reject) => {
      fs.createReadStream(csvFilePath)
        .pipe(csvParser())
        .on("data", (row) => csvData.push(row))
        .on("end", resolve)
        .on("error", reject);
    });

    for (const record of failedRecords) {
      const ip = record.source_ip;
      const match = csvData.find((row) => ip >= row.start_ip && ip <= row.end_ip);

      if (match) {
        await db.collection("countries").updateOne(
          { country: match.country || "Unknown" },
          {
            $inc: { attackCount: 1 },
            $setOnInsert: { geo: { latitude: match.latitude, longitude: match.longitude, lastSeen: new Date() } }
          },
          { upsert: true }
        );

        await logsCollection.updateOne(
          { _id: record._id },
          { $set: { geo_info: { ...match, enriched: true } } }
        );
        console.log(`Successfully enriched IP: ${ip}`);
      } else {
        console.log(`No match for IP: ${ip}`);
      }
    }
  } catch (err) {
    console.error("Error during retry enrichment:", err.message);
  } finally {
    await client.close();
    console.log("Connection closed.");
  }
};

retryFailedEnrichment();
