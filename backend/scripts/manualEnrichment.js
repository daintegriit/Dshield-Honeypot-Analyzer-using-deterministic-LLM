const { MongoClient } = require("mongodb");
const fs = require("fs");
const csvParser = require("csv-parser");
const path = require("path");
require("dotenv").config();

const dbUri = process.env.MONGO_URI;
const dbName = "DSHIELDHoneypotDataDB";
const csvFilePath = path.join(__dirname, "../csv", "country_asn.csv");
console.log("CSV File Path:", csvFilePath); // Optional for debugging

const enrichLogs = async () => {
  const client = new MongoClient(dbUri);

  try {
    await client.connect();
    console.log("Connected to MongoDB.");
    const db = client.db(dbName);
    const logsCollection = db.collection("DShieldLogs");

    // Load CSV Data into Memory
    const csvData = [];
    console.log("Loading CSV...");
    await new Promise((resolve, reject) => {
      fs.createReadStream(csvFilePath)
        .pipe(csvParser())
        .on("data", (row) => csvData.push(row))
        .on("end", resolve)
        .on("error", reject);
    });

    console.log(`Loaded ${csvData.length} rows from CSV.`);

    // Find Logs Missing geo_info.country
    const logsToEnrich = await logsCollection
      .find({ "geo_info.country": { $exists: false } })
      .toArray();

    console.log(`Found ${logsToEnrich.length} logs to enrich.`);

    let updatedCount = 0;

    for (const log of logsToEnrich) {
      const ip = log.source_ip;

      // Match IP Range in CSV Data
      const match = csvData.find((row) => ip >= row.start_ip && ip <= row.end_ip);

      if (match) {
        await logsCollection.updateOne(
          { _id: log._id },
          {
            $set: {
              geo_info: {
                country: match.country,
                latitude: parseFloat(match.latitude),
                longitude: parseFloat(match.longitude),
              },
            },
          }
        );
        updatedCount++;
      }
    }

    console.log(`Enrichment complete. Total logs updated: ${updatedCount}`);
  } catch (err) {
    console.error("Error during enrichment:", err.message);
  } finally {
    await client.close();
    console.log("Connection closed.");
  }
};

enrichLogs();
