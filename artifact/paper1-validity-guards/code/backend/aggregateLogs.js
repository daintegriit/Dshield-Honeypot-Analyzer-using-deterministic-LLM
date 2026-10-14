const { MongoClient } = require("mongodb");
require("dotenv").config();

const dbUri = process.env.MONGO_URI;
const dbName = "IntegriSecure";
const collectionName = "DShieldLogs";

const aggregateLogs = async (logEntry) => {
  try {
    const client = new MongoClient(dbUri, { useNewUrlParser: true, useUnifiedTopology: true });
    await client.connect();
    console.log("Connected to MongoDB.");
    const db = client.db(dbName);

    const { source_ip, geo_info, attack_type, timestamp } = logEntry;

    // Find existing record for the IP
    const existingRecord = await db.collection(collectionName).findOne({ source_ip });

    if (existingRecord) {
      // Update the existing record
      const updateResult = await db.collection(collectionName).updateOne(
        { source_ip },
        {
          $set: { geo_info }, // Ensure geo_info is up-to-date
          $addToSet: { attack_types: attack_type, timestamps: timestamp }, // Avoid duplicates in arrays
        }
      );
      console.log(`Updated record for IP ${source_ip}:`, updateResult);
    } else {
      // Insert a new record if no existing record is found
      const newRecord = {
        source_ip,
        geo_info,
        attack_types: [attack_type],
        timestamps: [timestamp],
        created_at: new Date(),
      };
      const insertResult = await db.collection(collectionName).insertOne(newRecord);
      console.log(`Inserted new record for IP ${source_ip}:`, insertResult);
    }

    await client.close();
  } catch (error) {
    console.error("Error during aggregation:", error);
  }
};

// Example usage with a new log entry
aggregateLogs({
  source_ip: "103.102.230.5",
  geo_info: {
    country: "CA",
    region: null,
    city: null,
    latitude: null,
    longitude: null,
    as_name: "Skoali SAS",
    asn: "AS216167",
    country_name: "Canada",
    enriched: true,
  },
  attack_type: "TCP",
  timestamp: new Date().toISOString(),
});
