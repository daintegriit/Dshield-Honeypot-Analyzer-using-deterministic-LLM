const { MongoClient } = require("mongodb");
require("dotenv").config();

const dbUri = process.env.MONGO_URI;
const dbName = "IntegriSecure";  
const LOGS = "DShieldLogs";
const ATTACKS = "attacks";

const updateAttacks = async () => {
  const client = new MongoClient(dbUri);

  try {
    await client.connect();
    console.log("Connected to MongoDB.");
    const db = client.db(dbName);

    const logs = await db.collection(LOGS).find({
      source_ip: { $exists: true },
      timestamp: { $exists: true },
      dpt: { $exists: true }       
    }).toArray();

    console.log(`Found ${logs.length} logs.`);

    let inserted = 0;

    for (const log of logs) {

      const doc = {
        source_ip: log.source_ip,                       // backend expects this
        protocol: log.protocol || log.proto || "TCP",   // supports both formats
        timestamp: log.timestamp,
        attack_type: log.attack_type || "Unknown",      // backend uses attack_type
        port: log.dpt,                                   // backend needs "port"
        severity: log.dpt <= 1024 ? "High" : "Low",
        country: log.geo_info?.country || "Unknown",
        asn: log.geo_info?.asn || "Unknown",
      };

      // Prevent duplicates (IP + timestamp)
      const exists = await db.collection(ATTACKS).findOne({
        source_ip: doc.source_ip,
        timestamp: doc.timestamp,
      });

      if (!exists) {
        await db.collection(ATTACKS).insertOne(doc);
        inserted++;
      }
    }

    console.log(`Inserted ${inserted} new attack documents.`);
  } catch (err) {
    console.error("Error:", err.message);
  } finally {
    await client.close();
    console.log("Connection closed.");
  }
};

updateAttacks();