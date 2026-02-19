const { MongoClient } = require("mongodb");
require("dotenv").config();

const uri = process.env.MONGO_URI;
const dbName = "DSHIELDHoneypotDataDB";
const collectionName = "DShieldLogs";
const portsCollectionName = "ports";

const updatePortsCollection = async () => {
  const client = new MongoClient(uri);

  try {
    await client.connect();
    console.log("Connected to MongoDB.");

    const db = client.db(dbName);
    const logsCollection = db.collection(collectionName);
    const portsCollection = db.collection(portsCollectionName);

    console.log("Aggregating attack counts by port...");

    // Aggregate attack counts for each port
    const aggregationPipeline = [
      {
        $match: {
          destinationPort: { $exists: true, $ne: null }, // Ensure ports exist
        },
      },
      {
        $group: {
          _id: "$destinationPort", // Group by destination port
          attackCount: { $sum: 1 }, // Count occurrences
          lastSeen: { $max: "$timestamp" }, // Get the latest timestamp
        },
      },
      {
        $sort: { attackCount: -1 }, // Sort by attack count descending
      },
    ];

    const results = await logsCollection.aggregate(aggregationPipeline).toArray();

    // Update ports collection
    for (const portData of results) {
      await portsCollection.updateOne(
        { port: portData._id },
        {
          $set: {
            port: portData._id,
            attackCount: portData.attackCount,
            lastSeen: portData.lastSeen,
          },
        },
        { upsert: true } // Insert if it doesn't exist
      );
    }

    console.log(`Updated ${results.length} port records.`);
  } catch (error) {
    console.error("Error updating ports collection:", error.message);
  } finally {
    await client.close();
    console.log("Connection closed.");
  }
};

updatePortsCollection();
