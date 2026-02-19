const { MongoClient } = require("mongodb");
require("dotenv").config();

const dbUri = process.env.MONGO_URI;
const dbName = "DSHIELDHoneypotDataDB";
const collectionLogs = "DShieldLogs";
const collectionTopIPs = "topIPs";

const updateTopIPs = async () => {
  const client = new MongoClient(dbUri);

  try {
    await client.connect();
    console.log("Connected to MongoDB.");

    const db = client.db(dbName);
    const logsCollection = db.collection(collectionLogs);
    const topIPsCollection = db.collection(collectionTopIPs);

    console.log("Aggregating attack counts by IP...");

    // Aggregate attack counts and latest seen timestamp for each IP
    const aggregatedData = await logsCollection
      .aggregate([
        {
          $group: {
            _id: "$source_ip",
            attackCount: { $sum: 1 },
            lastSeen: { $max: "$timestamp" },
          },
        },
        { $sort: { attackCount: -1 } }, // Sort by attack count in descending order
        { $limit: 1000 }, // Keep top 1000 IPs
      ])
      .toArray();

    console.log(`Found ${aggregatedData.length} IPs to update.`);

    // Update the topIPs collection
    for (const ipData of aggregatedData) {
      await topIPsCollection.updateOne(
        { ipAddress: ipData._id }, // Match IP
        {
          $set: {
            ipAddress: ipData._id,
            attackCount: ipData.attackCount,
            lastSeen: ipData.lastSeen,
          },
        },
        { upsert: true }
      );
    }

    console.log("Top IPs collection updated successfully.");
  } catch (error) {
    console.error("Error updating top IPs:", error.message);
  } finally {
    await client.close();
    console.log("Connection closed.");
  }
};

updateTopIPs();
