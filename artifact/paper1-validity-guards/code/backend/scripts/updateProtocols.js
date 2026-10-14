const { MongoClient } = require("mongodb");
require("dotenv").config();

const dbUri = process.env.MONGO_URI; // MongoDB connection string
const dbName = "DSHIELDHoneypotDataDB";
const dShieldLogsCollection = "DShieldLogs";
const protocolsCollection = "protocols";

const updateProtocols = async () => {
  const client = new MongoClient(dbUri);

  try {
    await client.connect();
    console.log("Connected to MongoDB.");

    const db = client.db(dbName);
    const logs = db.collection(dShieldLogsCollection);
    const protocols = db.collection(protocolsCollection);

    console.log("Aggregating protocols...");

    // Aggregate protocols and count attacks
    const pipeline = [
      {
        $match: {
          protocol: { $exists: true },
        },
      },
      {
        $group: {
          _id: "$protocol", // Group by protocol field
          attackCount: { $sum: 1 }, // Count number of attacks for each protocol
          lastSeen: { $max: "$timestamp" }, // Get latest timestamp for each protocol
        },
      },
      {
        $project: {
          _id: 0,
          protocol: "$_id",
          attackCount: 1,
          lastSeen: 1,
          lastUpdated: { $toDate: new Date() }, // Add a 'lastUpdated' timestamp
        },
      },
    ];

    const aggregatedProtocols = await logs.aggregate(pipeline).toArray();

    console.log("Updating protocols collection...");
    for (const proto of aggregatedProtocols) {
      await protocols.updateOne(
        { protocol: proto.protocol }, // Match the existing protocol
        { $set: proto }, // Update with the new data
        { upsert: true } // Insert if not already present
      );
    }

    console.log(
      `Protocols collection updated successfully. Processed ${aggregatedProtocols.length} protocols.`
    );
  } catch (err) {
    console.error("Error updating protocols collection:", err.message);
  } finally {
    await client.close();
    console.log("Connection closed.");
  }
};

updateProtocols();
