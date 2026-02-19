const { MongoClient } = require("mongodb");
require("dotenv").config();

const dbUri = process.env.MONGO_URI;
const dbName = "DSHIELDHoneypotDataDB";

const updateSeverity = async () => {
  const client = new MongoClient(dbUri);
  try {
    await client.connect();
    const db = client.db(dbName);
    const logsCollection = db.collection("DShieldLogs");
    const severityCollection = db.collection("severity");

    const severityAggregation = await logsCollection
      .aggregate([
        {
          $set: {
            severity: {
              $switch: {
                branches: [
                  { case: { $in: ["$port", [22, 80]] }, then: "High" },
                  { case: { $lt: ["$attack_attempts", 5] }, then: "Low" },
                ],
                default: "Medium",
              },
            },
          },
        },
        { $group: { _id: "$severity", count: { $sum: 1 } } },
      ])
      .toArray();

    for (const severity of severityAggregation) {
      await severityCollection.updateOne(
        { severity: severity._id },
        { $set: { attackCount: severity.count } },
        { upsert: true }
      );
    }
    console.log("Severity levels updated successfully.");
  } finally {
    await client.close();
  }
};

updateSeverity();
