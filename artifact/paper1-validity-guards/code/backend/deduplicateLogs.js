const { MongoClient } = require("mongodb");
require("dotenv").config();

const dbUri = process.env.MONGO_URI;
const dbName = "IntegriSecure";

const deduplicateLogs = async () => {
  const client = new MongoClient(dbUri);
  await client.connect();
  const db = client.db(dbName);

  const duplicates = await db
    .collection("DShieldLogs")
    .aggregate([
      { $group: { _id: "$source_ip", count: { $sum: 1 }, ids: { $push: "$_id" } } },
      { $match: { count: { $gt: 1 } } },
    ])
    .toArray();

  for (const dup of duplicates) {
    const [keepId, ...deleteIds] = dup.ids;
    await db.collection("DShieldLogs").deleteMany({ _id: { $in: deleteIds } });
    console.log(`Deduplicated IP: ${dup._id}`);
  }

  console.log("Deduplication completed.");
  await client.close();
};

deduplicateLogs();
