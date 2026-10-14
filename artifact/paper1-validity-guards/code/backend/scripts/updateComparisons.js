const { MongoClient } = require("mongodb");
require("dotenv").config();

const dbUri = process.env.MONGO_URI;
const dbName = "DSHIELDHoneypotDataDB";

const updateComparisons = async () => {
  const client = new MongoClient(dbUri);

  try {
    await client.connect();
    console.log("Connected to MongoDB.");

    const db = client.db(dbName);
    const logsCollection = db.collection("DShieldLogs");
    const comparisonsCollection = db.collection("comparisons");

    // 1. Aggregate total attack count by region
    const regionAggregation = await logsCollection
      .aggregate([
        { $group: { _id: "$geo_info.region", totalAttacks: { $sum: 1 } } },
      ])
      .toArray();

    for (const region of regionAggregation) {
      await comparisonsCollection.updateOne(
        { region: region._id || "Unknown" },
        {
          $set: {
            region: region._id || "Unknown",
            attackCount: region.totalAttacks,
            lastUpdated: new Date(),
          },
        },
        { upsert: true }
      );
    }

    console.log(`Updated regional attack summaries.`);

    // 2. Compare protocols
    const protocolAggregation = await logsCollection
      .aggregate([
        { $group: { _id: "$protocol", protocolCount: { $sum: 1 } } },
      ])
      .toArray();

    for (const protocol of protocolAggregation) {
      await comparisonsCollection.updateOne(
        { comparisonField: "protocol", fieldValue: protocol._id },
        {
          $set: {
            comparisonField: "protocol",
            fieldValue: protocol._id,
            comparisonCount: protocol.protocolCount,
            lastUpdated: new Date(),
          },
        },
        { upsert: true }
      );
    }

    console.log(`Updated protocol summaries.`);

    // 3. Compare top ports
    const portAggregation = await logsCollection
      .aggregate([
        { $group: { _id: "$destinationPort", portCount: { $sum: 1 } } },
      ])
      .toArray();

    for (const port of portAggregation) {
      await comparisonsCollection.updateOne(
        { comparisonField: "destinationPort", fieldValue: port._id },
        {
          $set: {
            comparisonField: "destinationPort",
            fieldValue: port._id,
            comparisonCount: port.portCount,
            lastUpdated: new Date(),
          },
        },
        { upsert: true }
      );
    }

    console.log(`Updated port summaries.`);

    // 4. Compare severities
    const severityAggregation = await logsCollection
      .aggregate([
        { $group: { _id: "$severity", severityCount: { $sum: 1 } } },
      ])
      .toArray();

    for (const severity of severityAggregation) {
      await comparisonsCollection.updateOne(
        { comparisonField: "severity", fieldValue: severity._id },
        {
          $set: {
            comparisonField: "severity",
            fieldValue: severity._id,
            comparisonCount: severity.severityCount,
            lastUpdated: new Date(),
          },
        },
        { upsert: true }
      );
    }

    console.log(`Updated severity summaries.`);

  } catch (err) {
    console.error("Error updating comparisons collection:", err.message);
  } finally {
    await client.close();
    console.log("Connection closed.");
  }
};

updateComparisons();
