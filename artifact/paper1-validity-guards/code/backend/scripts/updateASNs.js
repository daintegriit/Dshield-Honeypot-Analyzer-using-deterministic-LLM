const { MongoClient } = require("mongodb");
const axios = require("axios");
require("dotenv").config();

const dbUri = process.env.MONGO_URI;
const dbName = "DSHIELDHoneypotDataDB";
const collectionName = "DShieldLogs";
const ipInfoToken = process.env.IPInfo_Token;

const updateASNs = async () => {
  const client = new MongoClient(dbUri);
  let updatedCount = 0;
  let failedIPs = [];

  try {
    await client.connect();
    console.log("Connected to MongoDB.");

    const db = client.db(dbName);
    const logsCollection = db.collection(collectionName);

    // Find logs missing ASN info and deduplicate by source_ip
    console.log("Checking for logs missing ASN...");
    const logsToUpdate = await logsCollection
      .aggregate([
        { $match: { asn: { $exists: false } } },
        { $group: { _id: "$source_ip", doc: { $first: "$$ROOT" } } },
        { $replaceRoot: { newRoot: "$doc" } }
      ])
      .toArray();

    console.log(`Found ${logsToUpdate.length} unique logs missing ASN info.`);

    for (const log of logsToUpdate) {
      const ip = log.source_ip;

      try {
        // Call IPInfo API
        const response = await axios.get(`https://ipinfo.io/${ip}/json?token=${ipInfoToken}`);
        const asn = response.data.org ? response.data.org.split(" ")[0] : null; // Extract ASN code

        if (asn) {
          await logsCollection.updateOne(
            { _id: log._id },
            { $set: { asn: asn } }
          );
          updatedCount++;
        } else {
          // Mark as unknown if ASN is not found
          await logsCollection.updateOne(
            { _id: log._id },
            { $set: { asn: "Unknown" } }
          );
          failedIPs.push(ip);
        }
      } catch (apiErr) {
        console.log(`Failed to fetch ASN for IP: ${ip}`);
        failedIPs.push(ip);
      }
    }

    // Output Summary
    console.log("\nASN Update Summary:");
    console.log(`- Successfully updated ${updatedCount} logs.`);
    console.log(`- Failed to find ASN for ${failedIPs.length} IPs.`);

    if (failedIPs.length > 0) {
      console.log("\nIPs with missing ASN info:");
      console.log([...new Set(failedIPs)].join("\n"));
    }
  } catch (err) {
    console.error("Error updating ASNs:", err.message);
  } finally {
    await client.close();
    console.log("Connection closed.");
  }
};

updateASNs();
