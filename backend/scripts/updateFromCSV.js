const { MongoClient } = require("mongodb");
const { Address4 } = require("ip-address");
const fs = require("fs");
const csvParser = require("csv-parser");
require("dotenv").config();

const dbUri = process.env.MONGO_URI;
const dbName = "IntegriSecure";
const csvFilePath = "./csv/country_asn.csv";

const updateFromCSV = async () => {
  const client = new MongoClient(dbUri);
  await client.connect();
  const db = client.db(dbName);

  const csvData = [];
  fs.createReadStream(csvFilePath)
    .pipe(csvParser())
    .on("data", (row) => csvData.push(row))
    .on("end", async () => {
      for (const row of csvData) {
        await db.collection("DShieldLogs").updateMany(
          { source_ip: { $gte: row.start_ip, $lte: row.end_ip } },
          { $set: { geo_info: { ...row, enriched: true } } }
        );
      }
      console.log("CSV updates completed.");
      await client.close();
    });
};

updateFromCSV();
