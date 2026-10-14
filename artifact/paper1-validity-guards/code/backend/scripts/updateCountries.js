const { MongoClient } = require("mongodb");
require("dotenv").config();

const dbUri = process.env.MONGO_URI;
const dbName = "DSHIELDHoneypotDataDB";

const updateCountries = async () => {
  const client = new MongoClient(dbUri);

  try {
    await client.connect();
    console.log("Connected to MongoDB.");
    const db = client.db(dbName);
    const logsCollection = db.collection("DShieldLogs");
    const countriesCollection = db.collection("countries");

    console.log("Aggregating attack counts by country...");

    // Aggregate attack counts by country
    const pipeline = [
      { 
        $match: { "geo_info.country": { $exists: true } }
      },
      { 
        $group: {
          _id: "$geo_info.country",
          attackCount: { $sum: 1 },
          lastSeen: { $max: "$timestamp" }, // Get the latest timestamp
          latitude: { $first: "$geo_info.latitude" },
          longitude: { $first: "$geo_info.longitude" }
        }
      }
    ];

    const aggregationResults = await logsCollection.aggregate(pipeline).toArray();

    console.log(`Updating ${aggregationResults.length} country records...`);

    for (const result of aggregationResults) {
      const country = result._id;

      await countriesCollection.updateOne(
        { country: country },
        {
          $set: {
            attackCount: result.attackCount,
            "geo.latitude": result.latitude,
            "geo.longitude": result.longitude,
            lastSeen: result.lastSeen,
          }
        },
        { upsert: true } // Insert if the country does not exist
      );

      console.log(`Updated country: ${country}, Attacks: ${result.attackCount}`);
    }

    console.log("Countries collection updated successfully.");
  } catch (err) {
    console.error("Error updating countries collection:", err.message);
  } finally {
    await client.close();
    console.log("Connection closed.");
  }
};

updateCountries();
