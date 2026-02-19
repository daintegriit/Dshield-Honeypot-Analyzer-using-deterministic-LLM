// analysis/debug/inspect_timestamp_fields.js
require("dotenv").config();
const mongoose = require("mongoose");
const Attack = require("../../models/AttackModel");

(async () => {
  await mongoose.connect(process.env.MONGO_URI);

  const sample = await Attack.findOne().lean();

  console.log("🧪 Sample keys:", Object.keys(sample));
  console.log("🧪 timestamp:", sample.timestamp);
  console.log("🧪 createdAt:", sample.createdAt);

  process.exit(0);
})();