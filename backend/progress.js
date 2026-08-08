require("dotenv").config();
const mongoose = require("mongoose");
const Attack = require("./models/AttackModel");
(async () => {
  await mongoose.connect(process.env.MONGO_URI, { socketTimeoutMS: 0 });
  const remaining = await Attack.countDocuments({ needs_enrichment: true, source: { $exists: false } });
  const done = await Attack.countDocuments({ enrichment_skipped: "legacy_pre_tagging" });
  console.log(`remaining: ${remaining.toLocaleString()}  |  marked: ${done.toLocaleString()}`);
  await mongoose.disconnect(); process.exit(0);
})();
