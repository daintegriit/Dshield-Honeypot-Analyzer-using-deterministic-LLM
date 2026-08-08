require("dotenv").config();
const mongoose = require("mongoose");
const Attack = require("./models/AttackModel");
(async () => {
  await mongoose.connect(process.env.MONGO_URI);
  const pending = await Attack.countDocuments({ needs_enrichment: true });
  const pendingReplay = await Attack.countDocuments({ needs_enrichment: true, source: "replay" });
  const pendingNoSource = await Attack.countDocuments({ needs_enrichment: true, source: { $exists: false } });
  const total = await Attack.countDocuments({});
  console.log(JSON.stringify({ total, pending, pendingReplay, pendingNoSource }, null, 2));
  await mongoose.disconnect(); process.exit(0);
})();
