require("dotenv").config();
const mongoose = require("mongoose");
const Attack = require("./models/AttackModel");

(async () => {
  await mongoose.connect(process.env.MONGO_URI, {
    serverSelectionTimeoutMS: 60000,
    socketTimeoutMS: 0,
  });

  console.log("Marking legacy (untagged) docs as enrichment-complete...");
  console.log("This touches ~11.6M docs — expect several minutes. Do not interrupt.");
  const t0 = Date.now();

  const res = await Attack.updateMany(
    { needs_enrichment: true, source: { $exists: false } },
    { $set: { needs_enrichment: false, enrichment_skipped: "legacy_pre_tagging" } }
  );

  console.log("Modified:", res.modifiedCount, `(${((Date.now()-t0)/1000).toFixed(1)}s)`);

  const stillPending = await Attack.countDocuments({ needs_enrichment: true });
  console.log("Still pending after cleanup:", stillPending);

  await mongoose.disconnect();
  process.exit(0);
})();
