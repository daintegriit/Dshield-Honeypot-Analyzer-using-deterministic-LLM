require("dotenv").config();
const mongoose = require("mongoose");
const { buildCopilotCore } = require("./services/copilotCore");
(async () => {
  await mongoose.connect(process.env.MONGO_URI, { socketTimeoutMS: 0 });
  const all = await buildCopilotCore({ minutes: 60 });
  const replay = await buildCopilotCore({ minutes: 60, sourceFilter: "replay" });
  const honeypot = await buildCopilotCore({ minutes: 60, sourceFilter: "honeypot" });
  console.log(JSON.stringify({
    coreVersion: all.coreVersion,
    all:      { scope: all.sourceFilter,      events: all.attackMetrics.attacksLastHour },
    replay:   { scope: replay.sourceFilter,   events: replay.attackMetrics.attacksLastHour },
    honeypot: { scope: honeypot.sourceFilter, events: honeypot.attackMetrics.attacksLastHour }
  }, null, 2));
  await mongoose.disconnect(); process.exit(0);
})();
