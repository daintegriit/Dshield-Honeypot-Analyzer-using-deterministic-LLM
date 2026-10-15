// export_flows.js -- dump every replayed CTU-13 document for the given scenarios,
// with both clocks, so third-party detectors see exactly the flows Chiron scored.
// Run from a backend copy that has .env and node_modules (the poscontrol copy).
// Usage: node export_flows.js <outdir> 1 2 6 8 9
require("dotenv").config();
const fs = require("fs");
const path = require("path");
const mongoose = require("mongoose");
const Attack = require("./models/AttackModel");
(async () => {
  const [outdir, ...scen] = process.argv.slice(2);
  fs.mkdirSync(outdir, { recursive: true });
  await mongoose.connect(process.env.MONGO_URI);
  for (const s of scen) {
    const p = `ctu13-s${s}`;
    const f = fs.createWriteStream(path.join(outdir, `mongo_s${s}.jsonl`));
    let n = 0;
    const cur = Attack.find({ replay_pcap: p })
      .select({ raw: 1, timestamp: 1, event_time: 1, ctu_class: 1, ctu_subclass: 1, ctu_label: 1 })
      .sort({ timestamp: 1, _id: 1 }).lean().cursor();
    for await (const d of cur) {
      f.write(JSON.stringify({ raw: d.raw, timestamp: d.timestamp, event_time: d.event_time,
        ctu_class: d.ctu_class, ctu_subclass: d.ctu_subclass, ctu_label: d.ctu_label }) + "\n");
      n++;
    }
    await new Promise((r) => f.end(r));
    console.log(`${p} exported ${n}`);
  }
  await mongoose.disconnect();
})();
