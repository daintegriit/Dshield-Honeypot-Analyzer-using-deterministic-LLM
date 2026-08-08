require('dotenv').config();
const m = require('mongoose');
(async () => {
  await m.connect(process.env.MONGO_URI);
  const db = m.connection.db;
  const c = db.collection('attacks');

  const st = await db.command({ collStats: 'attacks' });
  console.log('docs        :', st.count.toLocaleString());
  console.log('dataSize    :', (st.size / 1e9).toFixed(2), 'GB');
  console.log('storageSize :', (st.storageSize / 1e9).toFixed(2), 'GB');
  console.log('indexSize   :', (st.totalIndexSize / 1e9).toFixed(2), 'GB');
  console.log('avgObjSize  :', st.avgObjSize, 'bytes');
  console.log('');

  // what the analyzer's first query actually does
  const exp = await c.find({ replay_pcap: 'ctu13-s8' })
    .sort({ timestamp: 1 }).limit(1)
    .explain('queryPlanner');
  const w = exp.queryPlanner.winningPlan;
  console.log('winning plan:', JSON.stringify(w).slice(0, 400));
  await m.disconnect();
})();
