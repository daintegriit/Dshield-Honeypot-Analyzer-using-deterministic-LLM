require('dotenv').config();
const m = require('mongoose');
(async () => {
  await m.connect(process.env.MONGO_URI);
  const c = m.connection.collection('attacks');
  const seen = new Map();
  // timestamp is indexed; replay ingests all ran mid-July 2026
  const cur = c.find(
    { timestamp: { $gte: new Date('2026-07-01'), $lte: new Date('2026-08-01') } },
    { projection: { replay_pcap: 1, _id: 0 }, maxTimeMS: 60000 }
  );
  let n = 0;
  for await (const d of cur) {
    n++;
    const k = d.replay_pcap || '(none)';
    seen.set(k, (seen.get(k) || 0) + 1);
  }
  console.log('docs scanned in July window:', n);
  console.log([...seen.entries()].sort((a, b) => b[1] - a[1]));
  await m.disconnect();
})();
