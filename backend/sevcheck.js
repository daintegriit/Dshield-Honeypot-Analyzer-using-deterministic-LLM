require('dotenv').config();
const m = require('mongoose');
(async () => {
  await m.connect(process.env.MONGO_URI);
  const c = m.connection.collection('attacks');
  console.log('with ctu_class:', await c.countDocuments({ ctu_class: { $exists: true } }));
  console.log(await c.aggregate([
    { $match: { ctu_class: { $exists: true } } },
    { $group: { _id: '$severity', n: { $sum: 1 } } }
  ]).toArray());
  await m.disconnect();
})();
