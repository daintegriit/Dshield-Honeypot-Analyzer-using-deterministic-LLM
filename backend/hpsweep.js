require('dotenv').config();
const m = require('mongoose');
const { buildCopilotCore } = require('./services/copilotCore');
(async () => {
  await m.connect(process.env.MONGO_URI);
  const end = new Date('2025-12-10T00:00:00Z').getTime();
  for (let i = 0; i < 24; i++) {
    const we = new Date(end + i * 3600 * 1000).toISOString();
    const c = await buildCopilotCore({ minutes: 5, sourceFilter: null, windowEnd: we });
    console.log(we, 'risk=', c.riskScore0to100, c.state, 'dom=', c.attackClassification?.dominantAttack?.type);
  }
  await m.disconnect();
})();
