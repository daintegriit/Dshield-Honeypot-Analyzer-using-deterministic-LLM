require('dotenv').config();
const m = require('mongoose');
const { buildCopilotCore } = require('./services/copilotCore');
(async () => {
  await m.connect(process.env.MONGO_URI);
  const core = await buildCopilotCore({
    windowMinutes: 5,
    windowEnd: '2026-07-15T09:00:00Z',
    sourceFilter: 'replay',
  });
  console.log('riskScore0to100:', core.riskScore0to100);
  console.log('state           :', core.state);
  console.log('riskBudget      :', core.riskBudget);
  await m.disconnect();
})();
