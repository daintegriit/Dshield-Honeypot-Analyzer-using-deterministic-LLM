require('dotenv').config();
const m = require('mongoose');
const { buildCopilotCore } = require('./services/copilotCore');
(async () => {
  await m.connect(process.env.MONGO_URI);
  const days = ['2025-12-08','2025-12-09','2025-12-10','2025-12-11','2025-12-12'];
  const rows = [];
  for (const d of days) {
    for (let h = 0; h < 24; h += 2) {
      const we = new Date(`${d}T${String(h).padStart(2,'0')}:00:00Z`).toISOString();
      const c = await buildCopilotCore({ minutes: 5, sourceFilter: null, windowEnd: we });
      rows.push({
        t: we,
        risk: c.riskScore0to100,
        state: c.state,
        dom: c.attackClassification?.dominantAttack?.type,
        entropy: c.riskComponents?.entropyComponent,
        amp: c.riskComponents?.signalAmplifier,
        c2: c.riskComponents?.c2Bonus,
        sev: c.riskComponents?.severityComponent,
      });
      console.log(rows[rows.length-1]);
    }
  }
  require('fs').writeFileSync(process.env.HOME + '/research/honeypot_sweep.json', JSON.stringify(rows, null, 2));
  await m.disconnect();
})();
