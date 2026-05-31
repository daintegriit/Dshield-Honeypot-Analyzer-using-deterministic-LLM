const axios = require("axios");

// 🔥 CHANGE THIS IF NEEDED
const BASE_URL = "http://34.232.64.91:5002/api";

const routes = [
  "/charts/top-countries",
  "/charts/top-ips",
  "/charts/top-attack-types",
  "/charts/attack-trends",
  "/charts/protocol-breakdown",
  "/charts/severity-distribution",
  "/charts/port-scanning",
  "/charts/top-asns",
  "/charts/recent-logs",
  "/charts/threat-summary",
  "/charts/geolocation",

  "/attacks/top-countries",
  "/attacks/top-ips",
  "/attacks/top-attack-types",
  "/attacks/attack-trends",
  "/attacks/protocol-breakdown",
  "/attacks/severity-distribution",
  "/attacks/port-scanning",
  "/attacks/source-asn",
  "/attacks/comparative-traffic",
  "/attacks/global-threats"
];

async function testRoutes() {
  console.log("🚀 TESTING ALL ROUTES...\n");

  for (const route of routes) {
    const url = `${BASE_URL}${route.replace("/charts", "")}`;

    const start = Date.now();

    try {
      const res = await axios.get(url, { timeout: 100000 });

      const time = Date.now() - start;

      console.log(`✅ ${route}`);
      console.log(`   Status: ${res.status}`);
      console.log(`   Time: ${time}ms`);
      console.log(
        `   Data: ${
          Array.isArray(res.data)
            ? `Array(${res.data.length})`
            : typeof res.data
        }\n`
      );
    } catch (err) {
      const time = Date.now() - start;

      console.log(`❌ ${route}`);
      console.log(`   Error: ${err.message}`);
      console.log(`   Time: ${time}ms\n`);
    }
  }

  console.log("✅ TEST COMPLETE");
}

testRoutes();