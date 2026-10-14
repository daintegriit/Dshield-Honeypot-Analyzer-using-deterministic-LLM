// backend/routes/copilotRoutes.js
const express = require("express");
const router = express.Router();

const { getCopilotInsight } = require("../controllers/copilotController");
const { askCopilot } = require("../controllers/copilotAskController");


// GET /api/copilot/insight?minutes=60&limit=5000
router.get("/insight", getCopilotInsight);
// POST /api/copilot/ask
router.post("/ask", askCopilot);

module.exports = router;