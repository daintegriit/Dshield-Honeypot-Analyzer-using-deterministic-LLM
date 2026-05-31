// backend/server.js  (LOCAL ANALYST MODE)

const express = require("express");
require("dotenv").config();
const connectDB = require("./config/db");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");

// Routes
const attackRoutes = require("./routes/attackRoutes");
const authRoutes = require("./routes/auth");
const chartRoutes = require("./routes/chartRoutes");
const ingestRoutes = require("./routes/ingestRoutes");
const copilotRoutes = require("./routes/copilotRoutes");

const app = express();
const PORT = process.env.PORT || 5002;

console.log("🧠 Starting LOCAL analyst backend...");

// --------------------------------------------
// Middleware
// --------------------------------------------
app.use(express.json());
console.log("✓ JSON parsing enabled");

app.use(cors());
console.log("✓ CORS enabled");

app.use(helmet());
console.log("✓ Helmet security enabled");

app.use(morgan("dev"));
console.log("✓ Morgan logger enabled");

// --------------------------------------------
// Database (READ-ONLY INTENT)
// --------------------------------------------
console.log("Connecting to MongoDB (analyst mode)...");
connectDB()
  .then(() => {
    console.log("✓ MongoDB connected (read-only usage)");
    console.log("🚫 Enrichment worker DISABLED (local analyst mode)");
  })
  .catch((err) => {
    console.error("MongoDB connection failed:", err);
    process.exit(1);
  });

// --------------------------------------------
// Routes
// --------------------------------------------
console.log("Registering routes...");

app.use("/api/auth", authRoutes);
console.log("✓ /api/auth");

app.use("/api/charts", chartRoutes);
console.log("✓ /api/charts");

app.use("/api/attacks", attackRoutes);
console.log("✓ /api/attacks");

app.use("/api/copilot", copilotRoutes);
console.log("✓ /api/copilot");

app.use("/api/ingest", ingestRoutes);
console.log("Registered: /api/ingest");

// Ingest belongs to EC2 ONLY.

// --------------------------------------------
// Health Check
// --------------------------------------------
app.get("/", (req, res) => {
  res.send("LOCAL Analyst Backend Running");
});

// --------------------------------------------
// Debug: Registered routes
// --------------------------------------------
console.log("Registered Routes:");
app._router.stack.forEach((m) => {
  if (m.route) {
    console.log(` • ${m.route.path}`);
  }
});

// --------------------------------------------
// Global Error Handler
// --------------------------------------------
app.use((err, req, res, next) => {
  console.error("Global Error:", err.stack);
  res.status(500).json({ error: "Internal Server Error" });
});

// --------------------------------------------
// Start Server
// --------------------------------------------
if (process.env.NODE_ENV !== "test") {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server is running at http://0.0.0.0:${PORT}`);
    console.log(`📘 Swagger docs: http://localhost:${PORT}/api-docs`);
  });
}

module.exports = app;