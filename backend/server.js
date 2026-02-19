const express = require("express");
require("dotenv").config();
const connectDB = require("./config/db");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const { spawn } = require("child_process");

const attackRoutes = require("./routes/attackRoutes");
const authRoutes = require("./routes/auth");
const chartRoutes = require("./routes/chartRoutes");
const ingestRoutes = require("./routes/ingestRoutes");
const copilotRoutes = require("./routes/copilotRoutes");

const app = express();
const PORT = process.env.PORT || 5002;

console.log("Starting server...");


// --------------------------------------------
// Middleware
// --------------------------------------------
app.use(express.json());
console.log("Middleware: JSON Parsing Enabled");

app.use(cors());
console.log("Middleware: CORS Enabled");

app.use(helmet());
console.log("Middleware: Helmet Security Enabled");

app.use(morgan("dev"));
console.log("Middleware: Morgan Logger Enabled");

// --------------------------------------------
// DB Connection + Enrichment Worker
// --------------------------------------------
console.log("Connecting to MongoDB...");
connectDB()
  .then(() => {
    console.log("MongoDB connected.");

    console.log("Starting enrichment worker...");
    const worker = spawn("node", ["scripts/enrichmentWorker.js"], {
      stdio: "inherit",
      env: process.env,
    });

    worker.on("close", (code) => {
      console.log(`Enrichment worker exited with code ${code}`);
    });
  })
  .catch((err) => console.error("MongoDB connection failed:", err));

// --------------------------------------------
// Routes
// --------------------------------------------
console.log("Loading routes...");

app.use("/api/auth", authRoutes);
console.log("Registered: /api/auth");

app.use("/api/charts", chartRoutes);
console.log("Registered: /api/charts");

app.use("/api/attacks", attackRoutes);
console.log("Registered: /api/attacks");

app.use("/api/ingest", ingestRoutes);
console.log("Registered: /api/ingest");

app.use("/api/copilot", copilotRoutes);
console.log("Registered: /api/copilot");

// --------------------------------------------
// Health Check
// --------------------------------------------
app.get("/", (req, res) => {
  console.log("Health check route accessed.");
  res.send("Welcome to the API");
});

// --------------------------------------------
// Debug: Print all registered routes
// --------------------------------------------
console.log("Registered Routes:");
app._router.stack.forEach((middleware) => {
  if (middleware.route) {
    console.log(`Route registered: ${middleware.route.path}`);
  }
});

// --------------------------------------------
// Global Error Handler
// --------------------------------------------
app.use((err, req, res, next) => {
  console.error("Global Error:", err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

// --------------------------------------------
// Start Server
// --------------------------------------------
if (process.env.NODE_ENV !== "test") {
  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server is running at http://0.0.0.0:${PORT}`);
    console.log(`Swagger Docs available at http://localhost:${PORT}/api-docs`);
  });
}

module.exports = app;