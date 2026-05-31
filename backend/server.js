const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
require("dotenv").config();
const connectDB = require("./config/db");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");

// -------------------------------
// ROUTES
// -------------------------------
const attackRoutes = require("./routes/attackRoutes");
const authRoutes = require("./routes/auth");
const chartRoutes = require("./routes/chartRoutes");
const ingestRoutes = require("./routes/ingestRoutes");
const copilotRoutes = require("./routes/copilotRoutes");

// -------------------------------
// APP INIT
// -------------------------------
const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },

  transports: ["websocket"],

  pingTimeout: 60000,
  pingInterval: 25000,
});

// expose globally
app.locals.io = io;
const PORT = process.env.PORT || 5002;

console.log("🚀 Starting server...");

// =====================================================
// REAL-TIME INGEST QUEUE
// =====================================================
const ingestQueue = [];
const MAX_QUEUE_SIZE = 10000;

// expose queue globally so ingestRoutes can push into it
app.locals.ingestQueue = ingestQueue;

// =====================================================
// QUEUE PROCESSOR (NON-BLOCKING PIPELINE)
// =====================================================
const parseDShieldLog = require("./utils/parseLogs");
const Attack = require("./models/AttackModel");
const TopIP = require("./models/TopIPModel");
const Port = require("./models/PortModel");
const Protocol = require("./models/ProtocolModel");

let processing = false;

const processQueue = async () => {
  if (processing) return;
  processing = true;

  try {
    while (ingestQueue.length > 0) {
      const raw = ingestQueue.shift();

      try {
        const parsed = parseDShieldLog(raw);
        if (!parsed || !parsed.source_ip) continue;

        const now = new Date();

        // 🔥 NON-BLOCKING WRITES (critical)
        Attack.create(parsed).catch(console.error);

        TopIP.updateOne(
          { source_ip: parsed.source_ip },
          {
            $inc: { count: 1 },
            $set: { last_seen: now },
            $setOnInsert: { first_seen: now }
          },
          { upsert: true }
        ).catch(console.error);

        if (parsed.target_port) {
          Port.updateOne(
            { port: parsed.target_port },
            {
              $inc: { count: 1 },
              $set: { last_updated: now }
            },
            { upsert: true }
          ).catch(console.error);
        }

        if (parsed.protocol) {
          Protocol.updateOne(
            { protocol: parsed.protocol },
            {
              $inc: { count: 1 },
              $set: { last_updated: now }
            },
            { upsert: true }
          ).catch(console.error);
        }

      } catch (err) {
        console.error("❌ Queue item failed:", err.message);
      }
    }
  } catch (err) {
    console.error("❌ Queue processor error:", err);
  }

  processing = false;
};

// run queue processor continuously
setInterval(processQueue, 1000);

// =====================================================
// MIDDLEWARE
// =====================================================
app.use(express.json());
console.log("Middleware: JSON Parsing Enabled");

app.use(cors());
console.log("Middleware: CORS Enabled");

app.use(helmet());
console.log("Middleware: Helmet Security Enabled");

app.use(morgan("dev"));
console.log("Middleware: Morgan Logger Enabled");

// =====================================================
// REAL-TIME TELEMETRY SOCKETS
// =====================================================

io.on("connection", (socket) => {

  console.log(
    `🔌 Telemetry client connected: ${socket.id}`
  );

  socket.emit("telemetry:status", {
    connected: true,
    timestamp: Date.now(),
  });

  socket.on("disconnect", () => {

    console.log(
      `🔌 Telemetry client disconnected: ${socket.id}`
    );

  });

});

// =====================================================
// DB CONNECTION + WORKER
// =====================================================
console.log("Connecting to MongoDB...");
connectDB()
  .then(() => {
    console.log("✅ MongoDB connected.");

  })
  .catch((err) => console.error("❌ MongoDB connection failed:", err));

// =====================================================
// ROUTES
// =====================================================
console.log("Loading routes...");

app.use("/api/auth", authRoutes);
console.log("Registered: /api/auth");

app.use("/api/charts", chartRoutes);
console.log("Registered: /api/charts");

app.use("/api/attacks", attackRoutes);
console.log("Registered: /api/attacks");

// 🔥 IMPORTANT: ingest route will now PUSH TO QUEUE ONLY
app.use("/api/ingest", ingestRoutes);
console.log("Registered: /api/ingest");

app.use("/api/copilot", copilotRoutes);
console.log("Registered: /api/copilot");

// =====================================================
// HEALTH CHECK (UPGRADED)
// =====================================================
app.get("/", (req, res) => {
  res.json({
    status: "ok",
    uptime: process.uptime(),
    queueDepth: ingestQueue.length,
    timestamp: Date.now()
  });
});

// =====================================================
// DEBUG ROUTES
// =====================================================
console.log("Registered Routes:");
app._router.stack.forEach((middleware) => {
  if (middleware.route) {
    console.log(`Route registered: ${middleware.route.path}`);
  }
});

// =====================================================
// GLOBAL ERROR HANDLER
// =====================================================
app.use((err, req, res, next) => {
  console.error("❌ Global Error:", err.stack);
  res.status(500).json({ error: "Something went wrong!" });
});

// =====================================================
// SERVER START (WITH KEEPALIVE FIX)
// =====================================================
if (process.env.NODE_ENV !== "test") {

  server.listen(PORT, "0.0.0.0", () => {

    console.log(
      `🌐 Server running at http://0.0.0.0:${PORT}`
    );

    console.log(
      `📡 WebSocket telemetry enabled`
    );

    console.log(
      `📄 Swagger Docs at http://localhost:${PORT}/api-docs`
    );

  });

  // ================================================
  // REAL-TIME STABILITY
  // ================================================

  server.keepAliveTimeout = 65000;

  server.headersTimeout = 66000;

}