import "dotenv/config";
import express from "express";
import cors from "cors";
import path from "path";
import passport from "./config/passport.js";
import { ensureSchema } from "./config/database.js";
import authRoutes from "./routes/auth.js";
import providersRoutes from "./routes/providers.js";
import oidcRoutes from "./routes/oidc.js";
import toolsRoutes from "./routes/tools.js";
import brandingRoutes from "./routes/branding.js";
import discoveryRoutes from "./routes/discovery.js";

const app = express();
const PORT = parseInt(process.env.PORT || "3010");

app.use(cors({
  origin: process.env.CORS_ORIGIN || true,
  credentials: true,
}));
app.use(express.json());
app.use(passport.initialize());

// Serve uploaded files
app.use("/uploads", express.static(path.resolve("uploads")));

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/providers", providersRoutes);
app.use("/api/oidc", oidcRoutes);
app.use("/api/tools", toolsRoutes);
app.use("/api/branding", brandingRoutes);
app.use("/api/discovery", discoveryRoutes);

// Health check
app.get("/api/health", (_req, res) => res.json({ status: "ok" }));

async function startServer() {
  try {
    await ensureSchema();
    app.listen(PORT, () => {
      console.log(`SecVersions API running on port ${PORT}`);
    });
  } catch (err) {
    console.error("Failed to initialize database schema:", err);
    process.exit(1);
  }
}

void startServer();
