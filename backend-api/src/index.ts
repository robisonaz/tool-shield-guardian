import express from "express";
import cors from "cors";
import passport from "./config/passport.js";
import authRoutes from "./routes/auth.js";
import providersRoutes from "./routes/providers.js";
import oidcRoutes from "./routes/oidc.js";
import toolsRoutes from "./routes/tools.js";

const app = express();
const PORT = parseInt(process.env.PORT || "3010");

app.use(cors({
  origin: process.env.CORS_ORIGIN || true,
  credentials: true,
}));
app.use(express.json());
app.use(passport.initialize());

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/providers", providersRoutes);
app.use("/api/oidc", oidcRoutes);
app.use("/api/tools", toolsRoutes);

// Health check
app.get("/api/health", (_req, res) => res.json({ status: "ok" }));

app.listen(PORT, () => {
  console.log(`SecVersions API running on port ${PORT}`);
});
