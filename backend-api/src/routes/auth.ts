import { Router } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import passport from "../config/passport.js";
import { JWT_SECRET } from "../config/passport.js";
import pool from "../config/database.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();
const TOKEN_EXPIRY = "24h";
const REFRESH_EXPIRY_DAYS = 30;

function generateTokens(userId: string) {
  const accessToken = jwt.sign({ sub: userId }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
  const refreshToken = crypto.randomUUID() + crypto.randomUUID();
  return { accessToken, refreshToken };
}

// Login
router.post("/login", (req, res, next) => {
  passport.authenticate("local", { session: false }, async (err: any, user: any, info: any) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ error: info?.message || "Credenciais inválidas" });

    const { accessToken, refreshToken } = generateTokens(user.id);

    // Store refresh token
    const expiresAt = new Date(Date.now() + REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
    await pool.query(
      "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
      [user.id, refreshToken, expiresAt]
    );

    // Check admin
    const { rows: roleRows } = await pool.query(
      "SELECT 1 FROM user_roles WHERE user_id = $1 AND role = 'admin'",
      [user.id]
    );

    res.json({
      accessToken,
      refreshToken,
      user: { id: user.id, email: user.email, full_name: user.full_name },
      isAdmin: roleRows.length > 0,
    });
  })(req, res, next);
});

// Refresh token
router.post("/refresh", async (req, res) => {
  const { refreshToken } = req.body;
  if (!refreshToken) return res.status(400).json({ error: "refreshToken obrigatório" });

  const { rows } = await pool.query(
    "SELECT * FROM refresh_tokens WHERE token = $1 AND expires_at > now()",
    [refreshToken]
  );
  if (rows.length === 0) return res.status(401).json({ error: "Token inválido ou expirado" });

  const tokenRow = rows[0];

  // Delete old token and generate new pair
  await pool.query("DELETE FROM refresh_tokens WHERE id = $1", [tokenRow.id]);

  const tokens = generateTokens(tokenRow.user_id);
  const expiresAt = new Date(Date.now() + REFRESH_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
  await pool.query(
    "INSERT INTO refresh_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)",
    [tokenRow.user_id, tokens.refreshToken, expiresAt]
  );

  res.json({ accessToken: tokens.accessToken, refreshToken: tokens.refreshToken });
});

// Get current user info
router.get("/me", requireAuth, async (req, res) => {
  const user = (req as any).user;
  const { rows: roleRows } = await pool.query(
    "SELECT 1 FROM user_roles WHERE user_id = $1 AND role = 'admin'",
    [user.id]
  );
  res.json({
    user: { id: user.id, email: user.email, full_name: user.full_name },
    isAdmin: roleRows.length > 0,
  });
});

// Logout (invalidate refresh token)
router.post("/logout", async (req, res) => {
  const { refreshToken } = req.body;
  if (refreshToken) {
    await pool.query("DELETE FROM refresh_tokens WHERE token = $1", [refreshToken]);
  }
  res.json({ ok: true });
});

export default router;
