import { Router } from "express";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import pool from "../config/database.js";
import { JWT_SECRET } from "../config/passport.js";

const router = Router();
const TOKEN_EXPIRY = "24h";
const REFRESH_EXPIRY_DAYS = 30;

// OIDC callback - exchange code for tokens, create/find user, return JWT
router.post("/callback", async (req, res) => {
  try {
    const { code, providerId, redirectUri } = req.body;
    if (!code || !providerId || !redirectUri) {
      return res.status(400).json({ error: "Parâmetros obrigatórios faltando" });
    }

    // Fetch provider
    const { rows: providerRows } = await pool.query(
      "SELECT * FROM oidc_providers WHERE id = $1 AND enabled = true",
      [providerId]
    );
    const provider = providerRows[0];
    if (!provider) return res.status(404).json({ error: "Provedor não encontrado" });

    // Exchange code for tokens
    const tokenUrl = `${provider.issuer_url}/protocol/openid-connect/token`;
    const tokenRes = await fetch(tokenUrl, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code",
        code,
        redirect_uri: redirectUri,
        client_id: provider.client_id,
        client_secret: provider.client_secret,
      }),
    });

    if (!tokenRes.ok) {
      console.error("Token exchange failed:", await tokenRes.text());
      return res.status(401).json({ error: "Falha na troca de tokens" });
    }

    const tokens = await tokenRes.json();

    // Fetch user info
    const userinfoUrl = `${provider.issuer_url}/protocol/openid-connect/userinfo`;
    const userinfoRes = await fetch(userinfoUrl, {
      headers: { Authorization: `Bearer ${tokens.access_token}` },
    });
    if (!userinfoRes.ok) return res.status(401).json({ error: "Falha ao obter informações do usuário" });

    const userinfo = await userinfoRes.json();
    const email = userinfo.email;
    const fullName = userinfo.name || userinfo.preferred_username || "";
    if (!email) return res.status(400).json({ error: "Email não fornecido pelo provedor OIDC" });

    // Find or create user
    let { rows: userRows } = await pool.query("SELECT * FROM users WHERE email = $1", [email.toLowerCase()]);
    let user = userRows[0];

    if (!user) {
      const { rows } = await pool.query(
        "INSERT INTO users (email, full_name, oidc_provider) VALUES ($1, $2, $3) RETURNING *",
        [email.toLowerCase(), fullName, provider.name]
      );
      user = rows[0];
    }

    // Generate JWT
    const accessToken = jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: TOKEN_EXPIRY });
    const refreshToken = crypto.randomUUID() + crypto.randomUUID();
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
  } catch (err) {
    console.error("OIDC callback error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

export default router;
