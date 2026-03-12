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

// Update profile
router.put("/profile", requireAuth, async (req, res) => {
  const user = (req as any).user;
  const { full_name, email } = req.body;

  try {
    const fields: string[] = [];
    const values: any[] = [];
    let idx = 1;

    if (full_name !== undefined) {
      fields.push(`full_name = $${idx++}`);
      values.push(full_name);
    }
    if (email !== undefined) {
      fields.push(`email = $${idx++}`);
      values.push(email);
    }

    if (fields.length === 0) {
      return res.status(400).json({ error: "Nenhum campo para atualizar" });
    }

    values.push(user.id);
    await pool.query(
      `UPDATE users SET ${fields.join(", ")}, updated_at = now() WHERE id = $${idx}`,
      values
    );

    // Also update profiles table
    const profileFields: string[] = [];
    const profileValues: any[] = [];
    let pidx = 1;
    if (full_name !== undefined) {
      profileFields.push(`full_name = $${pidx++}`);
      profileValues.push(full_name);
    }
    if (email !== undefined) {
      profileFields.push(`email = $${pidx++}`);
      profileValues.push(email);
    }
    if (profileFields.length > 0) {
      profileValues.push(user.id);
      await pool.query(
        `UPDATE profiles SET ${profileFields.join(", ")}, updated_at = now() WHERE id = $${pidx}`,
        profileValues
      );
    }

    const { rows } = await pool.query("SELECT id, email, full_name FROM users WHERE id = $1", [user.id]);
    res.json({ user: rows[0] });
  } catch (err: any) {
    console.error("Profile update error:", err);
    res.status(500).json({ error: "Erro ao atualizar perfil" });
  }
});

// Change password
router.post("/change-password", requireAuth, async (req, res) => {
  const user = (req as any).user;
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: "Senha atual e nova senha são obrigatórias" });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: "A nova senha deve ter pelo menos 6 caracteres" });
  }

  try {
    const { rows } = await pool.query("SELECT password_hash FROM users WHERE id = $1", [user.id]);
    if (rows.length === 0) return res.status(404).json({ error: "Usuário não encontrado" });

    const valid = await bcrypt.compare(currentPassword, rows[0].password_hash);
    if (!valid) return res.status(401).json({ error: "Senha atual incorreta" });

    const hash = await bcrypt.hash(newPassword, 12);
    await pool.query("UPDATE users SET password_hash = $1, updated_at = now() WHERE id = $2", [hash, user.id]);

    res.json({ ok: true });
  } catch (err: any) {
    console.error("Change password error:", err);
    res.status(500).json({ error: "Erro ao alterar senha" });
  }
});

// Admin: List users
router.get("/users", requireAuth, async (req, res) => {
  const adminUser = (req as any).user;
  const { rows: roleCheck } = await pool.query(
    "SELECT 1 FROM user_roles WHERE user_id = $1 AND role = 'admin'", [adminUser.id]
  );
  if (roleCheck.length === 0) return res.status(403).json({ error: "Acesso negado" });

  try {
    const { rows } = await pool.query(`
      SELECT u.id, u.email, u.full_name, u.created_at,
        COALESCE(ur.role, 'user') as role
      FROM users u
      LEFT JOIN user_roles ur ON ur.user_id = u.id
      ORDER BY u.created_at DESC
    `);
    res.json(rows);
  } catch (err: any) {
    console.error("List users error:", err);
    res.status(500).json({ error: "Erro ao listar usuários" });
  }
});

// Admin: Create user
router.post("/users", requireAuth, async (req, res) => {
  const adminUser = (req as any).user;
  const { rows: roleCheck } = await pool.query(
    "SELECT 1 FROM user_roles WHERE user_id = $1 AND role = 'admin'", [adminUser.id]
  );
  if (roleCheck.length === 0) return res.status(403).json({ error: "Acesso negado" });

  const { email, password, full_name, role } = req.body;
  if (!email || !password) return res.status(400).json({ error: "E-mail e senha obrigatórios" });

  try {
    const hash = await bcrypt.hash(password, 12);
    const { rows } = await pool.query(
      "INSERT INTO users (email, password_hash, full_name) VALUES ($1, $2, $3) RETURNING id, email, full_name",
      [email, hash, full_name || ""]
    );
    const newUser = rows[0];

    // Create profile
    await pool.query(
      "INSERT INTO profiles (id, email, full_name) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING",
      [newUser.id, email, full_name || ""]
    );

    // Assign role
    if (role && role !== "user") {
      await pool.query(
        "INSERT INTO user_roles (user_id, role) VALUES ($1, $2) ON CONFLICT (user_id, role) DO NOTHING",
        [newUser.id, role]
      );
    }

    res.json({ ...newUser, role: role || "user" });
  } catch (err: any) {
    if (err.code === "23505") return res.status(409).json({ error: "E-mail já cadastrado" });
    console.error("Create user error:", err);
    res.status(500).json({ error: "Erro ao criar usuário" });
  }
});

// Admin: Update user role
router.put("/users/:userId/role", requireAuth, async (req, res) => {
  const adminUser = (req as any).user;
  const { rows: roleCheck } = await pool.query(
    "SELECT 1 FROM user_roles WHERE user_id = $1 AND role = 'admin'", [adminUser.id]
  );
  if (roleCheck.length === 0) return res.status(403).json({ error: "Acesso negado" });

  const { userId } = req.params;
  const { role } = req.body;

  try {
    // Remove existing roles
    await pool.query("DELETE FROM user_roles WHERE user_id = $1", [userId]);

    // Add new role if not default 'user'
    if (role && role !== "user") {
      await pool.query(
        "INSERT INTO user_roles (user_id, role) VALUES ($1, $2)",
        [userId, role]
      );
    }

    res.json({ ok: true });
  } catch (err: any) {
    console.error("Update role error:", err);
    res.status(500).json({ error: "Erro ao atualizar papel" });
  }
});

// Admin: Delete user
router.delete("/users/:userId", requireAuth, async (req, res) => {
  const adminUser = (req as any).user;
  const { rows: roleCheck } = await pool.query(
    "SELECT 1 FROM user_roles WHERE user_id = $1 AND role = 'admin'", [adminUser.id]
  );
  if (roleCheck.length === 0) return res.status(403).json({ error: "Acesso negado" });

  const { userId } = req.params;

  if (userId === adminUser.id) {
    return res.status(400).json({ error: "Você não pode excluir sua própria conta" });
  }

  try {
    await pool.query("DELETE FROM user_roles WHERE user_id = $1", [userId]);
    await pool.query("DELETE FROM profiles WHERE id = $1", [userId]);
    await pool.query("DELETE FROM refresh_tokens WHERE user_id = $1", [userId]);
    await pool.query("DELETE FROM users WHERE id = $1", [userId]);
    res.json({ ok: true });
  } catch (err: any) {
    console.error("Delete user error:", err);
    res.status(500).json({ error: "Erro ao excluir usuário" });
  }
});

export default router;
