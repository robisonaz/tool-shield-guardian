import { Router } from "express";
import pool from "../config/database.js";
import { requireAuth, requireAdmin } from "../middleware/auth.js";

const router = Router();

// Public: list enabled providers (for login page)
router.get("/public", async (_req, res) => {
  const { rows } = await pool.query(
    "SELECT id, display_name, name, issuer_url, client_id, scopes FROM oidc_providers WHERE enabled = true"
  );
  res.json(rows);
});

// Admin: list all providers
router.get("/", requireAuth, requireAdmin, async (_req, res) => {
  const { rows } = await pool.query("SELECT * FROM oidc_providers ORDER BY created_at ASC");
  res.json(rows);
});

// Admin: create provider
router.post("/", requireAuth, requireAdmin, async (req, res) => {
  const { name, display_name, issuer_url, client_id, client_secret, scopes, enabled } = req.body;
  const { rows } = await pool.query(
    `INSERT INTO oidc_providers (name, display_name, issuer_url, client_id, client_secret, scopes, enabled)
     VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
    [name, display_name, issuer_url, client_id, client_secret, scopes || "openid profile email", enabled || false]
  );
  res.json(rows[0]);
});

// Admin: update provider
router.put("/:id", requireAuth, requireAdmin, async (req, res) => {
  const { name, display_name, issuer_url, client_id, client_secret, scopes, enabled } = req.body;
  const { rows } = await pool.query(
    `UPDATE oidc_providers SET name=$1, display_name=$2, issuer_url=$3, client_id=$4,
     client_secret=$5, scopes=$6, enabled=$7 WHERE id=$8 RETURNING *`,
    [name, display_name, issuer_url, client_id, client_secret, scopes, enabled, req.params.id]
  );
  if (rows.length === 0) return res.status(404).json({ error: "Provedor não encontrado" });
  res.json(rows[0]);
});

// Admin: delete provider
router.delete("/:id", requireAuth, requireAdmin, async (req, res) => {
  await pool.query("DELETE FROM oidc_providers WHERE id = $1", [req.params.id]);
  res.json({ ok: true });
});

export default router;
