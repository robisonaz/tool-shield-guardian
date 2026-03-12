import { Router } from "express";
import multer from "multer";
import path from "path";
import fs from "fs";
import pool from "../config/database.js";
import { requireAuth } from "../middleware/auth.js";

const router = Router();

// Ensure uploads directory exists
const UPLOAD_DIR = path.resolve("uploads/branding");
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (_req, _file, cb) => cb(null, UPLOAD_DIR),
  filename: (_req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `logo${ext}`);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 2 * 1024 * 1024 }, // 2MB
  fileFilter: (_req, file, cb) => {
    const allowed = ["image/png", "image/jpeg", "image/svg+xml", "image/webp"];
    cb(null, allowed.includes(file.mimetype));
  },
});

// Public: Get branding (no auth required)
router.get("/", async (_req, res) => {
  try {
    const { rows } = await pool.query(
      "SELECT * FROM branding_settings LIMIT 1"
    );
    if (rows.length === 0) {
      return res.json(null);
    }
    res.json(rows[0]);
  } catch (err: any) {
    console.error("Get branding error:", err);
    res.status(500).json({ error: "Erro ao carregar branding" });
  }
});

// Admin: Update branding
router.put("/", requireAuth, async (req, res) => {
  const user = (req as any).user;
  const { rows: roleCheck } = await pool.query(
    "SELECT 1 FROM user_roles WHERE user_id = $1 AND role = 'admin'",
    [user.id]
  );
  if (roleCheck.length === 0) return res.status(403).json({ error: "Acesso negado" });

  const { app_name, app_subtitle, logo_url, primary_color, accent_color } = req.body;

  try {
    // Check if row exists
    const { rows: existing } = await pool.query("SELECT id FROM branding_settings LIMIT 1");

    if (existing.length === 0) {
      const { rows } = await pool.query(
        `INSERT INTO branding_settings (app_name, app_subtitle, logo_url, primary_color, accent_color)
         VALUES ($1, $2, $3, $4, $5) RETURNING *`,
        [app_name, app_subtitle, logo_url, primary_color, accent_color]
      );
      return res.json(rows[0]);
    }

    const { rows } = await pool.query(
      `UPDATE branding_settings SET
        app_name = COALESCE($1, app_name),
        app_subtitle = COALESCE($2, app_subtitle),
        logo_url = $3,
        primary_color = COALESCE($4, primary_color),
        accent_color = COALESCE($5, accent_color),
        updated_at = now()
       WHERE id = $6 RETURNING *`,
      [app_name, app_subtitle, logo_url, primary_color, accent_color, existing[0].id]
    );
    res.json(rows[0]);
  } catch (err: any) {
    console.error("Update branding error:", err);
    res.status(500).json({ error: "Erro ao salvar branding" });
  }
});

// Admin: Upload logo
router.post("/logo", requireAuth, upload.single("logo"), async (req, res) => {
  const user = (req as any).user;
  const { rows: roleCheck } = await pool.query(
    "SELECT 1 FROM user_roles WHERE user_id = $1 AND role = 'admin'",
    [user.id]
  );
  if (roleCheck.length === 0) return res.status(403).json({ error: "Acesso negado" });

  if (!req.file) return res.status(400).json({ error: "Nenhum arquivo enviado" });

  const logoUrl = `/uploads/branding/${req.file.filename}?t=${Date.now()}`;
  res.json({ logo_url: logoUrl });
});

export default router;
