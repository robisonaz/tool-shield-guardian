import type { Request, Response, NextFunction } from "express";
import passport from "../config/passport.js";
import pool from "../config/database.js";

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  passport.authenticate("jwt", { session: false }, (err: any, user: any) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ error: "Não autorizado" });
    (req as any).user = user;
    next();
  })(req, res, next);
}

export async function requireAdmin(req: Request, res: Response, next: NextFunction) {
  const user = (req as any).user;
  if (!user) return res.status(401).json({ error: "Não autorizado" });

  const { rows } = await pool.query(
    "SELECT 1 FROM user_roles WHERE user_id = $1 AND role = 'admin'",
    [user.id]
  );
  if (rows.length === 0) return res.status(403).json({ error: "Acesso restrito a administradores" });
  next();
}
