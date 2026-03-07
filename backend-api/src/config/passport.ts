import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as JwtStrategy, ExtractJwt } from "passport-jwt";
import bcrypt from "bcryptjs";
import pool from "./database.js";

const JWT_SECRET = process.env.JWT_SECRET || "change-me-in-production";

// Local strategy (email + password)
passport.use(
  new LocalStrategy(
    { usernameField: "email", passwordField: "password" },
    async (email, password, done) => {
      try {
        const { rows } = await pool.query(
          "SELECT * FROM users WHERE email = $1",
          [email.toLowerCase().trim()]
        );
        const user = rows[0];
        if (!user) return done(null, false, { message: "Credenciais inválidas" });
        if (!user.password_hash) return done(null, false, { message: "Use o login OIDC para esta conta" });

        const valid = await bcrypt.compare(password, user.password_hash);
        if (!valid) return done(null, false, { message: "Credenciais inválidas" });

        return done(null, user);
      } catch (err) {
        return done(err);
      }
    }
  )
);

// JWT strategy
passport.use(
  new JwtStrategy(
    {
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: JWT_SECRET,
    },
    async (payload, done) => {
      try {
        const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [payload.sub]);
        if (!rows[0]) return done(null, false);
        return done(null, rows[0]);
      } catch (err) {
        return done(err);
      }
    }
  )
);

export { JWT_SECRET };
export default passport;
