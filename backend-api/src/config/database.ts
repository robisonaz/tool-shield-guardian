import pg from "pg";

const { Pool } = pg;

const pool = new Pool({
  host: process.env.DB_HOST || "localhost",
  port: parseInt(process.env.DB_PORT || "5432"),
  user: process.env.DB_USER || "secversions",
  password: process.env.DB_PASSWORD || "",
  database: process.env.DB_NAME || "secversions",
  max: 20,
  idleTimeoutMillis: 30000,
});

export default pool;
