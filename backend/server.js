import express from "express";
import cors from "cors";
import pkg from "pg";

const { Pool } = pkg;

const app = express();
app.use(cors());
app.use(express.json());

const pool = new Pool({
  host: "10.151.144.47",
  port: 30432,
  user: "secversions",
  password: "rJnxy6II2ICR9L",
  database: "secversions"
});

app.get("/users", async (req, res) => {
  const result = await pool.query("SELECT * FROM users");
  res.json(result.rows);
});

app.listen(3010, () => {
  console.log("API rodando na porta 3010");
});
