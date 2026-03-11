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

let toolVersionsSchemaEnsured = false;

export async function ensureToolVersionsSchema() {
  if (toolVersionsSchemaEnsured) return;

  await pool.query(`
    CREATE TABLE IF NOT EXISTS tool_versions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tool_id UUID NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
      version TEXT NOT NULL,
      latest_version TEXT,
      latest_patch_for_cycle TEXT,
      is_outdated BOOLEAN,
      is_patch_outdated BOOLEAN,
      eol TEXT,
      lts TEXT,
      cycle_label TEXT,
      cves JSONB NOT NULL DEFAULT '[]',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );

    CREATE INDEX IF NOT EXISTS idx_tool_versions_tool_id ON tool_versions(tool_id);
  `);

  await pool.query(`
    DO $$
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_proc WHERE proname = 'update_updated_at') THEN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'tool_versions_updated_at') THEN
          CREATE TRIGGER tool_versions_updated_at
          BEFORE UPDATE ON tool_versions
          FOR EACH ROW
          EXECUTE FUNCTION update_updated_at();
        END IF;
      END IF;
    END
    $$;
  `);

  toolVersionsSchemaEnsured = true;
}

export default pool;
