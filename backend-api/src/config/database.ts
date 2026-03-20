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

let schemaEnsured = false;

export async function ensureSchema() {
  if (schemaEnsured) return;

  console.log("Ensuring database schema...");

  // Extensions
  await pool.query(`CREATE EXTENSION IF NOT EXISTS "pgcrypto";`);

  // Enum
  await pool.query(`
    DO $$ BEGIN
      CREATE TYPE app_role AS ENUM ('admin', 'user');
    EXCEPTION WHEN duplicate_object THEN NULL;
    END $$;
  `);

  // Users
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT,
      full_name TEXT,
      oidc_provider TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // User roles
  await pool.query(`
    CREATE TABLE IF NOT EXISTS user_roles (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      role app_role NOT NULL,
      UNIQUE (user_id, role)
    );
    CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
  `);

  // OIDC providers
  await pool.query(`
    CREATE TABLE IF NOT EXISTS oidc_providers (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      name TEXT NOT NULL DEFAULT 'keycloak',
      display_name TEXT NOT NULL DEFAULT 'Keycloak',
      issuer_url TEXT NOT NULL,
      client_id TEXT NOT NULL,
      client_secret TEXT NOT NULL,
      scopes TEXT NOT NULL DEFAULT 'openid profile email',
      enabled BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Tools
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tools (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      name TEXT NOT NULL,
      version TEXT NOT NULL,
      source_url TEXT,
      latest_version TEXT,
      latest_patch_for_cycle TEXT,
      is_outdated BOOLEAN,
      is_patch_outdated BOOLEAN,
      eol TEXT,
      lts TEXT,
      cycle_label TEXT,
      cves JSONB NOT NULL DEFAULT '[]',
      category TEXT NOT NULL DEFAULT 'ferramenta',
      added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE tools ADD COLUMN IF NOT EXISTS category TEXT NOT NULL DEFAULT 'ferramenta';
    ALTER TABLE tools ADD COLUMN IF NOT EXISTS description TEXT;
    CREATE INDEX IF NOT EXISTS idx_tools_user_id ON tools(user_id);
  `);

  // Tool versions
  await pool.query(`
    CREATE TABLE IF NOT EXISTS tool_versions (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      tool_id UUID NOT NULL REFERENCES tools(id) ON DELETE CASCADE,
      version TEXT NOT NULL,
      source_url TEXT,
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
    ALTER TABLE tool_versions ADD COLUMN IF NOT EXISTS source_url TEXT;
    CREATE INDEX IF NOT EXISTS idx_tool_versions_tool_id ON tool_versions(tool_id);
    CREATE INDEX IF NOT EXISTS idx_tool_versions_tool_lookup ON tool_versions(tool_id, version, source_url);
  `);

  // Discovery scans history
  await pool.query(`
    CREATE TABLE IF NOT EXISTS discovery_scans (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      cidr TEXT NOT NULL,
      total_hosts INTEGER NOT NULL DEFAULT 0,
      total_ports_scanned INTEGER NOT NULL DEFAULT 0,
      results JSONB NOT NULL DEFAULT '[]',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_discovery_scans_user_id ON discovery_scans(user_id);
  `);

  // Refresh tokens
  await pool.query(`
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      token TEXT UNIQUE NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
    CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);
  `);

  // Branding settings
  await pool.query(`
    CREATE TABLE IF NOT EXISTS branding_settings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      app_name TEXT NOT NULL DEFAULT 'SecVersions',
      app_subtitle TEXT NOT NULL DEFAULT 'Monitoramento de versões e vulnerabilidades',
      logo_url TEXT,
      logo_size INTEGER NOT NULL DEFAULT 36,
      primary_color TEXT NOT NULL DEFAULT '160 100% 45%',
      accent_color TEXT NOT NULL DEFAULT '190 90% 50%',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
    ALTER TABLE branding_settings ADD COLUMN IF NOT EXISTS logo_size INTEGER NOT NULL DEFAULT 36;
  `);

  // Znuny integration settings
  await pool.query(`
    CREATE TABLE IF NOT EXISTS znuny_settings (
      id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
      enabled BOOLEAN NOT NULL DEFAULT false,
      base_url TEXT NOT NULL DEFAULT '',
      username TEXT NOT NULL DEFAULT '',
      password TEXT NOT NULL DEFAULT '',
      queue TEXT NOT NULL DEFAULT 'Raw',
      priority TEXT NOT NULL DEFAULT '3 normal',
      ticket_type TEXT NOT NULL DEFAULT 'Unclassified',
      customer_user TEXT NOT NULL DEFAULT '',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `);

  // Insert default znuny settings if empty
  await pool.query(`
    INSERT INTO znuny_settings (enabled, base_url)
    SELECT false, ''
    WHERE NOT EXISTS (SELECT 1 FROM znuny_settings);
  `);

  // Insert default branding if empty
  await pool.query(`
    INSERT INTO branding_settings (app_name, app_subtitle, primary_color, accent_color)
    SELECT 'SecVersions', 'Monitoramento de versões e vulnerabilidades', '160 100% 45%', '190 90% 50%'
    WHERE NOT EXISTS (SELECT 1 FROM branding_settings);
  `);

  // Helper function & triggers
  await pool.query(`
    CREATE OR REPLACE FUNCTION update_updated_at()
    RETURNS TRIGGER AS $$
    BEGIN
      NEW.updated_at = now();
      RETURN NEW;
    END;
    $$ LANGUAGE plpgsql;
  `);

  // Create triggers (idempotent via DO block)
  await pool.query(`
    DO $$
    DECLARE
      tbl TEXT;
      trg TEXT;
    BEGIN
      FOR tbl, trg IN VALUES
        ('users', 'users_updated_at'),
        ('oidc_providers', 'oidc_providers_updated_at'),
        ('tools', 'tools_updated_at'),
        ('tool_versions', 'tool_versions_updated_at'),
        ('branding_settings', 'branding_settings_updated_at')
      LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = trg) THEN
          EXECUTE format(
            'CREATE TRIGGER %I BEFORE UPDATE ON %I FOR EACH ROW EXECUTE FUNCTION update_updated_at()',
            trg, tbl
          );
        END IF;
      END LOOP;
    END $$;
  `);

  // has_role function
  await pool.query(`
    CREATE OR REPLACE FUNCTION has_role(_user_id UUID, _role app_role)
    RETURNS BOOLEAN
    LANGUAGE sql
    STABLE
    AS $$
      SELECT EXISTS (
        SELECT 1 FROM user_roles
        WHERE user_id = _user_id AND role = _role
      )
    $$;
  `);

  schemaEnsured = true;
  console.log("Database schema ensured successfully.");
}

export default pool;
