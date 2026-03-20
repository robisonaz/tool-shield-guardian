-- SecVersions - Pure PostgreSQL Schema
-- Run this against your PostgreSQL instance to set up the database

-- Extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Enum for user roles
DO $$ BEGIN
  CREATE TYPE app_role AS ENUM ('admin', 'user');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

-- Users table (replaces Supabase auth.users)
CREATE TABLE IF NOT EXISTS users (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT, -- NULL for OIDC-only users
  full_name TEXT,
  oidc_provider TEXT, -- which OIDC provider created this user (if any)
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- User roles
CREATE TABLE IF NOT EXISTS user_roles (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  role app_role NOT NULL,
  UNIQUE (user_id, role)
);

-- OIDC providers configuration
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

-- Tools table (move from localStorage to DB)
CREATE TABLE IF NOT EXISTS tools (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  version TEXT NOT NULL,
  source_url TEXT,
  description TEXT,
  latest_version TEXT,
  latest_patch_for_cycle TEXT,
  is_outdated BOOLEAN,
  is_patch_outdated BOOLEAN,
  eol TEXT, -- stored as text, can be 'true', 'false', or a date string
  lts TEXT,
  cycle_label TEXT,
  cves JSONB NOT NULL DEFAULT '[]',
  added_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Refresh tokens for JWT auth
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  token TEXT UNIQUE NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Helper function: check if user has a role
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

-- Indexes
CREATE INDEX IF NOT EXISTS idx_user_roles_user_id ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_tools_user_id ON tools(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token ON refresh_tokens(token);

-- Auto-update updated_at
CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE TRIGGER users_updated_at BEFORE UPDATE ON users
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE OR REPLACE TRIGGER oidc_providers_updated_at BEFORE UPDATE ON oidc_providers
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

CREATE OR REPLACE TRIGGER tools_updated_at BEFORE UPDATE ON tools
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Sub-versions table (multiple installed versions per tool)
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

CREATE INDEX IF NOT EXISTS idx_tool_versions_tool_id ON tool_versions(tool_id);
CREATE INDEX IF NOT EXISTS idx_tool_versions_tool_lookup ON tool_versions(tool_id, version, source_url);

CREATE OR REPLACE TRIGGER tool_versions_updated_at BEFORE UPDATE ON tool_versions
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Branding settings (singleton row)
CREATE TABLE IF NOT EXISTS branding_settings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  app_name TEXT NOT NULL DEFAULT 'SecVersions',
  app_subtitle TEXT NOT NULL DEFAULT 'Monitoramento de versões e vulnerabilidades',
  logo_url TEXT,
  primary_color TEXT NOT NULL DEFAULT '160 100% 45%',
  accent_color TEXT NOT NULL DEFAULT '190 90% 50%',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE OR REPLACE TRIGGER branding_settings_updated_at BEFORE UPDATE ON branding_settings
  FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- Insert default branding if empty
INSERT INTO branding_settings (app_name, app_subtitle, primary_color, accent_color)
SELECT 'SecVersions', 'Monitoramento de versões e vulnerabilidades', '160 100% 45%', '190 90% 50%'
WHERE NOT EXISTS (SELECT 1 FROM branding_settings);
