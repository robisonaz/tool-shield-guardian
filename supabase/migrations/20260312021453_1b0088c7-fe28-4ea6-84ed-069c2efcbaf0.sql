
-- Remove the anon policy we just added (it re-exposes all columns via direct table access)
DROP POLICY IF EXISTS "Anon can read enabled providers via view" ON public.oidc_providers;

-- Drop the view approach entirely
DROP VIEW IF EXISTS public.oidc_providers_public;

-- Create a SECURITY DEFINER function that returns only safe columns
CREATE OR REPLACE FUNCTION public.get_public_providers()
RETURNS TABLE(
  id uuid,
  display_name text,
  name text,
  issuer_url text,
  client_id text,
  scopes text
)
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
  SELECT id, display_name, name, issuer_url, client_id, scopes
  FROM public.oidc_providers
  WHERE enabled = true;
$$;
