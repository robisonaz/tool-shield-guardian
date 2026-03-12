
-- Create a secure view that excludes sensitive columns
CREATE OR REPLACE VIEW public.oidc_providers_public AS
SELECT id, display_name, name, issuer_url, client_id, scopes, enabled
FROM public.oidc_providers
WHERE enabled = true;

-- Grant anon access to the view
GRANT SELECT ON public.oidc_providers_public TO anon;

-- Drop the existing anon policy that exposes all columns including client_secret
DROP POLICY IF EXISTS "Anon can read enabled providers" ON public.oidc_providers;
