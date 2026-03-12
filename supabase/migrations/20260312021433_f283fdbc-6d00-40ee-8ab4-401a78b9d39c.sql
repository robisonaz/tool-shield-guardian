
-- Recreate view with SECURITY INVOKER to avoid security definer warning
DROP VIEW IF EXISTS public.oidc_providers_public;

CREATE VIEW public.oidc_providers_public
WITH (security_invoker = true) AS
SELECT id, display_name, name, issuer_url, client_id, scopes, enabled
FROM public.oidc_providers
WHERE enabled = true;

-- Grant anon access to the view
GRANT SELECT ON public.oidc_providers_public TO anon;

-- Need a permissive policy for anon to read through the view (since RLS is on)
CREATE POLICY "Anon can read enabled providers via view"
ON public.oidc_providers
FOR SELECT
TO anon
USING (enabled = true);
