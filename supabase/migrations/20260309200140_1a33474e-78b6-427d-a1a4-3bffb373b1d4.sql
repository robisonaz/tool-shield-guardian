CREATE POLICY "Anon can read enabled providers"
ON public.oidc_providers
FOR SELECT TO anon
USING (enabled = true);