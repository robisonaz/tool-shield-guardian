
-- Branding settings table (single row)
CREATE TABLE public.branding_settings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  app_name text NOT NULL DEFAULT 'SecVersions',
  app_subtitle text NOT NULL DEFAULT 'Monitoramento de versões e vulnerabilidades',
  logo_url text,
  primary_color text NOT NULL DEFAULT '160 100% 45%',
  accent_color text NOT NULL DEFAULT '190 90% 50%',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.branding_settings ENABLE ROW LEVEL SECURITY;

-- Everyone authenticated can read branding
CREATE POLICY "Anyone can read branding" ON public.branding_settings
  FOR SELECT TO authenticated, anon
  USING (true);

-- Only admins can manage branding  
CREATE POLICY "Admins can manage branding" ON public.branding_settings
  FOR ALL TO authenticated
  USING (public.has_role(auth.uid(), 'admin'))
  WITH CHECK (public.has_role(auth.uid(), 'admin'));

-- Insert default row
INSERT INTO public.branding_settings (app_name, app_subtitle, primary_color, accent_color)
VALUES ('SecVersions', 'Monitoramento de versões e vulnerabilidades', '160 100% 45%', '190 90% 50%');
