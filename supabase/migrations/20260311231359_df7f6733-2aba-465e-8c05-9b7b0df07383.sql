
-- Create storage bucket for branding logos
INSERT INTO storage.buckets (id, name, public, file_size_limit, allowed_mime_types)
VALUES ('branding', 'branding', true, 2097152, ARRAY['image/png', 'image/jpeg', 'image/svg+xml', 'image/webp']);

-- Allow anyone to read branding files
CREATE POLICY "Public read branding" ON storage.objects
  FOR SELECT TO public
  USING (bucket_id = 'branding');

-- Only admins can upload branding files
CREATE POLICY "Admins upload branding" ON storage.objects
  FOR INSERT TO authenticated
  WITH CHECK (bucket_id = 'branding' AND public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins update branding" ON storage.objects
  FOR UPDATE TO authenticated
  USING (bucket_id = 'branding' AND public.has_role(auth.uid(), 'admin'));

CREATE POLICY "Admins delete branding" ON storage.objects
  FOR DELETE TO authenticated
  USING (bucket_id = 'branding' AND public.has_role(auth.uid(), 'admin'));
