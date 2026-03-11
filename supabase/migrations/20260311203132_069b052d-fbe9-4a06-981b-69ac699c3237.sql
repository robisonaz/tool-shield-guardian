CREATE TABLE public.tool_versions (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  tool_id uuid NOT NULL REFERENCES public.tools(id) ON DELETE CASCADE,
  version text NOT NULL,
  latest_version text,
  latest_patch_for_cycle text,
  is_outdated boolean,
  is_patch_outdated boolean,
  eol text,
  lts text,
  cycle_label text,
  cves jsonb NOT NULL DEFAULT '[]'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE public.tool_versions ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own tool versions" ON public.tool_versions
  FOR SELECT TO authenticated
  USING (EXISTS (SELECT 1 FROM public.tools WHERE tools.id = tool_versions.tool_id AND tools.user_id = auth.uid()));

CREATE POLICY "Users can insert own tool versions" ON public.tool_versions
  FOR INSERT TO authenticated
  WITH CHECK (EXISTS (SELECT 1 FROM public.tools WHERE tools.id = tool_versions.tool_id AND tools.user_id = auth.uid()));

CREATE POLICY "Users can update own tool versions" ON public.tool_versions
  FOR UPDATE TO authenticated
  USING (EXISTS (SELECT 1 FROM public.tools WHERE tools.id = tool_versions.tool_id AND tools.user_id = auth.uid()));

CREATE POLICY "Users can delete own tool versions" ON public.tool_versions
  FOR DELETE TO authenticated
  USING (EXISTS (SELECT 1 FROM public.tools WHERE tools.id = tool_versions.tool_id AND tools.user_id = auth.uid()));