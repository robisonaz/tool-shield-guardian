
CREATE TABLE public.tools (
  id UUID NOT NULL DEFAULT gen_random_uuid() PRIMARY KEY,
  user_id UUID NOT NULL,
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
  cves JSONB NOT NULL DEFAULT '[]'::jsonb,
  created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now(),
  updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT now()
);

ALTER TABLE public.tools ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Users can view own tools"
  ON public.tools FOR SELECT
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can insert own tools"
  ON public.tools FOR INSERT
  TO authenticated
  WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can update own tools"
  ON public.tools FOR UPDATE
  TO authenticated
  USING (auth.uid() = user_id);

CREATE POLICY "Users can delete own tools"
  ON public.tools FOR DELETE
  TO authenticated
  USING (auth.uid() = user_id);
