import { createClient, type SupabaseClient } from "@supabase/supabase-js";
import type { Database } from "@/integrations/supabase/types";

let cachedClient: SupabaseClient<Database> | null | undefined;

function getSupabaseConfig() {
  const projectId = import.meta.env.VITE_SUPABASE_PROJECT_ID as string | undefined;
  const supabaseUrl =
    (import.meta.env.VITE_SUPABASE_URL as string | undefined) ||
    (projectId ? `https://${projectId}.supabase.co` : undefined);
  const supabaseKey = import.meta.env.VITE_SUPABASE_PUBLISHABLE_KEY as string | undefined;

  return { supabaseUrl, supabaseKey };
}

export function getBrandingClient() {
  if (cachedClient !== undefined) {
    return cachedClient;
  }

  const { supabaseUrl, supabaseKey } = getSupabaseConfig();

  if (!supabaseUrl || !supabaseKey) {
    console.error("Branding client indisponível: variáveis de ambiente ausentes.");
    cachedClient = null;
    return cachedClient;
  }

  cachedClient = createClient<Database>(supabaseUrl, supabaseKey, {
    auth: {
      persistSession: false,
      autoRefreshToken: false,
    },
  });

  return cachedClient;
}
