import { createContext, useContext, useState, useEffect, ReactNode } from "react";
import { getBrandingClient } from "@/lib/branding-client";

export interface BrandingSettings {
  id: string;
  app_name: string;
  app_subtitle: string;
  logo_url: string | null;
  primary_color: string;
  accent_color: string;
}

const DEFAULT_BRANDING: BrandingSettings = {
  id: "",
  app_name: "SecVersions",
  app_subtitle: "Monitoramento de versões e vulnerabilidades",
  logo_url: null,
  primary_color: "160 100% 45%",
  accent_color: "190 90% 50%",
};

interface BrandingContextType {
  branding: BrandingSettings;
  loading: boolean;
  reload: () => Promise<void>;
}

const BrandingContext = createContext<BrandingContextType>({
  branding: DEFAULT_BRANDING,
  loading: true,
  reload: async () => {},
});

function applyColors(primary: string, accent: string) {
  const root = document.documentElement;
  root.style.setProperty("--primary", primary);
  root.style.setProperty("--ring", primary);
  root.style.setProperty("--sidebar-primary", primary);
  root.style.setProperty("--sidebar-ring", primary);
  root.style.setProperty("--accent", accent);

  // Update glow variables
  root.style.setProperty("--glow-primary", `0 0 20px hsl(${primary} / 0.3)`);
  root.style.setProperty("--glow-accent", `0 0 20px hsl(${accent} / 0.3)`);
}

export function BrandingProvider({ children }: { children: ReactNode }) {
  const [branding, setBranding] = useState<BrandingSettings>(DEFAULT_BRANDING);
  const [loading, setLoading] = useState(true);

  const reload = async () => {
    const client = getBrandingClient();
    if (!client) {
      setLoading(false);
      return;
    }

    try {
      const { data, error } = await client
        .from("branding_settings")
        .select("*")
        .limit(1)
        .single();

      if (!error && data) {
        const b: BrandingSettings = {
          id: data.id,
          app_name: data.app_name,
          app_subtitle: data.app_subtitle,
          logo_url: data.logo_url,
          primary_color: data.primary_color,
          accent_color: data.accent_color,
        };
        setBranding(b);
        applyColors(b.primary_color, b.accent_color);
      }
    } catch (err) {
      console.error("Failed to load branding:", err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    reload();
  }, []);

  return (
    <BrandingContext.Provider value={{ branding, loading, reload }}>
      {children}
    </BrandingContext.Provider>
  );
}

export function useBranding() {
  return useContext(BrandingContext);
}

