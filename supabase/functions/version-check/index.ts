import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const PRODUCT_SLUGS: Record<string, string> = {
  gitlab: "gitlab",
  jenkins: "jenkins",
  kubernetes: "kubernetes",
  nginx: "nginx",
  docker: "docker-engine",
  terraform: "hashicorp-terraform",
  sonarqube: "sonarqube",
  apache: "apache-http-server",
  nodejs: "nodejs",
  python: "python",
  openssl: "openssl",
  postgresql: "postgresql",
  mysql: "mysql",
  redis: "redis",
  elasticsearch: "elasticsearch",
  mongodb: "mongodb",
  grafana: "grafana",
  prometheus: "prometheus",
  tomcat: "apache-tomcat",
  rabbitmq: "rabbitmq",
  vault: "hashicorp-vault",
  consul: "hashicorp-consul",
  ansible: "ansible-core",
  php: "php",
  ruby: "ruby",
  go: "go",
  java: "java",
  dotnet: "dotnet",
};

const emptyResult = { latestVersion: null, latestPatchForCycle: null, eol: null, lts: null, cycleLabel: null, cycles: [] };

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Require authenticated user
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2");
    const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
      global: { headers: { Authorization: authHeader } },
    });
    const { error: claimsError } = await supabase.auth.getClaims(authHeader.replace("Bearer ", ""));
    if (claimsError) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { toolName, version } = await req.json();

    if (!toolName) {
      return new Response(JSON.stringify({ error: "toolName is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const slug = PRODUCT_SLUGS[toolName.toLowerCase().trim()];
    if (!slug) {
      return new Response(JSON.stringify(emptyResult),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const url = `https://endoflife.date/api/${slug}.json`;
    console.log(`Fetching: ${url} for version ${version}`);

    const response = await fetch(url, { headers: { "Accept": "application/json" } });
    if (!response.ok) {
      console.error(`endoflife.date error: ${response.status}`);
      return new Response(JSON.stringify(emptyResult),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const cycles = await response.json();
    const latestVersion = cycles?.[0]?.latest || cycles?.[0]?.cycle || null;

    let latestPatchForCycle: string | null = null;
    let eol: any = null;
    let lts: any = null;
    let cycleLabel: string | null = null;

    if (version && cycles.length > 0) {
      const vParts = version.split(".");

      // Try exact major.minor match across ALL cycles
      for (const c of cycles) {
        const cStr = String(c.cycle);
        const cParts = cStr.split(".");
        if (cParts[0] === vParts[0]) {
          if (cParts.length === 1 || vParts.length === 1 || cParts[1] === vParts[1]) {
            latestPatchForCycle = c.latest || null;
            eol = c.eol ?? null;
            lts = c.lts ?? null;
            cycleLabel = cStr;
            console.log(`Matched cycle ${cStr} -> latest: ${latestPatchForCycle}`);
            break;
          }
        }
      }

      // Fallback: first cycle with same major
      if (!latestPatchForCycle) {
        for (const c of cycles) {
          if (String(c.cycle).split(".")[0] === vParts[0]) {
            latestPatchForCycle = c.latest || null;
            eol = c.eol ?? null;
            lts = c.lts ?? null;
            cycleLabel = String(c.cycle);
            console.log(`Fallback cycle ${cycleLabel} -> latest: ${latestPatchForCycle}`);
            break;
          }
        }
      }
    }

    return new Response(JSON.stringify({
      latestVersion,
      latestPatchForCycle,
      eol,
      lts,
      cycleLabel,
      // Return enough cycles for client-side fallback
      cycles: cycles.slice(0, 30),
    }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });

  } catch (error) {
    console.error("Error:", error);
    return new Response(JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } });
  }
});
