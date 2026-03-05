import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

// Maps user-friendly names to endoflife.date product slugs
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

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { toolName } = await req.json();

    if (!toolName) {
      return new Response(
        JSON.stringify({ error: "toolName is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const key = toolName.toLowerCase().trim();
    const slug = PRODUCT_SLUGS[key];

    if (!slug) {
      return new Response(
        JSON.stringify({ latestVersion: null, cycles: [] }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const url = `https://endoflife.date/api/${slug}.json`;
    console.log(`Fetching endoflife.date: ${url}`);

    const response = await fetch(url, {
      headers: { "Accept": "application/json" },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`endoflife.date error [${response.status}]: ${errorText}`);
      return new Response(
        JSON.stringify({ latestVersion: null, cycles: [] }),
        { headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const cycles = await response.json();

    // The first cycle is the latest
    const latestVersion = cycles?.[0]?.latest || cycles?.[0]?.cycle || null;

    return new Response(
      JSON.stringify({ latestVersion, cycles: cycles.slice(0, 5) }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("Error in version-check:", error);
    return new Response(
      JSON.stringify({ error: error.message || "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
