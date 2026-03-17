import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

// CPE vendor:product mappings for accurate CVE lookups
const CPE_MAP: Record<string, { vendor: string; product: string }> = {
  zabbix: { vendor: "zabbix", product: "zabbix" },
  "zabbix server": { vendor: "zabbix", product: "zabbix" },
  "zabbix agent": { vendor: "zabbix", product: "zabbix" },
  "zabbix proxy": { vendor: "zabbix", product: "zabbix" },
  gitlab: { vendor: "gitlab", product: "gitlab" },
  jenkins: { vendor: "jenkins", product: "jenkins" },
  kubernetes: { vendor: "kubernetes", product: "kubernetes" },
  nginx: { vendor: "f5", product: "nginx" },
  docker: { vendor: "docker", product: "docker" },
  terraform: { vendor: "hashicorp", product: "terraform" },
  sonarqube: { vendor: "sonarsource", product: "sonarqube" },
  apache: { vendor: "apache", product: "http_server" },
  nodejs: { vendor: "nodejs", product: "node.js" },
  python: { vendor: "python", product: "python" },
  openssh: { vendor: "openbsd", product: "openssh" },
  openssl: { vendor: "openssl", product: "openssl" },
  postgresql: { vendor: "postgresql", product: "postgresql" },
  mysql: { vendor: "oracle", product: "mysql" },
  redis: { vendor: "redis", product: "redis" },
  elasticsearch: { vendor: "elastic", product: "elasticsearch" },
  mongodb: { vendor: "mongodb", product: "mongodb" },
  grafana: { vendor: "grafana", product: "grafana" },
  prometheus: { vendor: "prometheus", product: "prometheus" },
  tomcat: { vendor: "apache", product: "tomcat" },
  rabbitmq: { vendor: "vmware", product: "rabbitmq" },
  vault: { vendor: "hashicorp", product: "vault" },
  consul: { vendor: "hashicorp", product: "consul" },
  ansible: { vendor: "redhat", product: "ansible" },
  php: { vendor: "php", product: "php" },
  ruby: { vendor: "ruby-lang", product: "ruby" },
  go: { vendor: "golang", product: "go" },
  java: { vendor: "oracle", product: "jdk" },
  dotnet: { vendor: "microsoft", product: ".net" },
};

interface NvdCve {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  publishedDate: string;
}

function mapCvssToSeverity(score: number): "critical" | "high" | "medium" | "low" {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

function extractSeverity(cve: any): "critical" | "high" | "medium" | "low" {
  const metrics = cve.metrics || {};
  
  const v31 = metrics.cvssMetricV31?.[0]?.cvssData?.baseScore;
  if (v31 != null) return mapCvssToSeverity(v31);

  const v30 = metrics.cvssMetricV30?.[0]?.cvssData?.baseScore;
  if (v30 != null) return mapCvssToSeverity(v30);

  const v2 = metrics.cvssMetricV2?.[0]?.cvssData?.baseScore;
  if (v2 != null) return mapCvssToSeverity(v2);

  return "medium";
}

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
    const { data: { user }, error: userError } = await supabase.auth.getUser();
    if (userError || !user) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { toolName, version } = await req.json();

    if (!toolName || !version) {
      return new Response(
        JSON.stringify({ error: "toolName and version are required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    const toolKey = toolName.toLowerCase().trim();
    const cpeEntry = CPE_MAP[toolKey];
    
    // Normalize version for CPE lookup (e.g. strip OpenSSH portable suffix "p1")
    let cpeVersion = version;
    if (toolKey === "openssh" || toolKey === "openssl") {
      // OpenSSH: "8.9p1" -> "8.9", "9.6p1" -> "9.6"
      // OpenSSL: "3.0.2" stays "3.0.2" (no change needed, but strip letter suffixes like "1.1.1w" -> "1.1.1")
      cpeVersion = version.replace(/p\d+$/i, "");
    }

    let url: string;
    
    if (cpeEntry) {
      // Use virtualMatchString for version range matching (catches CVEs affecting this version)
      const cpeMatch = `cpe:2.3:a:${cpeEntry.vendor}:${cpeEntry.product}:${cpeVersion}`;
      url = `${NVD_API_BASE}?virtualMatchString=${encodeURIComponent(cpeMatch)}&resultsPerPage=50`;
      console.log(`Fetching NVD API (virtualMatchString): ${url}`);
    } else {
      // Fallback to keyword search for unmapped tools
      const keywordSearch = `${toolName} ${version}`;
      url = `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(keywordSearch)}&resultsPerPage=20`;
      console.log(`Fetching NVD API (keyword): ${url}`);
    }

    const response = await fetch(url, {
      headers: { "Accept": "application/json" },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`NVD API error [${response.status}]: ${errorText}`);
      
      if (response.status === 403 || response.status === 429) {
        return new Response(
          JSON.stringify({ cves: [], rateLimited: true }),
          { headers: { ...corsHeaders, "Content-Type": "application/json" } }
        );
      }
      
      throw new Error(`NVD API returned ${response.status}`);
    }

    const data = await response.json();
    const vulnerabilities = data.vulnerabilities || [];

    const cves: NvdCve[] = vulnerabilities.map((vuln: any) => {
      const cve = vuln.cve;
      const description =
        cve.descriptions?.find((d: any) => d.lang === "en")?.value ||
        cve.descriptions?.[0]?.value ||
        "No description available";

      return {
        id: cve.id,
        severity: extractSeverity(cve),
        description: description.length > 200 ? description.substring(0, 200) + "..." : description,
        publishedDate: cve.published?.split("T")[0] || "Unknown",
      };
    });

    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    cves.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    return new Response(
      JSON.stringify({ cves, total: data.totalResults || 0 }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("Error in nvd-lookup:", error);
    return new Response(
      JSON.stringify({ error: "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
