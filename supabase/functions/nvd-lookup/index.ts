import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

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
  // Try CVSS v3.1 first, then v3.0, then v2
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
    const { toolName, version } = await req.json();

    if (!toolName || !version) {
      return new Response(
        JSON.stringify({ error: "toolName and version are required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Build keyword search — combine tool name with version for better results
    const keywordSearch = `${toolName} ${version}`;
    const url = `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(keywordSearch)}&resultsPerPage=20`;

    console.log(`Fetching NVD API: ${url}`);

    const response = await fetch(url, {
      headers: {
        "Accept": "application/json",
      },
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error(`NVD API error [${response.status}]: ${errorText}`);
      
      // NVD rate limits — return empty instead of erroring
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

    // Sort by severity
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    cves.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

    return new Response(
      JSON.stringify({ cves, total: data.totalResults || 0 }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("Error in nvd-lookup:", error);
    return new Response(
      JSON.stringify({ error: error.message || "Internal server error" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
