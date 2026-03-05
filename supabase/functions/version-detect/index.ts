import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers":
    "authorization, x-client-info, apikey, content-type, x-supabase-client-platform, x-supabase-client-platform-version, x-supabase-client-runtime, x-supabase-client-runtime-version",
};

// Patterns to detect tool name and version from HTML/headers
const DETECTION_PATTERNS: { tool: string; patterns: RegExp[] }[] = [
  {
    tool: "Zabbix",
    patterns: [
      /Zabbix\s+(?:SIA\s+)?(?:v?(\d+\.\d+(?:\.\d+)?))/i,
      /zabbix[_-]?version["\s:=]+["\s]*(\d+\.\d+(?:\.\d+)?)/i,
      /<title>.*Zabbix.*<\/title>/i,
    ],
  },
  {
    tool: "Grafana",
    patterns: [
      /Grafana\s+v?(\d+\.\d+(?:\.\d+)?)/i,
      /"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/i,
    ],
  },
  {
    tool: "GitLab",
    patterns: [
      /gitlab[_-]?version["\s:=]+(\d+\.\d+(?:\.\d+)?)/i,
      /GitLab\s+(?:Community|Enterprise)?\s*Edition\s+(\d+\.\d+(?:\.\d+)?)/i,
      /gon\.version\s*=\s*["'](\d+\.\d+(?:\.\d+)?)/i,
    ],
  },
  {
    tool: "Jenkins",
    patterns: [
      /Jenkins\s+ver\.\s*(\d+\.\d+(?:\.\d+)?)/i,
      /X-Jenkins:\s*(\d+\.\d+(?:\.\d+)?)/i,
      /"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/i,
    ],
  },
  {
    tool: "SonarQube",
    patterns: [
      /SonarQube\s+(\d+\.\d+(?:\.\d+)?)/i,
      /sonar\.version["\s:=]+(\d+\.\d+(?:\.\d+)?)/i,
    ],
  },
  {
    tool: "Prometheus",
    patterns: [
      /Prometheus\s+v?(\d+\.\d+(?:\.\d+)?)/i,
    ],
  },
];

// Headers that may reveal tool/version
const VERSION_HEADERS = [
  { header: "x-jenkins", tool: "Jenkins" },
  { header: "server", tool: null }, // generic
  { header: "x-powered-by", tool: null },
  { header: "x-gitlab-meta", tool: "GitLab" },
];

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const { url } = await req.json();

    if (!url) {
      return new Response(
        JSON.stringify({ success: false, error: "URL is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = `https://${targetUrl}`;
    }

    console.log(`Detecting version from: ${targetUrl}`);

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    let response: Response;
    try {
      response = await fetch(targetUrl, {
        signal: controller.signal,
        headers: {
          "User-Agent": "Mozilla/5.0 (compatible; SecVersions/1.0)",
          "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        },
        redirect: "follow",
      });
    } catch (fetchErr) {
      clearTimeout(timeout);
      console.error("Fetch error:", fetchErr);
      return new Response(
        JSON.stringify({ success: false, error: "Não foi possível acessar a URL. Verifique se está acessível." }),
        { status: 200, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }
    clearTimeout(timeout);

    // Check headers first
    let detectedTool: string | null = null;
    let detectedVersion: string | null = null;

    for (const vh of VERSION_HEADERS) {
      const headerVal = response.headers.get(vh.header);
      if (headerVal) {
        console.log(`Header ${vh.header}: ${headerVal}`);
        if (vh.tool) {
          detectedTool = vh.tool;
        }
        const versionMatch = headerVal.match(/(\d+\.\d+(?:\.\d+)?)/);
        if (versionMatch) {
          detectedVersion = versionMatch[1];
          if (vh.tool) detectedTool = vh.tool;
          if (!detectedTool) {
            // Try to identify from header value
            if (/jenkins/i.test(headerVal)) detectedTool = "Jenkins";
            else if (/nginx/i.test(headerVal)) detectedTool = "Nginx";
            else if (/apache/i.test(headerVal)) detectedTool = "Apache";
          }
          break;
        }
      }
    }

    // Parse HTML body for version info
    if (!detectedVersion) {
      const html = await response.text();

      for (const dp of DETECTION_PATTERNS) {
        for (const pattern of dp.patterns) {
          const match = html.match(pattern);
          if (match) {
            detectedTool = dp.tool;
            if (match[1]) {
              detectedVersion = match[1];
            }
            break;
          }
        }
        if (detectedVersion) break;
      }

      // If we found the tool but not version, try generic version pattern near tool name
      if (detectedTool && !detectedVersion) {
        const toolRegex = new RegExp(detectedTool + "[\\s\\S]{0,50}?(\\d+\\.\\d+(?:\\.\\d+)?)", "i");
        const genericMatch = html.match(toolRegex);
        if (genericMatch?.[1]) {
          detectedVersion = genericMatch[1];
        }
      }
    }

    console.log(`Detected: tool=${detectedTool}, version=${detectedVersion}`);

    return new Response(
      JSON.stringify({
        success: true,
        tool: detectedTool,
        version: detectedVersion,
        message: detectedTool
          ? detectedVersion
            ? `Detectado: ${detectedTool} ${detectedVersion}`
            : `Ferramenta detectada (${detectedTool}), mas não foi possível identificar a versão.`
          : "Não foi possível detectar a ferramenta/versão automaticamente.",
      }),
      { headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  } catch (error) {
    console.error("Error in version-detect:", error);
    return new Response(
      JSON.stringify({ success: false, error: error.message || "Erro interno" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
