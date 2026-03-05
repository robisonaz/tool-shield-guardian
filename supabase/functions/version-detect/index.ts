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

// Headers that may reveal tool/version (non-proxy tools only)
const VERSION_HEADERS = [
  { header: "x-jenkins", tool: "Jenkins" },
  { header: "x-gitlab-meta", tool: "GitLab" },
];

// Proxy/generic headers — record but don't stop searching
const PROXY_HEADERS = ["server", "x-powered-by"];

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

    let detectedTool: string | null = null;
    let detectedVersion: string | null = null;
    let proxyTool: string | null = null;
    let proxyVersion: string | null = null;

    // Check definitive headers (Jenkins, GitLab) — these are the real app
    for (const vh of VERSION_HEADERS) {
      const headerVal = response.headers.get(vh.header);
      if (headerVal) {
        console.log(`Header ${vh.header}: ${headerVal}`);
        detectedTool = vh.tool;
        const versionMatch = headerVal.match(/(\d+\.\d+(?:\.\d+)?)/);
        if (versionMatch) detectedVersion = versionMatch[1];
        break;
      }
    }

    // Record proxy headers as fallback
    for (const ph of PROXY_HEADERS) {
      const headerVal = response.headers.get(ph);
      if (headerVal) {
        console.log(`Proxy header ${ph}: ${headerVal}`);
        const versionMatch = headerVal.match(/(\d+\.\d+(?:\.\d+)?)/);
        if (versionMatch) {
          proxyVersion = versionMatch[1];
          if (/nginx/i.test(headerVal)) proxyTool = "Nginx";
          else if (/apache/i.test(headerVal)) proxyTool = "Apache";
        }
      }
    }

    // Always parse HTML to find the actual application behind the proxy
    const html = await response.text();

    if (!detectedTool || !detectedVersion) {
      for (const dp of DETECTION_PATTERNS) {
        for (const pattern of dp.patterns) {
          const match = html.match(pattern);
          if (match) {
            detectedTool = dp.tool;
            if (match[1]) detectedVersion = match[1];
            break;
          }
        }
        if (detectedTool && detectedVersion) break;
      }

      // If tool found but no version, try generic nearby version
      if (detectedTool && !detectedVersion) {
        const toolRegex = new RegExp(detectedTool + "[\\s\\S]{0,50}?(\\d+\\.\\d+(?:\\.\\d+)?)", "i");
        const genericMatch = html.match(toolRegex);
        if (genericMatch?.[1]) detectedVersion = genericMatch[1];
      }
    }

    // If nothing found in HTML, fall back to proxy info
    if (!detectedTool && proxyTool) {
      detectedTool = proxyTool;
      detectedVersion = proxyVersion;
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
