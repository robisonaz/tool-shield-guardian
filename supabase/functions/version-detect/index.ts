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

/**
 * Validates that a URL hostname does not resolve to a private/internal IP range.
 * Prevents SSRF attacks targeting cloud metadata, internal services, etc.
 */
function isPrivateOrReservedIP(ip: string): boolean {
  // IPv4 private/reserved ranges
  const parts = ip.split(".").map(Number);
  if (parts.length === 4 && parts.every((p) => p >= 0 && p <= 255)) {
    // 127.0.0.0/8 (loopback)
    if (parts[0] === 127) return true;
    // 10.0.0.0/8
    if (parts[0] === 10) return true;
    // 172.16.0.0/12
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    // 192.168.0.0/16
    if (parts[0] === 192 && parts[1] === 168) return true;
    // 169.254.0.0/16 (link-local / cloud metadata)
    if (parts[0] === 169 && parts[1] === 254) return true;
    // 0.0.0.0
    if (parts.every((p) => p === 0)) return true;
  }

  // IPv6 loopback and private
  const normalized = ip.toLowerCase();
  if (normalized === "::1" || normalized === "0:0:0:0:0:0:0:1") return true;
  if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
  if (normalized.startsWith("fe80")) return true;

  return false;
}

async function validateUrl(urlStr: string): Promise<string> {
  const parsed = new URL(urlStr);

  // Only allow http/https
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error("Only http and https protocols are allowed.");
  }

  const hostname = parsed.hostname;

  // Block obvious localhost/metadata hostnames
  const blockedHostnames = [
    "localhost",
    "metadata.google.internal",
    "metadata.google.com",
  ];
  if (blockedHostnames.includes(hostname.toLowerCase())) {
    throw new Error("Access to internal/metadata hosts is not allowed.");
  }

  // Resolve hostname and check IP
  try {
    const addrs = await Deno.resolveDns(hostname, "A");
    for (const addr of addrs) {
      if (isPrivateOrReservedIP(addr)) {
        throw new Error("Access to private/internal IP addresses is not allowed.");
      }
    }
  } catch (err) {
    if (err instanceof Error && err.message.includes("not allowed")) {
      throw err;
    }
    // DNS resolution may fail for valid hosts in some environments; 
    // allow the fetch to proceed but disable redirects as a safeguard
  }

  return urlStr;
}

serve(async (req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    // Require authenticated user
    const authHeader = req.headers.get("Authorization");
    if (!authHeader?.startsWith("Bearer ")) {
      return new Response(JSON.stringify({ success: false, error: "Unauthorized" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }
    const { createClient } = await import("https://esm.sh/@supabase/supabase-js@2");
    const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, {
      global: { headers: { Authorization: authHeader } },
    });
    const { error: claimsError } = await supabase.auth.getClaims(authHeader.replace("Bearer ", ""));
    if (claimsError) {
      return new Response(JSON.stringify({ success: false, error: "Unauthorized" }), { status: 401, headers: { ...corsHeaders, "Content-Type": "application/json" } });
    }

    const { url } = await req.json();

    if (!url || typeof url !== "string") {
      return new Response(
        JSON.stringify({ success: false, error: "URL is required" }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    // Validate URL length to prevent abuse
    if (url.length > 2048) {
      return new Response(
        JSON.stringify({ success: false, error: "URL is too long." }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
    }

    let targetUrl = url.trim();
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = `https://${targetUrl}`;
    }

    // Validate against SSRF
    try {
      await validateUrl(targetUrl);
    } catch (validationErr) {
      return new Response(
        JSON.stringify({ success: false, error: (validationErr as Error).message }),
        { status: 400, headers: { ...corsHeaders, "Content-Type": "application/json" } }
      );
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
        redirect: "manual", // Don't follow redirects to prevent SSRF via redirect
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

    // Limit HTML size to prevent memory abuse
    const htmlToScan = html.length > 500_000 ? html.substring(0, 500_000) : html;

    if (!detectedTool || !detectedVersion) {
      for (const dp of DETECTION_PATTERNS) {
        for (const pattern of dp.patterns) {
          const match = htmlToScan.match(pattern);
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
        const genericMatch = htmlToScan.match(toolRegex);
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
      JSON.stringify({ success: false, error: "Erro interno" }),
      { status: 500, headers: { ...corsHeaders, "Content-Type": "application/json" } }
    );
  }
});
