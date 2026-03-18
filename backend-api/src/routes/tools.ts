import { Router } from "express";
import { requireAuth } from "../middleware/auth.js";
import pool from "../config/database.js";

const router = Router();

const NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

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
  keycloak: { vendor: "redhat", product: "keycloak" },
  jumpserver: { vendor: "fit2cloud", product: "jumpserver" },
  foreman: { vendor: "theforeman", product: "foreman" },
  puppet: { vendor: "puppet", product: "puppet" },
  "puppet server": { vendor: "puppet", product: "puppet" },
  "puppet agent": { vendor: "puppet", product: "puppet" },
};

function normalizeVersionForNvd(toolKey: string, version: string) {
  const trimmedVersion = version.trim();

  if (toolKey === "openssh") {
    const match = trimmedVersion.match(/(\d+\.\d+(?:\.\d+)?)(?:p\d+)?/i);
    return match?.[1] || trimmedVersion.replace(/p\d+$/i, "").trim();
  }

  if (toolKey === "openssl") {
    const match = trimmedVersion.match(/(\d+\.\d+(?:\.\d+)?)/);
    return match?.[1] || trimmedVersion.replace(/[a-z]+$/i, "").trim();
  }

  return trimmedVersion;
}

function buildCpeMatch(vendor: string, product: string, version: string) {
  return `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
}

function getCpeCandidates(toolKey: string) {
  const primary = CPE_MAP[toolKey];
  if (!primary) return [];

  if (toolKey === "openssh") {
    return [
      primary,
      { vendor: "openssh", product: "openssh" },
    ];
  }

  return [primary];
}

function buildNvdLookupUrls(toolName: string, toolKey: string, version: string) {
  const trimmedVersion = version.trim();
  const normalizedVersion = normalizeVersionForNvd(toolKey, trimmedVersion);
  const versionCandidates = Array.from(new Set([trimmedVersion, normalizedVersion].filter(Boolean)));
  const urls: string[] = [];

  for (const cpeEntry of getCpeCandidates(toolKey)) {
    for (const versionCandidate of versionCandidates) {
      const cpeMatch = buildCpeMatch(cpeEntry.vendor, cpeEntry.product, versionCandidate);
      urls.push(`${NVD_API_BASE}?virtualMatchString=${encodeURIComponent(cpeMatch)}&resultsPerPage=50`);
    }
  }

  const keywordCandidates = Array.from(new Set([
    `${toolName} ${trimmedVersion}`.trim(),
    normalizedVersion !== trimmedVersion ? `${toolName} ${normalizedVersion}`.trim() : "",
  ].filter(Boolean)));

  for (const keywordSearch of keywordCandidates) {
    urls.push(`${NVD_API_BASE}?keywordSearch=${encodeURIComponent(keywordSearch)}&resultsPerPage=50`);
  }

  return urls;
}

async function fetchNvdResponse(url: string) {
  const response = await fetch(url, { headers: { Accept: "application/json" } });

  if (!response.ok) {
    if (response.status === 403 || response.status === 429) {
      return { data: null, rateLimited: true };
    }

    throw new Error(`NVD API returned ${response.status}`);
  }

  const data = await response.json();
  return { data, rateLimited: false };
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

// NVD Lookup
router.post("/nvd-lookup", requireAuth, async (req, res) => {
  try {
    const { toolName, version } = req.body;
    if (!toolName || !version) return res.status(400).json({ error: "toolName and version required" });

    const toolKey = toolName.toLowerCase().trim();
    const lookupUrls = buildNvdLookupUrls(toolName, toolKey, version);

    let data: any = null;
    let rateLimited = false;

    for (const url of lookupUrls) {
      console.log(`[NVD] trying lookup for ${toolName} ${version}: ${url}`);
      const result = await fetchNvdResponse(url);

      if (result.rateLimited) {
        rateLimited = true;
        continue;
      }

      if ((result.data?.totalResults || 0) > 0) {
        data = result.data;
        break;
      }

      if (!data) {
        data = result.data;
      }
    }

    if (!data && rateLimited) {
      return res.json({ cves: [], rateLimited: true });
    }

    const vulnerabilities = data?.vulnerabilities || [];

    const cves = vulnerabilities.map((vuln: any) => {
      const cve = vuln.cve;
      const description = cve.descriptions?.find((d: any) => d.lang === "en")?.value
        || cve.descriptions?.[0]?.value || "No description available";
      return {
        id: cve.id,
        severity: extractSeverity(cve),
        description: description.length > 200 ? description.substring(0, 200) + "..." : description,
        publishedDate: cve.published?.split("T")[0] || "Unknown",
      };
    });

    const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
    cves.sort((a: any, b: any) => severityOrder[a.severity] - severityOrder[b.severity]);

    res.json({ cves, total: data?.totalResults || 0 });
  } catch (err) {
    console.error("NVD lookup error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Version detect from URL
const DETECTION_PATTERNS: { tool: string; patterns: RegExp[] }[] = [
  { tool: "Zabbix", patterns: [
    /Zabbix\s+(?:SIA\s+)?(?:v?(\d+\.\d+(?:\.\d+)?))/i,
    /zabbix[_-]?version["\s:=]+["\s]*(\d+\.\d+(?:\.\d+)?)/i,
    /<title>[^<]*Zabbix[^<]*<\/title>/i,
    /zabbix\.php/i,
    /class="zabbix/i,
    /name="zbx_sessionid"/i,
  ]},
  { tool: "Grafana", patterns: [
    /Grafana\s+v?(\d+\.\d+(?:\.\d+)?)/i,
    /"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/i,
    /<title>[^<]*Grafana[^<]*<\/title>/i,
    /grafana-app/i,
    /window\.grafanaBootData/i,
    /public\/build\/grafana/i,
  ]},
  { tool: "GitLab", patterns: [
    /gitlab[_-]?version["\s:=]+(\d+\.\d+(?:\.\d+)?)/i,
    /GitLab\s+(?:Community|Enterprise)?\s*Edition\s+(\d+\.\d+(?:\.\d+)?)/i,
    /gon\.version\s*=\s*["'](\d+\.\d+(?:\.\d+)?)/i,
    /data-qa-selector="version_badge"[^>]*>v?(\d+\.\d+(?:\.\d+)?)/i,
    /class="version"[^>]*>v?(\d+\.\d+(?:\.\d+)?)/i,
    /<title>[^<]*GitLab[^<]*<\/title>/i,
    /content="GitLab"/i,
    /gitlab-org/i,
    /assets\/webpack\//i,
    /\/users\/sign_in/i,
  ]},
  { tool: "Jenkins", patterns: [
    /Jenkins\s+ver\.\s*(\d+\.\d+(?:\.\d+)?)/i,
    /X-Jenkins:\s*(\d+\.\d+(?:\.\d+)?)/i,
    /<title>[^<]*Jenkins[^<]*<\/title>/i,
    /jenkins\.js/i,
    /id="jenkins"/i,
  ]},
  { tool: "SonarQube", patterns: [
    /SonarQube\s+(\d+\.\d+(?:\.\d+)?)/i,
    /<title>[^<]*SonarQube[^<]*<\/title>/i,
    /sonar\.version/i,
    /\/static\/sonarqube/i,
  ]},
  { tool: "Prometheus", patterns: [
    /Prometheus\s+v?(\d+\.\d+(?:\.\d+)?)/i,
    /<title>[^<]*Prometheus[^<]*<\/title>/i,
  ]},
  { tool: "Foreman", patterns: [
    /foreman-react-component/i,
    /<title>[^<]*Foreman[^<]*<\/title>/i,
    /\/users\/login.*foreman/i,
    /class="pf-m-redhat-font"/i,
  ]},
  { tool: "Rancher", patterns: [
    /<title>[^<]*Rancher[^<]*<\/title>/i,
    /rancher\.min\.js/i,
  ]},
  { tool: "AWX", patterns: [
    /<title>[^<]*AWX[^<]*<\/title>/i,
    /awx-app/i,
  ]},
  { tool: "Nexus", patterns: [
    /<title>[^<]*Nexus[^<]*<\/title>/i,
    /nexus-ui/i,
    /Sonatype Nexus/i,
  ]},
  { tool: "Harbor", patterns: [
    /<title>[^<]*Harbor[^<]*<\/title>/i,
    /harbor-app/i,
  ]},
  { tool: "Keycloak", patterns: [
    /<title>[^<]*Keycloak[^<]*<\/title>/i,
    /keycloak\.js/i,
    /\/auth\/realms\//i,
    /\/realms\//i,
    /kc-logo/i,
    /keycloak-theme/i,
    /login-actions\/authenticate/i,
    /powered by keycloak/i,
    /id="kc-/i,
  ]},
  { tool: "MinIO", patterns: [
    /<title>[^<]*MinIO[^<]*<\/title>/i,
    /minio-app/i,
  ]},
  { tool: "Portainer", patterns: [
    /<title>[^<]*Portainer[^<]*<\/title>/i,
    /portainer\.js/i,
  ]},
  { tool: "JumpServer", patterns: [
    /<title>[^<]*JumpServer[^<]*<\/title>/i,
    /<title>[^<]*Jump\s*Server[^<]*<\/title>/i,
    /jumpserver/i,
    /\/api\/v1\/authentication/i,
    /\/core\/auth\/login/i,
    /\/luna\//i,
    /\/lina\//i,
    /\/koko\//i,
    /static\/img\/login_image/i,
    /fit2cloud/i,
  ]},
];

// Known API endpoints that may reveal version
// Special fetch for APIs that need POST (e.g., Zabbix JSON-RPC)
async function tryPostFetch(url: string, body: any, timeoutMs = 5000): Promise<{ body: string; headers: Headers } | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      method: "POST",
      signal: controller.signal,
      headers: { "Content-Type": "application/json", "User-Agent": "Mozilla/5.0 (compatible; SecVersions/1.0)" },
      body: JSON.stringify(body),
      redirect: "follow",
    });
    clearTimeout(timeout);
    const text = await resp.text();
    return { body: text.substring(0, 500_000), headers: resp.headers };
  } catch {
    clearTimeout(timeout);
    return null;
  }
}

const KNOWN_API_ENDPOINTS: { tool: string; probe: (baseUrl: string) => Promise<string | null> }[] = [
  {
    tool: "Zabbix",
    probe: async (baseUrl) => {
      // Zabbix JSON-RPC: apiinfo.version doesn't require auth
      const result = await tryPostFetch(`${baseUrl}/api_jsonrpc.php`, {
        jsonrpc: "2.0",
        method: "apiinfo.version",
        params: [],
        id: 1,
      });
      if (result) {
        try {
          const json = JSON.parse(result.body);
          if (json.result) {
            const m = json.result.match(/(\d+\.\d+(?:\.\d+)?)/);
            return m ? m[1] : null;
          }
        } catch { /* not JSON */ }
      }
      return null;
    },
  },
  {
    tool: "Grafana",
    probe: async (baseUrl) => {
      const result = await tryFetch(`${baseUrl}/api/health`);
      if (result) {
        const m = result.body.match(/"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/);
        if (m) return m[1];
      }
      const result2 = await tryFetch(`${baseUrl}/api/frontend/settings`);
      if (result2) {
        const m = result2.body.match(/"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/);
        if (m) return m[1];
      }
      return null;
    },
  },
  {
    tool: "GitLab",
    probe: async (baseUrl) => {
      // Try unauthenticated API first
      const result = await tryFetch(`${baseUrl}/api/v4/version`);
      if (result) {
        const m = result.body.match(/"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/);
        if (m) return m[1];
      }
      // Try /help page which shows version for logged-out users on many instances
      const helpResult = await tryFetch(`${baseUrl}/help`);
      if (helpResult) {
        const m = helpResult.body.match(/GitLab\s+(?:Community|Enterprise)\s+Edition\s+(\d+\.\d+(?:\.\d+)?)/i)
          || helpResult.body.match(/v?(\d+\.\d+\.\d+)(?:-(?:ce|ee))?/i);
        if (m) return m[1];
      }
      // Try login page for version in footer/meta
      const loginResult = await tryFetch(`${baseUrl}/users/sign_in`);
      if (loginResult) {
        const m = loginResult.body.match(/GitLab\s+(?:Community|Enterprise)\s+Edition\s+(\d+\.\d+(?:\.\d+)?)/i)
          || loginResult.body.match(/gon\.version\s*=\s*["'](\d+\.\d+(?:\.\d+)?)/i)
          || loginResult.body.match(/data-qa-selector="version_badge"[^>]*>v?(\d+\.\d+(?:\.\d+)?)/i)
          || loginResult.body.match(/class="version"[^>]*>v?(\d+\.\d+(?:\.\d+)?)/i);
        if (m) return m[1];
      }
      return null;
    },
  },
  {
    tool: "Jenkins",
    probe: async (baseUrl) => {
      const result = await tryFetch(`${baseUrl}/api/json`);
      if (result) {
        const xj = result.headers.get("x-jenkins");
        if (xj) {
          const m = xj.match(/(\d+\.\d+(?:\.\d+)?)/);
          if (m) return m[1];
        }
      }
      return null;
    },
  },
  {
    tool: "SonarQube",
    probe: async (baseUrl) => {
      for (const path of ["/api/system/status", "/api/server/version"]) {
        const result = await tryFetch(`${baseUrl}${path}`);
        if (result) {
          const m = result.body.match(/"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"|^(\d+\.\d+(?:\.\d+)?)/);
          if (m) return m[1] || m[2];
        }
      }
      return null;
    },
  },
  {
    tool: "Nexus",
    probe: async (baseUrl) => {
      const result = await tryFetch(`${baseUrl}/service/rest/v1/status`);
      if (result) {
        const m = result.body.match(/"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/);
        if (m) return m[1];
      }
      return null;
    },
  },
  {
    tool: "Portainer",
    probe: async (baseUrl) => {
      const result = await tryFetch(`${baseUrl}/api/status`);
      if (result) {
        const m = result.body.match(/"Version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/);
        if (m) return m[1];
      }
      return null;
    },
  },
  {
    tool: "Keycloak",
    probe: async (baseUrl) => {
      // Try multiple known Keycloak endpoints
      // Keycloak 17+ (Quarkus) uses /realms/master, older uses /auth/realms/master
      const paths = [
        "/realms/master/.well-known/openid-configuration",
        "/auth/realms/master/.well-known/openid-configuration",
        "/realms/master",
        "/auth/realms/master",
      ];
      for (const path of paths) {
        const result = await tryFetch(`${baseUrl}${path}`);
        if (result) {
          // The well-known endpoint doesn't always include version, but confirms Keycloak
          // Check for version in response headers or body
          const serverHeader = result.headers.get("server") || "";
          const poweredBy = result.headers.get("x-powered-by") || "";
          
          // Check headers for version
          for (const h of [serverHeader, poweredBy]) {
            const m = h.match(/[Kk]eycloak[\/\s]+v?(\d+\.\d+(?:\.\d+)?)/);
            if (m) return m[1];
          }
        }
      }

      // Try admin API (usually requires auth but some expose version)
      const infoResult = await tryFetch(`${baseUrl}/auth/admin/serverinfo`);
      if (infoResult) {
        const m = infoResult.body.match(/"systemInfo"[^}]*"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/s)
          || infoResult.body.match(/"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/);
        if (m) return m[1];
      }

      // Try the main page or login page for version in HTML
      for (const path of ["", "/auth", "/auth/admin/master/console"]) {
        const result = await tryFetch(`${baseUrl}${path}`);
        if (result) {
          const m = result.body.match(/Keycloak\s+v?(\d+\.\d+(?:\.\d+)?)/i)
            || result.body.match(/"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/i)
            || result.body.match(/keycloak-theme[\/\-](\d+\.\d+(?:\.\d+)?)/i);
          if (m) return m[1];
        }
      }

      return null;
    },
  },
  {
    tool: "JumpServer",
    probe: async (baseUrl) => {
      // Try JumpServer API endpoints
      for (const path of [
        "/api/v1/health/",
        "/api/health/",
        "/api/v1/settings/public/",
        "/core/auth/login/",
        "/api/v1/authentication/connection-token/",
      ]) {
        const result = await tryFetch(`${baseUrl}${path}`);
        if (result) {
          const m = result.body.match(/"version"\s*:\s*"v?(\d+\.\d+(?:\.\d+)?)"/i)
            || result.body.match(/"CURRENT_VERSION"\s*:\s*"v?(\d+\.\d+(?:\.\d+)?)"/i)
            || result.body.match(/"current_version"\s*:\s*"v?(\d+\.\d+(?:\.\d+)?)"/i);
          if (m) return m[1];
          // If the endpoint responds, it's likely JumpServer even without version
          // Check for JumpServer-specific headers
          const xApp = result.headers.get("x-jumpserver-version") || result.headers.get("server") || "";
          const mh = xApp.match(/JumpServer[\/\s]+v?(\d+\.\d+(?:\.\d+)?)/i);
          if (mh) return mh[1];
        }
      }
      // Try main page for version in HTML/JS
      const mainResult = await tryFetch(`${baseUrl}/`);
      if (mainResult) {
        const m = mainResult.body.match(/JumpServer\s+v?(\d+\.\d+(?:\.\d+)?)/i)
          || mainResult.body.match(/"version"\s*:\s*"v?(\d+\.\d+(?:\.\d+)?)"/i)
          || mainResult.body.match(/static\/js\/[^"]*?(\d+\.\d+\.\d+)/i);
        if (m) return m[1];
      }
      return null;
    },
  },
  {
    tool: "Foreman",
    probe: async (baseUrl) => {
      // Foreman embeds version in data-props of the login page
      const result = await tryFetch(`${baseUrl}/`);
      if (result) {
        // Look for version in foreman-react-component data-props
        const m = result.body.match(/&quot;version&quot;:&quot;(\d+\.\d+(?:\.\d+)?)&quot;/i)
          || result.body.match(/"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/i)
          || result.body.match(/Foreman\s+v?(\d+\.\d+(?:\.\d+)?)/i);
        if (m) return m[1];
      }
      // Try API
      const apiResult = await tryFetch(`${baseUrl}/api/v2/status`);
      if (apiResult) {
        const m = apiResult.body.match(/"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/i);
        if (m) return m[1];
      }
      return null;
    },
  },
];

const VERSION_HEADERS = [
  { header: "x-jenkins", tool: "Jenkins" },
  { header: "x-gitlab-meta", tool: "GitLab" },
];

async function tryFetch(url: string, timeoutMs = 5000): Promise<{ body: string; headers: Headers } | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const resp = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "Mozilla/5.0 (compatible; SecVersions/1.0)", Accept: "text/html,application/json,*/*" },
      redirect: "follow",
    });
    clearTimeout(timeout);
    const body = await resp.text();
    return { body: body.substring(0, 500_000), headers: resp.headers };
  } catch {
    clearTimeout(timeout);
    return null;
  }
}

router.post("/version-detect", requireAuth, async (req, res) => {
  try {
    let { url } = req.body;
    if (!url) return res.status(400).json({ success: false, error: "URL obrigatória" });
    if (!url.startsWith("http://") && !url.startsWith("https://")) url = `https://${url}`;

    // Remove trailing slash for consistent path joining
    const baseUrl = url.replace(/\/+$/, "");

    // 1. Fetch main page
    const mainResult = await tryFetch(baseUrl, 10000);
    if (!mainResult) {
      return res.json({ success: false, error: "Não foi possível acessar a URL" });
    }

    let detectedTool: string | null = null;
    let detectedVersion: string | null = null;

    // 2. Check definitive response headers
    for (const vh of VERSION_HEADERS) {
      const val = mainResult.headers.get(vh.header);
      if (val) {
        detectedTool = vh.tool;
        const m = val.match(/(\d+\.\d+(?:\.\d+)?)/);
        if (m) detectedVersion = m[1];
        break;
      }
    }

    // 3. Scan HTML for tool patterns
    if (!detectedTool || !detectedVersion) {
      for (const dp of DETECTION_PATTERNS) {
        for (const pattern of dp.patterns) {
          const match = mainResult.body.match(pattern);
          if (match) {
            detectedTool = dp.tool;
            if (match[1]) detectedVersion = match[1];
            break;
          }
        }
        if (detectedTool) break;
      }
    }

    // 4. If tool detected but no version, try known API endpoints for that tool
    if (detectedTool && !detectedVersion) {
      const apiEntry = KNOWN_API_ENDPOINTS.find(e => e.tool === detectedTool);
      if (apiEntry) {
        const ver = await apiEntry.probe(baseUrl);
        if (ver) detectedVersion = ver;
      }
    }

    // 5. If no tool detected at all, try ALL known API endpoints
    if (!detectedTool) {
      for (const apiEntry of KNOWN_API_ENDPOINTS) {
        const ver = await apiEntry.probe(baseUrl);
        if (ver) {
          detectedTool = apiEntry.tool;
          detectedVersion = ver;
          break;
        }
      }
    }

    // 6. Only use proxy info (nginx/apache) as absolute last resort
    // But if the page is a generic error page (403/502/etc), warn user instead of returning proxy
    if (!detectedTool) {
      const serverHeader = mainResult.headers.get("server") || "";
      const isGenericErrorPage = /^<html>\s*<.*<center><h1>\d{3}\s/is.test(mainResult.body.trim())
        || (mainResult.body.length < 2000 && /<h1>\s*\d{3}\s+(Forbidden|Not Found|Bad Gateway|Service Unavailable)/i.test(mainResult.body));

      if (isGenericErrorPage) {
        // It's just a proxy error page, not a real app
        return res.json({
          success: true,
          tool: null,
          version: null,
          message: "Acesso bloqueado pelo servidor (403/502). A ferramenta pode não estar acessível externamente. Cadastre manualmente.",
        });
      }

      if (/nginx/i.test(serverHeader)) {
        const m = serverHeader.match(/(\d+\.\d+(?:\.\d+)?)/);
        detectedTool = "Nginx";
        detectedVersion = m ? m[1] : null;
      } else if (/apache/i.test(serverHeader)) {
        const m = serverHeader.match(/(\d+\.\d+(?:\.\d+)?)/);
        detectedTool = "Apache";
        detectedVersion = m ? m[1] : null;
      }
    }

    console.log(`Version detect: tool=${detectedTool}, version=${detectedVersion}`);

    res.json({
      success: true,
      tool: detectedTool,
      version: detectedVersion,
      message: detectedTool
        ? detectedVersion
          ? `Detectado: ${detectedTool} ${detectedVersion}`
          : `Ferramenta detectada (${detectedTool}), mas versão não identificada.`
        : "Não foi possível detectar a ferramenta/versão automaticamente.",
    });
  } catch (err) {
    console.error("Version detect error:", err);
    res.status(500).json({ success: false, error: "Erro interno" });
  }
});

// ─── CRUD ───

// List user's tools
router.get("/", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).user.id;
    const { rows } = await pool.query(
      "SELECT * FROM tools WHERE user_id = $1 ORDER BY added_at DESC",
      [userId]
    );
    res.json(rows);
  } catch (err) {
    console.error("List tools error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Create tool
router.post("/", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).user.id;
    const { name, version, source_url, latest_version, latest_patch_for_cycle, is_outdated, is_patch_outdated, eol, lts, cycle_label, cves, category } = req.body;
    if (!name || !version) return res.status(400).json({ error: "name and version required" });

    const { rows } = await pool.query(
      `INSERT INTO tools (user_id, name, version, source_url, latest_version, latest_patch_for_cycle, is_outdated, is_patch_outdated, eol, lts, cycle_label, cves, category)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
      [userId, name, version, source_url || null, latest_version || null, latest_patch_for_cycle || null, is_outdated ?? null, is_patch_outdated ?? null, eol ?? null, lts ?? null, cycle_label || null, JSON.stringify(cves || []), category || 'ferramenta']
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error("Create tool error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Update tool
router.put("/:id", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).user.id;
    const { id } = req.params;
    const { name, version, source_url, latest_version, latest_patch_for_cycle, is_outdated, is_patch_outdated, eol, lts, cycle_label, cves, category } = req.body;

    const { rows } = await pool.query(
      `UPDATE tools SET name=$1, version=$2, source_url=$3, latest_version=$4, latest_patch_for_cycle=$5, is_outdated=$6, is_patch_outdated=$7, eol=$8, lts=$9, cycle_label=$10, cves=$11, category=COALESCE($14, category)
       WHERE id=$12 AND user_id=$13 RETURNING *`,
      [name, version, source_url || null, latest_version || null, latest_patch_for_cycle || null, is_outdated ?? null, is_patch_outdated ?? null, eol ?? null, lts ?? null, cycle_label || null, JSON.stringify(cves || []), id, userId, category || null]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Ferramenta não encontrada" });
    res.json(rows[0]);
  } catch (err) {
    console.error("Update tool error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Delete tool
router.delete("/:id", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).user.id;
    const { id } = req.params;
    const { rowCount } = await pool.query(
      "DELETE FROM tools WHERE id = $1 AND user_id = $2",
      [id, userId]
    );
    if (rowCount === 0) return res.status(404).json({ error: "Ferramenta não encontrada" });
    res.json({ success: true });
  } catch (err) {
    console.error("Delete tool error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Change tool category
router.patch("/:id/category", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).user.id;
    const { id } = req.params;
    const { category } = req.body;
    if (!category) return res.status(400).json({ error: "category required" });

    const { rows } = await pool.query(
      "UPDATE tools SET category = $1 WHERE id = $2 AND user_id = $3 RETURNING *",
      [category, id, userId]
    );
    if (rows.length === 0) return res.status(404).json({ error: "Ferramenta não encontrada" });
    res.json(rows[0]);
  } catch (err) {
    console.error("Change category error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// ─── Sub-versions CRUD ───


// List sub-versions for a tool
router.get("/:id/versions", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).user.id;
    const { id } = req.params;
    // Verify tool ownership
    const { rows: toolRows } = await pool.query("SELECT id FROM tools WHERE id = $1 AND user_id = $2", [id, userId]);
    if (toolRows.length === 0) return res.status(404).json({ error: "Ferramenta não encontrada" });

    const { rows } = await pool.query(
      "SELECT * FROM tool_versions WHERE tool_id = $1 ORDER BY created_at DESC",
      [id]
    );
    res.json(rows);
  } catch (err) {
    console.error("List sub-versions error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Create or refresh sub-version
router.post("/:id/versions", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).user.id;
    const { id } = req.params;
    // Verify tool ownership
    const { rows: toolRows } = await pool.query("SELECT id FROM tools WHERE id = $1 AND user_id = $2", [id, userId]);
    if (toolRows.length === 0) return res.status(404).json({ error: "Ferramenta não encontrada" });

    const { version, source_url, latest_version, latest_patch_for_cycle, is_outdated, is_patch_outdated, eol, lts, cycle_label, cves } = req.body;
    if (!version) return res.status(400).json({ error: "version required" });

    const normalizedVersion = String(version).trim();
    const normalizedSourceUrl = typeof source_url === "string" && source_url.trim() ? source_url.trim() : null;

    const { rows: existingRows } = await pool.query(
      `SELECT id
       FROM tool_versions
       WHERE tool_id = $1
         AND version = $2
         AND (
           source_url = $3
           OR (source_url IS NULL AND $3 IS NULL)
           OR (source_url IS NULL AND $3 IS NOT NULL)
         )
       ORDER BY CASE
         WHEN source_url = $3 THEN 0
         WHEN source_url IS NULL THEN 1
         ELSE 2
       END, created_at DESC
       LIMIT 1`,
      [id, normalizedVersion, normalizedSourceUrl]
    );

    if (existingRows.length > 0) {
      const { rows } = await pool.query(
        `UPDATE tool_versions
         SET source_url = COALESCE($1, source_url),
             latest_version = $2,
             latest_patch_for_cycle = $3,
             is_outdated = $4,
             is_patch_outdated = $5,
             eol = $6,
             lts = $7,
             cycle_label = $8,
             cves = $9,
             updated_at = now()
         WHERE id = $10
         RETURNING *`,
        [normalizedSourceUrl, latest_version || null, latest_patch_for_cycle || null, is_outdated ?? null, is_patch_outdated ?? null, eol ?? null, lts ?? null, cycle_label || null, JSON.stringify(cves || []), existingRows[0].id]
      );
      return res.json(rows[0]);
    }

    const { rows } = await pool.query(
      `INSERT INTO tool_versions (tool_id, version, source_url, latest_version, latest_patch_for_cycle, is_outdated, is_patch_outdated, eol, lts, cycle_label, cves)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11) RETURNING *`,
      [id, normalizedVersion, normalizedSourceUrl, latest_version || null, latest_patch_for_cycle || null, is_outdated ?? null, is_patch_outdated ?? null, eol ?? null, lts ?? null, cycle_label || null, JSON.stringify(cves || [])]
    );
    res.status(201).json(rows[0]);
  } catch (err) {
    console.error("Create sub-version error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Delete sub-version
router.delete("/:id/versions/:versionId", requireAuth, async (req, res) => {
  try {
    const userId = (req as any).user.id;
    const { id, versionId } = req.params;
    // Verify tool ownership
    const { rows: toolRows } = await pool.query("SELECT id FROM tools WHERE id = $1 AND user_id = $2", [id, userId]);
    if (toolRows.length === 0) return res.status(404).json({ error: "Ferramenta não encontrada" });

    const { rowCount } = await pool.query("DELETE FROM tool_versions WHERE id = $1 AND tool_id = $2", [versionId, id]);
    if (rowCount === 0) return res.status(404).json({ error: "Sub-versão não encontrada" });
    res.json({ success: true });
  } catch (err) {
    console.error("Delete sub-version error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

export default router;
