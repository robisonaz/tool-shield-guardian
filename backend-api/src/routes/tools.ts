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
    const cpeEntry = CPE_MAP[toolKey];

    let url: string;
    if (cpeEntry) {
      const cpeMatch = `cpe:2.3:a:${cpeEntry.vendor}:${cpeEntry.product}:${version}`;
      url = `${NVD_API_BASE}?virtualMatchString=${encodeURIComponent(cpeMatch)}&resultsPerPage=50`;
    } else {
      url = `${NVD_API_BASE}?keywordSearch=${encodeURIComponent(`${toolName} ${version}`)}&resultsPerPage=20`;
    }

    const response = await fetch(url, { headers: { Accept: "application/json" } });
    if (!response.ok) {
      if (response.status === 403 || response.status === 429) {
        return res.json({ cves: [], rateLimited: true });
      }
      throw new Error(`NVD API returned ${response.status}`);
    }

    const data = await response.json();
    const vulnerabilities = data.vulnerabilities || [];

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

    res.json({ cves, total: data.totalResults || 0 });
  } catch (err) {
    console.error("NVD lookup error:", err);
    res.status(500).json({ error: "Erro interno" });
  }
});

// Version detect from URL
const DETECTION_PATTERNS: { tool: string; patterns: RegExp[] }[] = [
  { tool: "Zabbix", patterns: [/Zabbix\s+(?:SIA\s+)?(?:v?(\d+\.\d+(?:\.\d+)?))/i, /zabbix[_-]?version["\s:=]+["\s]*(\d+\.\d+(?:\.\d+)?)/i] },
  { tool: "Grafana", patterns: [/Grafana\s+v?(\d+\.\d+(?:\.\d+)?)/i, /"version"\s*:\s*"(\d+\.\d+(?:\.\d+)?)"/i] },
  { tool: "GitLab", patterns: [/gitlab[_-]?version["\s:=]+(\d+\.\d+(?:\.\d+)?)/i, /GitLab\s+(?:Community|Enterprise)?\s*Edition\s+(\d+\.\d+(?:\.\d+)?)/i] },
  { tool: "Jenkins", patterns: [/Jenkins\s+ver\.\s*(\d+\.\d+(?:\.\d+)?)/i, /X-Jenkins:\s*(\d+\.\d+(?:\.\d+)?)/i] },
  { tool: "SonarQube", patterns: [/SonarQube\s+(\d+\.\d+(?:\.\d+)?)/i] },
  { tool: "Prometheus", patterns: [/Prometheus\s+v?(\d+\.\d+(?:\.\d+)?)/i] },
];

const VERSION_HEADERS = [
  { header: "x-jenkins", tool: "Jenkins" },
  { header: "x-gitlab-meta", tool: "GitLab" },
];

router.post("/version-detect", requireAuth, async (req, res) => {
  try {
    let { url } = req.body;
    if (!url) return res.status(400).json({ success: false, error: "URL obrigatória" });
    if (!url.startsWith("http://") && !url.startsWith("https://")) url = `https://${url}`;

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);

    let response: Response;
    try {
      response = await fetch(url, {
        signal: controller.signal,
        headers: { "User-Agent": "Mozilla/5.0 (compatible; SecVersions/1.0)", Accept: "text/html,*/*" },
        redirect: "manual",
      });
    } catch {
      clearTimeout(timeout);
      return res.json({ success: false, error: "Não foi possível acessar a URL" });
    }
    clearTimeout(timeout);

    let detectedTool: string | null = null;
    let detectedVersion: string | null = null;

    // Check headers
    for (const vh of VERSION_HEADERS) {
      const val = response.headers.get(vh.header);
      if (val) {
        detectedTool = vh.tool;
        const m = val.match(/(\d+\.\d+(?:\.\d+)?)/);
        if (m) detectedVersion = m[1];
        break;
      }
    }

    // Check proxy headers as fallback
    let proxyTool: string | null = null;
    let proxyVersion: string | null = null;
    for (const ph of ["server", "x-powered-by"]) {
      const val = response.headers.get(ph);
      if (val) {
        const m = val.match(/(\d+\.\d+(?:\.\d+)?)/);
        if (m) {
          proxyVersion = m[1];
          if (/nginx/i.test(val)) proxyTool = "Nginx";
          else if (/apache/i.test(val)) proxyTool = "Apache";
        }
      }
    }

    // Parse HTML
    const html = await response.text();
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
    }

    if (!detectedTool && proxyTool) {
      detectedTool = proxyTool;
      detectedVersion = proxyVersion;
    }

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
    const { name, version, source_url, latest_version, latest_patch_for_cycle, is_outdated, is_patch_outdated, eol, lts, cycle_label, cves } = req.body;
    if (!name || !version) return res.status(400).json({ error: "name and version required" });

    const { rows } = await pool.query(
      `INSERT INTO tools (user_id, name, version, source_url, latest_version, latest_patch_for_cycle, is_outdated, is_patch_outdated, eol, lts, cycle_label, cves)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12) RETURNING *`,
      [userId, name, version, source_url || null, latest_version || null, latest_patch_for_cycle || null, is_outdated ?? null, is_patch_outdated ?? null, eol ?? null, lts ?? null, cycle_label || null, JSON.stringify(cves || [])]
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
    const { name, version, source_url, latest_version, latest_patch_for_cycle, is_outdated, is_patch_outdated, eol, lts, cycle_label, cves } = req.body;

    const { rows } = await pool.query(
      `UPDATE tools SET name=$1, version=$2, source_url=$3, latest_version=$4, latest_patch_for_cycle=$5, is_outdated=$6, is_patch_outdated=$7, eol=$8, lts=$9, cycle_label=$10, cves=$11
       WHERE id=$12 AND user_id=$13 RETURNING *`,
      [name, version, source_url || null, latest_version || null, latest_patch_for_cycle || null, is_outdated ?? null, is_patch_outdated ?? null, eol ?? null, lts ?? null, cycle_label || null, JSON.stringify(cves || []), id, userId]
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

export default router;
