import { Router } from "express";
import { requireAuth } from "../middleware/auth.js";
import * as net from "net";

const router = Router();

// Common ports and their typical services
const COMMON_PORTS: Record<number, string> = {
  21: "FTP",
  22: "SSH",
  80: "HTTP",
  443: "HTTPS",
  3000: "Grafana/Node",
  3306: "MySQL",
  5432: "PostgreSQL",
  5601: "Kibana",
  6379: "Redis",
  8080: "HTTP-Alt",
  8443: "HTTPS-Alt",
  8888: "HTTP-Alt",
  9090: "Prometheus",
  9100: "Node Exporter",
  9200: "Elasticsearch",
  9443: "HTTPS-Alt",
  10050: "Zabbix Agent",
  10051: "Zabbix Server",
  27017: "MongoDB",
};

// Known service fingerprints from HTTP responses
const HTTP_FINGERPRINTS: { tool: string; patterns: RegExp[] }[] = [
  { tool: "Zabbix", patterns: [/Zabbix/i, /<title>.*Zabbix.*<\/title>/i] },
  { tool: "Grafana", patterns: [/Grafana/i, /"subTitle"\s*:\s*"Grafana"/i] },
  { tool: "GitLab", patterns: [/GitLab/i, /gitlab-ce|gitlab-ee/i] },
  { tool: "Jenkins", patterns: [/Jenkins/i, /X-Jenkins/i] },
  { tool: "SonarQube", patterns: [/SonarQube/i, /sonarqube/i] },
  { tool: "Prometheus", patterns: [/Prometheus/i, /prometheus/i] },
  { tool: "Kibana", patterns: [/Kibana/i, /kibana/i] },
  { tool: "Elasticsearch", patterns: [/elasticsearch/i, /"cluster_name"/i] },
  { tool: "Nginx", patterns: [/nginx/i] },
  { tool: "Apache", patterns: [/Apache/i] },
  { tool: "Tomcat", patterns: [/Apache Tomcat/i] },
  { tool: "Redis", patterns: [/redis_version/i] },
  { tool: "MinIO", patterns: [/MinIO/i] },
  { tool: "Portainer", patterns: [/Portainer/i] },
  { tool: "Rancher", patterns: [/Rancher/i] },
  { tool: "Nexus", patterns: [/Nexus Repository/i, /Sonatype Nexus/i] },
  { tool: "Harbor", patterns: [/Harbor/i] },
  { tool: "Keycloak", patterns: [/Keycloak/i] },
  { tool: "Vault", patterns: [/Vault/i, /hashicorp/i] },
  { tool: "Consul", patterns: [/Consul/i] },
];

const VERSION_PATTERNS = [
  /(?:version|ver\.?)\s*[:\s=]*[v"]?(\d+\.\d+(?:\.\d+)?)/i,
  /[\/\s]v?(\d+\.\d+(?:\.\d+)?)/,
];

// Parse CIDR to IP list
function parseCIDR(cidr: string): string[] {
  const [ip, prefixStr] = cidr.split("/");
  const prefix = parseInt(prefixStr ?? "32");

  if (prefix < 16 || prefix > 32) throw new Error("Prefix must be /16 to /32");

  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => isNaN(p) || p < 0 || p > 255)) {
    throw new Error("Invalid IP address");
  }

  const ipNum = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
  const mask = (~0 << (32 - prefix)) >>> 0;
  const network = (ipNum & mask) >>> 0;
  const broadcast = (network | ~mask) >>> 0;

  const ips: string[] = [];
  // Skip network and broadcast for /31+ ranges
  const start = prefix >= 31 ? network : network + 1;
  const end = prefix >= 31 ? broadcast : broadcast - 1;

  // Safety limit
  const maxHosts = 1024;
  const count = end - start + 1;
  if (count > maxHosts) throw new Error(`Range too large (${count} hosts, max ${maxHosts})`);

  for (let i = start; i <= end; i++) {
    ips.push(`${(i >>> 24) & 255}.${(i >>> 16) & 255}.${(i >>> 8) & 255}.${i & 255}`);
  }
  return ips;
}

// TCP connect scan with timeout
function scanPort(host: string, port: number, timeoutMs = 1500): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => {
      socket.destroy();
      resolve(true);
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve(false);
    });
    socket.once("error", () => {
      socket.destroy();
      resolve(false);
    });
    socket.connect(port, host);
  });
}

// Try to fingerprint an HTTP(S) service
async function fingerprint(host: string, port: number): Promise<{ tool: string | null; version: string | null; banner: string }> {
  const isHttps = [443, 8443, 9443].includes(port);
  const protocol = isHttps ? "https" : "http";
  const url = `${protocol}://${host}:${port}`;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const res = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "SecVersions-Discovery/1.0" },
      redirect: "manual",
    });
    clearTimeout(timeout);

    // Check headers first
    let detectedTool: string | null = null;
    let detectedVersion: string | null = null;
    const serverHeader = res.headers.get("server") || "";
    const poweredBy = res.headers.get("x-powered-by") || "";
    const jenkinsHeader = res.headers.get("x-jenkins");

    if (jenkinsHeader) {
      detectedTool = "Jenkins";
      const m = jenkinsHeader.match(/(\d+\.\d+(?:\.\d+)?)/);
      if (m) detectedVersion = m[1];
    }

    // Check body
    const body = await res.text().catch(() => "");
    const snippet = body.substring(0, 100000);
    const allText = `${serverHeader} ${poweredBy} ${snippet}`;

    if (!detectedTool) {
      for (const fp of HTTP_FINGERPRINTS) {
        for (const p of fp.patterns) {
          if (p.test(allText)) {
            detectedTool = fp.tool;
            break;
          }
        }
        if (detectedTool) break;
      }
    }

    if (detectedTool && !detectedVersion) {
      // Try to find version near tool name
      const toolRegex = new RegExp(detectedTool + "[\\s\\S]{0,50}?(\\d+\\.\\d+(?:\\.\\d+)?)", "i");
      const m = allText.match(toolRegex);
      if (m?.[1]) detectedVersion = m[1];

      // Try generic version patterns
      if (!detectedVersion) {
        for (const vp of VERSION_PATTERNS) {
          const m2 = allText.match(vp);
          if (m2?.[1]) {
            detectedVersion = m2[1];
            break;
          }
        }
      }
    }

    const banner = serverHeader || poweredBy || (detectedTool ? `${detectedTool} detected` : `HTTP ${res.status}`);
    return { tool: detectedTool, version: detectedVersion, banner: banner.substring(0, 200) };
  } catch {
    return { tool: null, version: null, banner: COMMON_PORTS[port] || "Unknown" };
  }
}

interface ScanResult {
  ip: string;
  port: number;
  service: string;
  tool: string | null;
  version: string | null;
  banner: string;
}

// POST /api/discovery/scan
router.post("/scan", requireAuth, async (req, res) => {
  try {
    const { cidr, ports: customPorts } = req.body;

    if (!cidr || typeof cidr !== "string") {
      return res.status(400).json({ error: "CIDR é obrigatório (ex: 192.168.1.0/24)" });
    }

    // Validate CIDR format
    const cidrRegex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(\/\d{1,2})?$/;
    if (!cidrRegex.test(cidr.trim())) {
      return res.status(400).json({ error: "Formato CIDR inválido" });
    }

    // Add /32 if no prefix
    const normalizedCidr = cidr.includes("/") ? cidr.trim() : `${cidr.trim()}/32`;

    let ips: string[];
    try {
      ips = parseCIDR(normalizedCidr);
    } catch (err: any) {
      return res.status(400).json({ error: err.message });
    }

    // Determine ports to scan
    let portsToScan: number[] = Object.keys(COMMON_PORTS).map(Number);
    if (Array.isArray(customPorts) && customPorts.length > 0) {
      portsToScan = customPorts
        .map(Number)
        .filter((p) => p > 0 && p <= 65535)
        .slice(0, 50); // Max 50 custom ports
    }

    console.log(`[Discovery] Scanning ${ips.length} host(s) on ${portsToScan.length} port(s)...`);

    const results: ScanResult[] = [];

    // Scan in batches to avoid overwhelming the network
    const BATCH_SIZE = 20;
    const allTasks: { ip: string; port: number }[] = [];

    for (const ip of ips) {
      for (const port of portsToScan) {
        allTasks.push({ ip, port });
      }
    }

    for (let i = 0; i < allTasks.length; i += BATCH_SIZE) {
      const batch = allTasks.slice(i, i + BATCH_SIZE);
      const batchResults = await Promise.all(
        batch.map(async ({ ip, port }) => {
          const open = await scanPort(ip, port);
          if (!open) return null;

          // Try HTTP fingerprinting for HTTP-like ports
          const httpPorts = [80, 443, 3000, 5601, 8080, 8443, 8888, 9090, 9200, 9443];
          let fp = { tool: null as string | null, version: null as string | null, banner: COMMON_PORTS[port] || "Unknown" };

          if (httpPorts.includes(port)) {
            fp = await fingerprint(ip, port);
          }

          return {
            ip,
            port,
            service: COMMON_PORTS[port] || "Unknown",
            tool: fp.tool,
            version: fp.version,
            banner: fp.banner,
          } as ScanResult;
        })
      );

      results.push(...batchResults.filter(Boolean) as ScanResult[]);
    }

    console.log(`[Discovery] Found ${results.length} open port(s)`);

    res.json({
      total_hosts: ips.length,
      total_ports_scanned: portsToScan.length,
      results,
    });
  } catch (err) {
    console.error("[Discovery] Error:", err);
    res.status(500).json({ error: "Erro interno no scan" });
  }
});

export default router;
