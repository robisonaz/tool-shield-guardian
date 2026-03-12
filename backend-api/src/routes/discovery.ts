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

// TCP connect scan with timeout — also grabs banner if available
function scanPort(host: string, port: number, timeoutMs = 2000): Promise<{ open: boolean; banner: string }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let banner = "";
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => {
      // For some protocols we need to wait for the server to send a banner
      socket.once("data", (data) => {
        banner = data.toString("utf8", 0, 512).trim();
        socket.destroy();
        resolve({ open: true, banner });
      });
      // If no data arrives within 1.5s, resolve without banner
      setTimeout(() => {
        socket.destroy();
        resolve({ open: true, banner });
      }, 1500);
    });
    socket.once("timeout", () => {
      socket.destroy();
      resolve({ open: false, banner: "" });
    });
    socket.once("error", () => {
      socket.destroy();
      resolve({ open: false, banner: "" });
    });
    socket.connect(port, host);
  });
}

// Parse version from TCP banner for known services
function parseTcpBanner(port: number, banner: string): { tool: string | null; version: string | null } {
  // SSH: "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
  const sshMatch = banner.match(/SSH-[\d.]+-(OpenSSH[_\s]?([\d.]+[p\d]*))/i);
  if (sshMatch) return { tool: "OpenSSH", version: sshMatch[2] || null };
  if (/^SSH-/i.test(banner)) {
    const v = banner.match(/SSH-[\d.]+-(.+)/);
    return { tool: "SSH", version: v?.[1]?.trim() || null };
  }

  // MySQL / MariaDB: version string in greeting packet
  // The greeting packet contains the version as a null-terminated string starting at byte 5
  const mysqlMatch = banner.match(/([\d]+\.[\d]+\.[\d]+[-\w]*)/);
  if (port === 3306 && mysqlMatch) {
    const isMariaDB = /mariadb/i.test(banner);
    return { tool: isMariaDB ? "MariaDB" : "MySQL", version: mysqlMatch[1] };
  }

  // PostgreSQL: after connection the server may not send a banner without SSL negotiation
  // But if we get something, try to parse it
  if (port === 5432 && banner.length > 0) {
    const pgMatch = banner.match(/PostgreSQL\s+([\d.]+)/i);
    return { tool: "PostgreSQL", version: pgMatch?.[1] || null };
  }

  // Zabbix Agent: responds to "agent.version" but also may have a banner
  if ((port === 10050 || port === 10051) && banner.length > 0) {
    const zbxMatch = banner.match(/([\d]+\.[\d]+\.[\d]+)/);
    return { tool: port === 10050 ? "Zabbix Agent" : "Zabbix Server", version: zbxMatch?.[1] || null };
  }

  // Redis: "+PONG" or redis_version in INFO
  if (port === 6379) {
    const redisMatch = banner.match(/redis_version:([\d.]+)/i);
    if (redisMatch) return { tool: "Redis", version: redisMatch[1] };
    if (banner.includes("DENIED") || banner.includes("+")) return { tool: "Redis", version: null };
  }

  // MongoDB
  if (port === 27017 && banner.length > 0) {
    return { tool: "MongoDB", version: null };
  }

  return { tool: null, version: null };
}

// For Zabbix Agent, send a command to get version
async function probeZabbixAgent(host: string, port: number): Promise<{ tool: string; version: string | null }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(3000);
    socket.once("connect", () => {
      // Zabbix passive agent protocol: send "agent.version\n"
      const key = "agent.version";
      // Zabbix protocol header: ZBXD\x01 + 8-byte data length (little-endian) + data
      const data = Buffer.from(key);
      const header = Buffer.alloc(13);
      header.write("ZBXD\x01");
      header.writeUInt32LE(data.length, 5);
      header.writeUInt32LE(0, 9);
      socket.write(Buffer.concat([header, data]));

      socket.once("data", (response) => {
        const str = response.toString("utf8").replace(/ZBXD\x01.{8}/s, "").trim();
        const vMatch = str.match(/([\d]+\.[\d]+\.[\d]+)/);
        socket.destroy();
        resolve({ tool: port === 10050 ? "Zabbix Agent" : "Zabbix Server", version: vMatch?.[1] || str || null });
      });
      setTimeout(() => { socket.destroy(); resolve({ tool: "Zabbix Agent", version: null }); }, 2500);
    });
    socket.once("error", () => { socket.destroy(); resolve({ tool: "Zabbix Agent", version: null }); });
    socket.once("timeout", () => { socket.destroy(); resolve({ tool: "Zabbix Agent", version: null }); });
    socket.connect(port, host);
  });
}

// PostgreSQL doesn't send a banner — we must send a StartupMessage to get the version
async function probePostgreSQL(host: string, port: number): Promise<{ tool: string; version: string | null }> {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(3000);
    socket.once("connect", () => {
      // Send SSLRequest first (int32 length=8, int32 code=80877103)
      // Server responds with 'S' (supports SSL) or 'N' (no SSL)
      const sslReq = Buffer.alloc(8);
      sslReq.writeInt32BE(8, 0);
      sslReq.writeInt32BE(80877103, 4);
      socket.write(sslReq);

      socket.once("data", (sslResponse) => {
        // After SSL response, send a StartupMessage with protocol 3.0
        // StartupMessage: int32 length, int32 protocol(196608 = 3.0), "user\0postgres\0database\0postgres\0\0"
        const params = "user\0postgres\0database\0postgres\0\0";
        const paramsBuffer = Buffer.from(params, "utf8");
        const startupLen = 4 + 4 + paramsBuffer.length;
        const startup = Buffer.alloc(startupLen);
        startup.writeInt32BE(startupLen, 0);
        startup.writeInt32BE(196608, 4); // protocol 3.0
        paramsBuffer.copy(startup, 8);
        socket.write(startup);

        let collected = Buffer.alloc(0);
        const onData = (chunk: Buffer) => {
          collected = Buffer.concat([collected, chunk]);
          const str = collected.toString("utf8");
          // Look for server_version in the parameter status messages
          const vMatch = str.match(/server_version\0([\d.]+)/);
          if (vMatch) {
            socket.removeListener("data", onData);
            socket.destroy();
            resolve({ tool: "PostgreSQL", version: vMatch[1] });
            return;
          }
          // Also check for ErrorResponse which contains version info sometimes
          const errMatch = str.match(/PostgreSQL\s+([\d.]+)/i);
          if (errMatch) {
            socket.removeListener("data", onData);
            socket.destroy();
            resolve({ tool: "PostgreSQL", version: errMatch[1] });
            return;
          }
          // If we got auth request or error, we know it's PostgreSQL
          if (collected.length > 100) {
            socket.removeListener("data", onData);
            socket.destroy();
            resolve({ tool: "PostgreSQL", version: null });
          }
        };
        socket.on("data", onData);
        setTimeout(() => {
          socket.removeAllListeners("data");
          socket.destroy();
          resolve({ tool: "PostgreSQL", version: null });
        }, 2500);
      });
    });
    socket.once("error", () => { socket.destroy(); resolve({ tool: "PostgreSQL", version: null }); });
    socket.once("timeout", () => { socket.destroy(); resolve({ tool: "PostgreSQL", version: null }); });
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
          const { open, banner: tcpBanner } = await scanPort(ip, port);
          if (!open) return null;

          // Try HTTP fingerprinting for HTTP-like ports
          const httpPorts = [80, 443, 3000, 5601, 8080, 8443, 8888, 9090, 9200, 9443];

          let tool: string | null = null;
          let version: string | null = null;
          let banner = COMMON_PORTS[port] || "Unknown";

          if (httpPorts.includes(port)) {
            const fp = await fingerprint(ip, port);
            tool = fp.tool;
            version = fp.version;
            banner = fp.banner;
          } else if ([10050, 10051].includes(port)) {
            // Special probe for Zabbix Agent/Server
            const zbx = await probeZabbixAgent(ip, port);
            tool = zbx.tool;
            version = zbx.version;
            banner = tcpBanner || `${zbx.tool} detected`;
          } else if (tcpBanner) {
            // Parse TCP banner for SSH, MySQL, PostgreSQL, Redis, etc.
            const parsed = parseTcpBanner(port, tcpBanner);
            tool = parsed.tool;
            version = parsed.version;
            banner = tcpBanner.substring(0, 200);
          }

          return {
            ip,
            port,
            service: COMMON_PORTS[port] || "Unknown",
            tool,
            version,
            banner,
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
