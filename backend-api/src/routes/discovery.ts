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

// PostgreSQL version detection — multi-strategy approach
async function probePostgreSQL(host: string, port: number): Promise<{ tool: string; version: string | null }> {
  // Strategy 1: Use the pg library (handles SSL, SCRAM, etc. automatically)
  // Works when trust/peer auth is configured (common on internal networks)
  try {
    const version = await pgLibraryProbe(host, port);
    if (version) return { tool: "PostgreSQL", version };
  } catch { /* fall through */ }

  // Strategy 2: Raw TCP handshake — send StartupMessage, respond to auth
  // challenge with dummy password to trigger ErrorResponse with file/line fingerprint
  try {
    const version = await pgRawHandshake(host, port);
    return { tool: "PostgreSQL", version };
  } catch { /* fall through */ }

  return { tool: "PostgreSQL", version: null };
}

// Strategy 1: Use pg library for SELECT version()
async function pgLibraryProbe(host: string, port: number): Promise<string | null> {
  const pg = (await import("pg")).default;
  const client = new pg.Client({
    host, port, user: "postgres", database: "postgres",
    connectionTimeoutMillis: 4000,
    statement_timeout: 2000,
  });
  try {
    await client.connect();
    const res = await client.query("SELECT version()");
    const m = (res.rows[0]?.version || "").match(/PostgreSQL\s+([\d.]+)/i);
    return m?.[1] || null;
  } finally {
    await client.end().catch(() => {});
  }
}

// Strategy 2: Raw TCP with protocol handshake and auth challenge
async function pgRawHandshake(host: string, port: number): Promise<string | null> {
  const tls = await import("tls");

  function collectAndParse(sock: net.Socket | import("tls").TLSSocket): Promise<string | null> {
    return new Promise((resolve) => {
      let collected = Buffer.alloc(0);
      let resolved = false;
      let authResponseSent = false;

      const done = (v: string | null) => {
        if (resolved) return;
        resolved = true;
        sock.removeAllListeners("data");
        sock.destroy();
        resolve(v);
      };

      // Build and send StartupMessage (protocol 3.0)
      const params = "user\0postgres\0database\0postgres\0\0";
      const pb = Buffer.from(params, "utf8");
      const startupLen = 4 + 4 + pb.length;
      const startup = Buffer.alloc(startupLen);
      startup.writeInt32BE(startupLen, 0);
      startup.writeInt32BE(196608, 4); // protocol 3.0
      pb.copy(startup, 8);
      sock.write(startup);

      sock.on("data", (chunk: Buffer) => {
        collected = Buffer.concat([collected, chunk]);

        let offset = 0;
        while (offset + 5 <= collected.length) {
          const msgType = collected[offset];
          const msgLen = collected.readInt32BE(offset + 1);
          if (msgLen < 4 || offset + 1 + msgLen > collected.length) break;

          const payload = collected.subarray(offset + 5, offset + 1 + msgLen);

          // 'S' (0x53) = ParameterStatus — look for server_version
          if (msgType === 0x53) {
            const ps = payload.toString("utf8");
            const ni = ps.indexOf("\0");
            if (ni >= 0) {
              const key = ps.substring(0, ni);
              const val = ps.substring(ni + 1).replace(/\0$/, "");
              if (key === "server_version") {
                const m = val.match(/([\d]+\.[\d]+(?:\.[\d]+)?)/);
                if (m) { done(m[1]); return; }
              }
            }
          }

          // 'R' (0x52) = AuthenticationRequest
          if (msgType === 0x52 && payload.length >= 4 && !authResponseSent) {
            const authType = payload.readInt32BE(0);
            if (authType === 0) {
              // AuthenticationOk — ParameterStatus messages should follow
            } else {
              // Auth required — send dummy PasswordMessage to trigger ErrorResponse
              authResponseSent = true;
              if (authType === 10) {
                // SCRAM-SHA-256 — send SASLInitialResponse with garbage
                const mech = "SCRAM-SHA-256";
                const clientFirst = "n,,n=*,r=invalidnonce12345";
                const saslLen = 4 + mech.length + 1 + 4 + clientFirst.length;
                const saslBuf = Buffer.alloc(1 + saslLen);
                let off = 0;
                saslBuf[off++] = 0x70; // 'p'
                saslBuf.writeInt32BE(saslLen, off); off += 4;
                saslBuf.write(mech, off, "utf8"); off += mech.length;
                saslBuf[off++] = 0;
                saslBuf.writeInt32BE(clientFirst.length, off); off += 4;
                saslBuf.write(clientFirst, off, "utf8");
                sock.write(saslBuf);
              } else {
                // MD5 (5) or cleartext (3) — send dummy PasswordMessage
                const pw = "wrong_password";
                const pwLen = 4 + pw.length + 1;
                const pwBuf = Buffer.alloc(1 + pwLen);
                pwBuf[0] = 0x70; // 'p'
                pwBuf.writeInt32BE(pwLen, 1);
                pwBuf.write(pw, 5, "utf8");
                pwBuf[5 + pw.length] = 0;
                sock.write(pwBuf);
              }
            }
          }

          // 'E' (0x45) = ErrorResponse — parse fields for version fingerprint
          if (msgType === 0x45) {
            const version = parsePostgresErrorFields(payload);
            done(version);
            return;
          }

          offset += 1 + msgLen;
        }

        if (collected.length > 16384) done(null);
      });

      setTimeout(() => done(null), 5000);
    });
  }

  return new Promise((resolve) => {
    const socket = new net.Socket();
    socket.setTimeout(6000);

    socket.once("connect", () => {
      // Send SSLRequest
      const sslReq = Buffer.alloc(8);
      sslReq.writeInt32BE(8, 0);
      sslReq.writeInt32BE(80877103, 4);
      socket.write(sslReq);

      socket.once("data", async (resp) => {
        const sslByte = String.fromCharCode(resp[0]);
        if (sslByte === "S") {
          const tlsSock = tls.connect({ socket, rejectUnauthorized: false });
          tlsSock.once("secureConnect", async () => {
            resolve(await collectAndParse(tlsSock));
          });
          tlsSock.once("error", () => { tlsSock.destroy(); resolve(null); });
        } else {
          resolve(await collectAndParse(socket));
        }
      });
    });

    socket.once("error", () => { socket.destroy(); resolve(null); });
    socket.once("timeout", () => { socket.destroy(); resolve(null); });
    socket.connect(port, host);
  });
}

// Parse ErrorResponse fields (F=file, L=line, R=routine, M=message)
// and extract PostgreSQL version via message text or file/line fingerprint
function parsePostgresErrorFields(payload: Buffer): string | null {
  let file = "", line = "", routine = "", message = "";
  let pos = 0;
  while (pos < payload.length) {
    const ft = payload[pos];
    if (ft === 0) break;
    pos++;
    const end = payload.indexOf(0, pos);
    if (end === -1) break;
    const val = payload.subarray(pos, end).toString("utf8");
    if (ft === 0x46) file = val;     // F
    if (ft === 0x4C) line = val;     // L
    if (ft === 0x52) routine = val;  // R
    if (ft === 0x4D) message = val;  // M
    pos = end + 1;
  }

  // Check message for explicit version string
  const msgMatch = message.match(/PostgreSQL\s+([\d.]+)/i);
  if (msgMatch) return msgMatch[1];

  // File/line fingerprint mapping (Metasploit + modern PostgreSQL source analysis)
  if (file && line) {
    const fp = `${file}:${line}:${routine}`;
    const known: Record<string, string> = {
      // PostgreSQL 9.x
      "auth.c:302:auth_failed": "9.1",
      "auth.c:285:auth_failed": "9.4",
      "auth.c:481:ClientAuthentication": "9.4",
      "miscinit.c:362:InitializeSessionUserId": "9.4",
      "postinit.c:794:InitPostgres": "9.4",
      // PostgreSQL 8.x
      "auth.c:395:auth_failed": "7.4",
      "auth.c:400:auth_failed": "8.0",
      "auth.c:337:auth_failed": "8.1",
      "auth.c:362:auth_failed": "8.2",
      "auth.c:1003:auth_failed": "8.3",
      "auth.c:258:auth_failed": "8.4",
      "auth.c:273:auth_failed": "8.4",
    };
    if (known[fp]) return known[fp];

    // Heuristic: file name tells us PG 17+ (backend_startup.c) vs older (postmaster.c/auth.c)
    if (file.includes("backend_startup")) return "17";

    // auth.c with auth_failed in modern PG (10+)
    if (routine === "auth_failed" && file.includes("auth.c")) {
      const ln = parseInt(line);
      // Modern PG auth.c auth_failed line ranges (approximate from source)
      if (ln >= 335 && ln <= 345) return "16";
      if (ln >= 330 && ln <= 340) return "15";
      if (ln >= 325 && ln <= 335) return "14";
      if (ln >= 320 && ln <= 330) return "13";
      if (ln >= 315 && ln <= 325) return "12";
      if (ln >= 310 && ln <= 320) return "11";
      if (ln >= 300 && ln <= 315) return "10";
    }

    // ClientAuthentication routine — broader ranges
    if (routine === "ClientAuthentication" && file.includes("auth.c")) {
      const ln = parseInt(line);
      if (ln >= 490 && ln <= 510) return "16";
      if (ln >= 485 && ln <= 500) return "15";
      if (ln >= 480 && ln <= 495) return "14";
      if (ln >= 475 && ln <= 490) return "13";
      if (ln >= 470 && ln <= 485) return "12";
      if (ln >= 465 && ln <= 480) return "11";
      if (ln >= 460 && ln <= 475) return "10";
    }
  }

  return null;
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
          } else if (port === 5432) {
            // PostgreSQL requires a startup handshake to reveal version
            const pg = await probePostgreSQL(ip, port);
            tool = pg.tool;
            version = pg.version;
            banner = tcpBanner || `PostgreSQL${pg.version ? ' ' + pg.version : ''} detected`;
          } else if (tcpBanner) {
            // Parse TCP banner for SSH, MySQL, Redis, etc.
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
