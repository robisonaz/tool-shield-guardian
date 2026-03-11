import { nvdLookup, fetchTools, createTool, updateToolApi, deleteTool } from "@/lib/api-client";

export interface ToolEntry {
  id: string;
  user_id?: string;
  name: string;
  version: string;
  source_url: string | null;
  added_at: string;
  latest_version: string | null;
  latest_patch_for_cycle: string | null;
  is_outdated: boolean | null;
  is_patch_outdated: boolean | null;
  eol: string | boolean | null;
  lts: string | boolean | null;
  cycle_label: string | null;
  cves: CVEEntry[];
  loading?: boolean;
}

export interface CVEEntry {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  publishedDate: string;
}

const SUPPORTED_TOOLS = [
  "gitlab", "jenkins", "kubernetes", "nginx", "docker", "terraform",
  "sonarqube", "apache", "nodejs", "python", "openssl", "postgresql",
  "mysql", "redis", "elasticsearch", "mongodb", "grafana", "prometheus",
  "tomcat", "rabbitmq", "vault", "consul", "ansible", "php", "ruby", "go", "java", "dotnet",
  "zabbix server", "zabbix agent", "zabbix proxy", "keycloak", "jumpserver",
];

function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] || 0;
    const nb = pb[i] || 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}

const PRODUCT_SLUGS: Record<string, string> = {
  gitlab: "gitlab", jenkins: "jenkins", kubernetes: "kubernetes", nginx: "nginx",
  docker: "docker-engine", terraform: "hashicorp-terraform", sonarqube: "sonarqube",
  apache: "apache-http-server", nodejs: "nodejs", python: "python", openssl: "openssl",
  postgresql: "postgresql", mysql: "mysql", redis: "redis", elasticsearch: "elasticsearch",
  mongodb: "mongodb", grafana: "grafana", prometheus: "prometheus", tomcat: "apache-tomcat",
  rabbitmq: "rabbitmq", vault: "hashicorp-vault", consul: "hashicorp-consul",
  ansible: "ansible-core", php: "php", ruby: "ruby", go: "go", java: "java", dotnet: "dotnet",
  "zabbix server": "zabbix", "zabbix agent": "zabbix", "zabbix proxy": "zabbix",
  zabbix: "zabbix",
  keycloak: "keycloak",
  jumpserver: "jumpserver",
};

async function fetchVersionInfo(toolName: string, version: string) {
  const empty = { latest_version: null, latest_patch_for_cycle: null, eol: null, lts: null, cycle_label: null };
  const slug = PRODUCT_SLUGS[toolName.toLowerCase().trim()];
  if (!slug) return empty;

  try {
    const res = await fetch(`https://endoflife.date/api/${slug}.json`);
    if (!res.ok) return empty;
    const cycles = await res.json();

    const latest_version = cycles?.[0]?.latest || cycles?.[0]?.cycle || null;
    const vParts = version.split(".");

    let latest_patch_for_cycle: string | null = null;
    let eol: any = null;
    let lts: any = null;
    let cycle_label: string | null = null;

    for (const c of cycles) {
      const cStr = String(c.cycle);
      const cParts = cStr.split(".");
      if (cParts[0] === vParts[0]) {
        if (cParts.length === 1 || vParts.length === 1 || cParts[1] === vParts[1]) {
          latest_patch_for_cycle = c.latest || null;
          eol = c.eol ?? null;
          lts = c.lts ?? null;
          cycle_label = cStr;
          break;
        }
      }
    }

    if (!latest_patch_for_cycle) {
      for (const c of cycles) {
        if (String(c.cycle).split(".")[0] === vParts[0]) {
          latest_patch_for_cycle = c.latest || null;
          eol = c.eol ?? null;
          lts = c.lts ?? null;
          cycle_label = String(c.cycle);
          break;
        }
      }
    }

    return { latest_version, latest_patch_for_cycle, eol, lts, cycle_label };
  } catch (err) {
    console.error("Failed to fetch version info:", err);
    return empty;
  }
}

export async function fetchCVEsFromNVD(toolName: string, version: string): Promise<CVEEntry[]> {
  try {
    const data = await nvdLookup(toolName, version);
    if ((data as any)?.rateLimited) return [];
    return data?.cves || [];
  } catch (err) {
    console.error("Failed to fetch CVEs:", err);
    return [];
  }
}

// ─── Database-backed CRUD ───

export async function getTools(): Promise<ToolEntry[]> {
  try {
    const rows = await fetchTools();
    return rows.map(mapDbToEntry);
  } catch (err) {
    console.error("Failed to fetch tools:", err);
    return [];
  }
}

function mapDbToEntry(row: any): ToolEntry {
  return {
    id: row.id,
    name: row.name,
    version: row.version,
    source_url: row.source_url,
    added_at: row.added_at || row.created_at,
    latest_version: row.latest_version,
    latest_patch_for_cycle: row.latest_patch_for_cycle,
    is_outdated: row.is_outdated,
    is_patch_outdated: row.is_patch_outdated,
    eol: row.eol,
    lts: row.lts,
    cycle_label: row.cycle_label,
    cves: typeof row.cves === "string" ? JSON.parse(row.cves) : (row.cves || []),
  };
}

export async function addTool(name: string, version: string, sourceUrl?: string): Promise<ToolEntry> {
  let versionResult = { latest_version: null as string | null, latest_patch_for_cycle: null as string | null, eol: null as any, lts: null as any, cycle_label: null as string | null };
  let cves: CVEEntry[] = [];

  try {
    [versionResult, cves] = await Promise.all([
      fetchVersionInfo(name, version),
      fetchCVEsFromNVD(name, version),
    ]);
  } catch (err) {
    console.error("Erro ao buscar dados da ferramenta:", err);
  }

  const is_outdated = versionResult.latest_version
    ? compareVersions(version, versionResult.latest_version) < 0
    : null;
  const is_patch_outdated = versionResult.latest_patch_for_cycle
    ? compareVersions(version, versionResult.latest_patch_for_cycle) < 0
    : null;

  const toolData = {
    name: name.trim(),
    version: version.trim(),
    source_url: sourceUrl?.trim() || null,
    latest_version: versionResult.latest_version,
    latest_patch_for_cycle: versionResult.latest_patch_for_cycle,
    is_outdated,
    is_patch_outdated,
    eol: versionResult.eol != null ? String(versionResult.eol) : null,
    lts: versionResult.lts != null ? String(versionResult.lts) : null,
    cycle_label: versionResult.cycle_label,
    cves,
  };

  const row = await createTool(toolData);
  return mapDbToEntry(row);
}

export async function removeTool(id: string) {
  await deleteTool(id);
}

export async function recheckTool(tool: ToolEntry): Promise<ToolEntry> {
  let currentVersion = tool.version;
  let currentName = tool.name;

  if (tool.source_url) {
    try {
      const { versionDetect } = await import("@/lib/api-client");
      const data = await versionDetect(tool.source_url);
      if (data?.version) {
        currentVersion = data.version;
        if (data.tool) currentName = data.tool;
      }
    } catch (err) {
      console.error("Failed to re-detect version from URL:", err);
    }
  }

  let versionResult = { latest_version: null as string | null, latest_patch_for_cycle: null as string | null, eol: null as any, lts: null as any, cycle_label: null as string | null };
  let cves: CVEEntry[] = [];

  try {
    [versionResult, cves] = await Promise.all([
      fetchVersionInfo(currentName, currentVersion),
      fetchCVEsFromNVD(currentName, currentVersion),
    ]);
  } catch (err) {
    console.error("Erro ao rechecar ferramenta:", err);
  }

  const is_outdated = versionResult.latest_version
    ? compareVersions(currentVersion, versionResult.latest_version) < 0
    : null;
  const is_patch_outdated = versionResult.latest_patch_for_cycle
    ? compareVersions(currentVersion, versionResult.latest_patch_for_cycle) < 0
    : null;

  const toolData = {
    name: currentName,
    version: currentVersion,
    source_url: tool.source_url,
    latest_version: versionResult.latest_version,
    latest_patch_for_cycle: versionResult.latest_patch_for_cycle,
    is_outdated,
    is_patch_outdated,
    eol: versionResult.eol != null ? String(versionResult.eol) : null,
    lts: versionResult.lts != null ? String(versionResult.lts) : null,
    cycle_label: versionResult.cycle_label,
    cves,
  };

  const row = await updateToolApi(tool.id, toolData);
  return mapDbToEntry(row);
}

export async function updateTool(id: string, name: string, version: string, sourceUrl?: string): Promise<ToolEntry> {
  let versionResult = { latest_version: null as string | null, latest_patch_for_cycle: null as string | null, eol: null as any, lts: null as any, cycle_label: null as string | null };
  let cves: CVEEntry[] = [];

  try {
    [versionResult, cves] = await Promise.all([
      fetchVersionInfo(name, version),
      fetchCVEsFromNVD(name, version),
    ]);
  } catch (err) {
    console.error("Erro ao atualizar ferramenta:", err);
  }

  const is_outdated = versionResult.latest_version
    ? compareVersions(version, versionResult.latest_version) < 0
    : null;
  const is_patch_outdated = versionResult.latest_patch_for_cycle
    ? compareVersions(version, versionResult.latest_patch_for_cycle) < 0
    : null;

  const toolData = {
    name: name.trim(),
    version: version.trim(),
    source_url: sourceUrl?.trim() || null,
    latest_version: versionResult.latest_version,
    latest_patch_for_cycle: versionResult.latest_patch_for_cycle,
    is_outdated,
    is_patch_outdated,
    eol: versionResult.eol != null ? String(versionResult.eol) : null,
    lts: versionResult.lts != null ? String(versionResult.lts) : null,
    cycle_label: versionResult.cycle_label,
    cves,
  };

  const row = await updateToolApi(id, toolData);
  return mapDbToEntry(row);
}

export const AVAILABLE_TOOLS = SUPPORTED_TOOLS.map(k =>
  k.split(" ").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ")
);
