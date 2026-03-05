import { supabase } from "@/integrations/supabase/client";

export interface ToolEntry {
  id: string;
  name: string;
  version: string;
  addedAt: string;
  latestVersion: string | null;
  latestPatchForCycle: string | null;
  isOutdated: boolean | null;
  isPatchOutdated: boolean | null;
  eol: string | boolean | null;
  lts: string | boolean | null;
  cycleLabel: string | null;
  cves: CVEEntry[];
  loading?: boolean;
}

export interface CVEEntry {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  publishedDate: string;
}

// Tools supported by endoflife.date (for autocomplete)
const SUPPORTED_TOOLS = [
  "gitlab", "jenkins", "kubernetes", "nginx", "docker", "terraform",
  "sonarqube", "apache", "nodejs", "python", "openssl", "postgresql",
  "mysql", "redis", "elasticsearch", "mongodb", "grafana", "prometheus",
  "tomcat", "rabbitmq", "vault", "consul", "ansible", "php", "ruby", "go", "java", "dotnet",
  "zabbix server", "zabbix agent", "zabbix proxy",
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
};

async function fetchVersionInfo(toolName: string, version: string): Promise<{
  latestVersion: string | null;
  latestPatchForCycle: string | null;
  eol: string | boolean | null;
  lts: string | boolean | null;
  cycleLabel: string | null;
}> {
  const empty = { latestVersion: null, latestPatchForCycle: null, eol: null, lts: null, cycleLabel: null };
  const slug = PRODUCT_SLUGS[toolName.toLowerCase().trim()];
  if (!slug) return empty;

  try {
    // Fetch all cycles from endoflife.date (public CORS-enabled API)
    const res = await fetch(`https://endoflife.date/api/${slug}.json`);
    if (!res.ok) return empty;
    const cycles = await res.json();

    const latestVersion = cycles?.[0]?.latest || cycles?.[0]?.cycle || null;
    const vParts = version.split(".");

    let latestPatchForCycle: string | null = null;
    let eol: any = null;
    let lts: any = null;
    let cycleLabel: string | null = null;

    // Try exact major.minor match
    for (const c of cycles) {
      const cStr = String(c.cycle);
      const cParts = cStr.split(".");
      if (cParts[0] === vParts[0]) {
        if (cParts.length === 1 || vParts.length === 1 || cParts[1] === vParts[1]) {
          latestPatchForCycle = c.latest || null;
          eol = c.eol ?? null;
          lts = c.lts ?? null;
          cycleLabel = cStr;
          break;
        }
      }
    }

    // Fallback: first cycle with same major
    if (!latestPatchForCycle) {
      for (const c of cycles) {
        if (String(c.cycle).split(".")[0] === vParts[0]) {
          latestPatchForCycle = c.latest || null;
          eol = c.eol ?? null;
          lts = c.lts ?? null;
          cycleLabel = String(c.cycle);
          break;
        }
      }
    }

    return { latestVersion, latestPatchForCycle, eol, lts, cycleLabel };
  } catch (err) {
    console.error("Failed to fetch version info:", err);
    return empty;
  }
}

export async function fetchCVEsFromNVD(toolName: string, version: string): Promise<CVEEntry[]> {
  try {
    const { data, error } = await supabase.functions.invoke("nvd-lookup", {
      body: { toolName, version },
    });

    if (error) {
      console.error("Error calling nvd-lookup:", error);
      return [];
    }

    if (data?.rateLimited) {
      console.warn("NVD API rate limited, returning empty CVEs");
      return [];
    }

    return data?.cves || [];
  } catch (err) {
    console.error("Failed to fetch CVEs:", err);
    return [];
  }
}

export function getStoredTools(): ToolEntry[] {
  try {
    const data = localStorage.getItem("sec-tools");
    return data ? JSON.parse(data) : [];
  } catch {
    return [];
  }
}

export function saveTools(tools: ToolEntry[]) {
  localStorage.setItem("sec-tools", JSON.stringify(tools));
}

export async function addTool(name: string, version: string): Promise<ToolEntry> {
  const entry: ToolEntry = {
    id: crypto.randomUUID(),
    name: name.trim(),
    version: version.trim(),
    addedAt: new Date().toISOString(),
    latestVersion: null,
    latestPatchForCycle: null,
    isOutdated: null,
    isPatchOutdated: null,
    eol: null,
    lts: null,
    cycleLabel: null,
    cves: [],
    loading: true,
  };

  const tools = getStoredTools();
  tools.unshift(entry);
  saveTools(tools);

  // Fetch version info AND CVEs in parallel
  const [versionResult, cves] = await Promise.all([
    fetchVersionInfo(name, version),
    fetchCVEsFromNVD(name, version),
  ]);

  entry.latestVersion = versionResult.latestVersion;
  entry.latestPatchForCycle = versionResult.latestPatchForCycle;
  entry.eol = versionResult.eol;
  entry.lts = versionResult.lts;
  entry.cycleLabel = versionResult.cycleLabel;
  entry.isOutdated = versionResult.latestVersion
    ? compareVersions(version, versionResult.latestVersion) < 0
    : null;
  entry.isPatchOutdated = versionResult.latestPatchForCycle
    ? compareVersions(version, versionResult.latestPatchForCycle) < 0
    : null;
  entry.cves = cves;
  entry.loading = false;

  // Update stored data
  const updatedTools = getStoredTools().map(t => t.id === entry.id ? entry : t);
  saveTools(updatedTools);

  return entry;
}

export function removeTool(id: string) {
  const tools = getStoredTools().filter(t => t.id !== id);
  saveTools(tools);
}

export const AVAILABLE_TOOLS = SUPPORTED_TOOLS.map(k =>
  k.split(" ").map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(" ")
);
