import { supabase } from "@/integrations/supabase/client";

export interface ToolEntry {
  id: string;
  name: string;
  version: string;
  addedAt: string;
  latestVersion: string | null;
  isOutdated: boolean | null;
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

async function fetchLatestVersion(toolName: string): Promise<{ latestVersion: string | null }> {
  try {
    const { data, error } = await supabase.functions.invoke("version-check", {
      body: { toolName },
    });

    if (error) {
      console.error("Error calling version-check:", error);
      return { latestVersion: null };
    }

    return { latestVersion: data?.latestVersion || null };
  } catch (err) {
    console.error("Failed to fetch latest version:", err);
    return { latestVersion: null };
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
    isOutdated: null,
    cves: [],
    loading: true,
  };

  const tools = getStoredTools();
  tools.unshift(entry);
  saveTools(tools);

  // Fetch latest version AND CVEs in parallel
  const [versionResult, cves] = await Promise.all([
    fetchLatestVersion(name),
    fetchCVEsFromNVD(name, version),
  ]);

  entry.latestVersion = versionResult.latestVersion;
  entry.isOutdated = versionResult.latestVersion
    ? compareVersions(version, versionResult.latestVersion) < 0
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

export const AVAILABLE_TOOLS = SUPPORTED_TOOLS.map(k => k.charAt(0).toUpperCase() + k.slice(1));
