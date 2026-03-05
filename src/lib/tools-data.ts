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

// Known tools and their latest versions (used for version comparison)
const KNOWN_TOOLS: Record<string, string> = {
  gitlab: "17.8.0",
  jenkins: "2.450",
  kubernetes: "1.30.0",
  nginx: "1.27.3",
  docker: "27.5.0",
  terraform: "1.9.8",
  sonarqube: "10.7.0",
  apache: "2.4.62",
  nodejs: "22.0.0",
  python: "3.13.0",
  openssl: "3.3.0",
  postgresql: "17.0",
  mysql: "8.4.0",
  redis: "7.4.0",
  elasticsearch: "8.15.0",
  mongodb: "7.0.0",
  grafana: "11.0.0",
  prometheus: "2.53.0",
};

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

export function lookupToolVersion(name: string, version: string): { latestVersion: string | null; isOutdated: boolean | null } {
  const key = name.toLowerCase().trim();
  const latest = KNOWN_TOOLS[key];

  if (!latest) {
    return { latestVersion: null, isOutdated: null };
  }

  const isOutdated = compareVersions(version, latest) < 0;
  return { latestVersion: latest, isOutdated };
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
  const versionInfo = lookupToolVersion(name, version);
  
  const entry: ToolEntry = {
    id: crypto.randomUUID(),
    name: name.trim(),
    version: version.trim(),
    addedAt: new Date().toISOString(),
    latestVersion: versionInfo.latestVersion,
    isOutdated: versionInfo.isOutdated,
    cves: [],
    loading: true,
  };

  const tools = getStoredTools();
  tools.unshift(entry);
  saveTools(tools);

  // Fetch real CVEs asynchronously
  const cves = await fetchCVEsFromNVD(name, version);
  entry.cves = cves;
  entry.loading = false;

  // Update stored data with CVEs
  const updatedTools = getStoredTools().map(t => t.id === entry.id ? entry : t);
  saveTools(updatedTools);

  return entry;
}

export function removeTool(id: string) {
  const tools = getStoredTools().filter(t => t.id !== id);
  saveTools(tools);
}

export const AVAILABLE_TOOLS = Object.keys(KNOWN_TOOLS).map(k => k.charAt(0).toUpperCase() + k.slice(1));
