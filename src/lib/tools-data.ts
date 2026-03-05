export interface ToolEntry {
  id: string;
  name: string;
  version: string;
  addedAt: string;
  latestVersion: string | null;
  isOutdated: boolean | null;
  cves: CVEEntry[];
}

export interface CVEEntry {
  id: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  publishedDate: string;
}

// Known tools and their latest versions (mock database)
const KNOWN_TOOLS: Record<string, { latest: string; cves: Record<string, CVEEntry[]> }> = {
  gitlab: {
    latest: "17.8.0",
    cves: {
      "15.3": [
        { id: "CVE-2022-3870", severity: "critical", description: "Remote code execution via specially crafted merge request", publishedDate: "2022-11-15" },
        { id: "CVE-2022-3514", severity: "high", description: "Server-side request forgery in project imports", publishedDate: "2022-10-28" },
        { id: "CVE-2022-3483", severity: "medium", description: "Information disclosure through API endpoint", publishedDate: "2022-10-20" },
      ],
      "16.0": [
        { id: "CVE-2023-2825", severity: "critical", description: "Path traversal vulnerability allows reading arbitrary files", publishedDate: "2023-05-23" },
      ],
      "16.5": [
        { id: "CVE-2023-6033", severity: "high", description: "Cross-site scripting in merge request diffs", publishedDate: "2023-11-30" },
      ],
    },
  },
  jenkins: {
    latest: "2.450",
    cves: {
      "2.346": [
        { id: "CVE-2023-27898", severity: "critical", description: "Cross-site scripting vulnerability in plugin manager", publishedDate: "2023-03-08" },
        { id: "CVE-2023-27905", severity: "high", description: "Stored XSS via update center", publishedDate: "2023-03-08" },
      ],
      "2.300": [
        { id: "CVE-2022-20612", severity: "critical", description: "CSRF protection bypass for build actions", publishedDate: "2022-01-12" },
        { id: "CVE-2022-20613", severity: "high", description: "Stored XSS vulnerability in build descriptions", publishedDate: "2022-01-12" },
        { id: "CVE-2022-20614", severity: "medium", description: "Permission check bypass in REST API", publishedDate: "2022-01-12" },
      ],
    },
  },
  kubernetes: {
    latest: "1.30.0",
    cves: {
      "1.24": [
        { id: "CVE-2023-5528", severity: "critical", description: "Insufficient input sanitization on Windows nodes leads to privilege escalation", publishedDate: "2023-11-14" },
      ],
      "1.26": [
        { id: "CVE-2023-2728", severity: "high", description: "Bypassing mountable secrets policy via ephemeral containers", publishedDate: "2023-06-15" },
      ],
    },
  },
  nginx: {
    latest: "1.27.3",
    cves: {
      "1.18": [
        { id: "CVE-2021-23017", severity: "critical", description: "DNS resolver vulnerability allowing crash or code execution", publishedDate: "2021-05-25" },
        { id: "CVE-2021-3618", severity: "high", description: "ALPACA attack allowing cross-protocol attacks", publishedDate: "2021-07-15" },
      ],
      "1.22": [
        { id: "CVE-2022-41741", severity: "high", description: "Memory corruption in mp4 module", publishedDate: "2022-10-19" },
      ],
    },
  },
  docker: {
    latest: "27.5.0",
    cves: {
      "20.10": [
        { id: "CVE-2024-21626", severity: "critical", description: "Container escape via runc internal file descriptor leak", publishedDate: "2024-01-31" },
        { id: "CVE-2023-28842", severity: "high", description: "Encrypted overlay network traffic may be unencrypted", publishedDate: "2023-04-04" },
      ],
      "24.0": [
        { id: "CVE-2024-24557", severity: "high", description: "Classic builder cache poisoning vulnerability", publishedDate: "2024-02-01" },
      ],
    },
  },
  terraform: {
    latest: "1.9.8",
    cves: {
      "1.0": [
        { id: "CVE-2023-0475", severity: "medium", description: "Sensitive values in plan output not properly redacted", publishedDate: "2023-02-09" },
      ],
    },
  },
  sonarqube: {
    latest: "10.7.0",
    cves: {
      "9.0": [
        { id: "CVE-2023-6944", severity: "high", description: "Authentication bypass in SAML integration", publishedDate: "2023-12-20" },
      ],
    },
  },
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

export function lookupTool(name: string, version: string): { latestVersion: string | null; isOutdated: boolean | null; cves: CVEEntry[] } {
  const key = name.toLowerCase().trim();
  const tool = KNOWN_TOOLS[key];
  
  if (!tool) {
    return { latestVersion: null, isOutdated: null, cves: [] };
  }

  const isOutdated = compareVersions(version, tool.latest) < 0;
  
  // Find CVEs for the given version or earlier
  let cves: CVEEntry[] = [];
  for (const [ver, verCves] of Object.entries(tool.cves)) {
    if (compareVersions(version, ver) <= 0) {
      cves = [...cves, ...verCves];
    }
  }
  // Remove duplicates
  const seen = new Set<string>();
  cves = cves.filter(c => {
    if (seen.has(c.id)) return false;
    seen.add(c.id);
    return true;
  });

  return { latestVersion: tool.latest, isOutdated, cves };
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

export function addTool(name: string, version: string): ToolEntry {
  const lookup = lookupTool(name, version);
  const entry: ToolEntry = {
    id: crypto.randomUUID(),
    name: name.trim(),
    version: version.trim(),
    addedAt: new Date().toISOString(),
    latestVersion: lookup.latestVersion,
    isOutdated: lookup.isOutdated,
    cves: lookup.cves,
  };
  const tools = getStoredTools();
  tools.unshift(entry);
  saveTools(tools);
  return entry;
}

export function removeTool(id: string) {
  const tools = getStoredTools().filter(t => t.id !== id);
  saveTools(tools);
}

export const AVAILABLE_TOOLS = Object.keys(KNOWN_TOOLS).map(k => k.charAt(0).toUpperCase() + k.slice(1));
