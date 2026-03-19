// API client for the custom Express backend
// Replaces all Supabase SDK calls

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:3010/api";
const BACKEND_BASE = API_BASE.replace(/\/api\/?$/, "");

/** Resolve a backend-relative path (e.g. /uploads/...) to a full URL */
export function resolveBackendUrl(path: string | null): string | null {
  if (!path) return null;
  if (path.startsWith("http://") || path.startsWith("https://")) return path;
  return `${BACKEND_BASE}${path}`;
}

interface TokenPair {
  accessToken: string;
  refreshToken: string;
}

function getTokens(): TokenPair | null {
  const raw = localStorage.getItem("auth_tokens");
  return raw ? JSON.parse(raw) : null;
}

function setTokens(tokens: TokenPair) {
  localStorage.setItem("auth_tokens", JSON.stringify(tokens));
}

function clearTokens() {
  localStorage.removeItem("auth_tokens");
}

async function refreshAccessToken(): Promise<string | null> {
  const tokens = getTokens();
  if (!tokens?.refreshToken) return null;

  try {
    const res = await fetch(`${API_BASE}/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refreshToken: tokens.refreshToken }),
    });
    if (!res.ok) {
      clearTokens();
      return null;
    }
    const data = await res.json();
    setTokens({ accessToken: data.accessToken, refreshToken: data.refreshToken });
    return data.accessToken;
  } catch {
    clearTokens();
    return null;
  }
}

async function apiFetch<T = any>(path: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE}${path}`;
  console.log(`[API] ${options.method || "GET"} ${url}`);
  const tokens = getTokens();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> || {}),
  };

  if (tokens?.accessToken) {
    headers["Authorization"] = `Bearer ${tokens.accessToken}`;
  }

  let res = await fetch(url, { ...options, headers });

  // Try refresh on 401
  if (res.status === 401 && tokens?.refreshToken) {
    const newToken = await refreshAccessToken();
    if (newToken) {
      headers["Authorization"] = `Bearer ${newToken}`;
      res = await fetch(url, { ...options, headers });
    }
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: "Erro de rede" }));
    console.error(`[API] Erro ${res.status}:`, body);
    throw new Error(body.error || `HTTP ${res.status}`);
  }

  console.log(`[API] ${res.status} OK`);
  return res.json();
}

// Auth
export async function login(email: string, password: string) {
  const data = await apiFetch<{
    accessToken: string;
    refreshToken: string;
    user: { id: string; email: string; full_name: string };
    isAdmin: boolean;
  }>("/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
  setTokens({ accessToken: data.accessToken, refreshToken: data.refreshToken });
  return data;
}

export async function getMe() {
  return apiFetch<{
    user: { id: string; email: string; full_name: string };
    isAdmin: boolean;
  }>("/auth/me");
}

export async function logout() {
  const tokens = getTokens();
  try {
    await apiFetch("/auth/logout", {
      method: "POST",
      body: JSON.stringify({ refreshToken: tokens?.refreshToken }),
    });
  } catch { /* ignore */ }
  clearTokens();
}

export function isAuthenticated(): boolean {
  return !!getTokens()?.accessToken;
}

// OIDC Providers
export async function getPublicProviders() {
  return apiFetch<any[]>("/providers/public");
}

export async function getProviders() {
  return apiFetch<any[]>("/providers");
}

export async function saveProvider(provider: any) {
  if (provider.id) {
    return apiFetch(`/providers/${provider.id}`, {
      method: "PUT",
      body: JSON.stringify(provider),
    });
  }
  return apiFetch("/providers", {
    method: "POST",
    body: JSON.stringify(provider),
  });
}

export async function deleteProvider(id: string) {
  return apiFetch(`/providers/${id}`, { method: "DELETE" });
}

// OIDC Callback
export async function oidcCallback(code: string, providerId: string, redirectUri: string) {
  const data = await apiFetch<{
    accessToken: string;
    refreshToken: string;
    user: { id: string; email: string; full_name: string };
    isAdmin: boolean;
  }>("/oidc/callback", {
    method: "POST",
    body: JSON.stringify({ code, providerId, redirectUri }),
  });
  setTokens({ accessToken: data.accessToken, refreshToken: data.refreshToken });
  return data;
}

// Tools API
export async function nvdLookup(toolName: string, version: string) {
  return apiFetch<{ cves: any[]; total?: number }>("/tools/nvd-lookup", {
    method: "POST",
    body: JSON.stringify({ toolName, version }),
  });
}

export async function versionDetect(url: string) {
  return apiFetch<{ success: boolean; tool: string | null; version: string | null; message: string }>("/tools/version-detect", {
    method: "POST",
    body: JSON.stringify({ url }),
  });
}

// Tools CRUD
export async function fetchTools() {
  return apiFetch<any[]>("/tools");
}

export async function createTool(tool: Record<string, any>) {
  return apiFetch<any>("/tools", {
    method: "POST",
    body: JSON.stringify(tool),
  });
}

export async function updateToolApi(id: string, tool: Record<string, any>) {
  return apiFetch<any>(`/tools/${id}`, {
    method: "PUT",
    body: JSON.stringify(tool),
  });
}

export async function deleteTool(id: string) {
  return apiFetch(`/tools/${id}`, { method: "DELETE" });
}

export async function changeToolCategory(id: string, category: string) {
  return apiFetch<any>(`/tools/${id}/category`, {
    method: "PATCH",
    body: JSON.stringify({ category }),
  });
}

// Sub-versions
export async function fetchSubVersions(toolId: string) {
  return apiFetch<any[]>(`/tools/${toolId}/versions`);
}

export async function createSubVersion(toolId: string, data: Record<string, any>) {
  return apiFetch<any>(`/tools/${toolId}/versions`, {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function deleteSubVersion(toolId: string, versionId: string) {
  return apiFetch(`/tools/${toolId}/versions/${versionId}`, { method: "DELETE" });
}

// Profile
export async function updateProfile(data: { full_name?: string; email?: string }) {
  return apiFetch<{ user: { id: string; email: string; full_name: string } }>("/auth/profile", {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function changePassword(currentPassword: string, newPassword: string) {
  return apiFetch("/auth/change-password", {
    method: "POST",
    body: JSON.stringify({ currentPassword, newPassword }),
  });
}

// Admin: User management
export async function listUsers() {
  return apiFetch<any[]>("/auth/users");
}

export async function createUser(data: { email: string; password: string; full_name: string; role?: string }) {
  return apiFetch<any>("/auth/users", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function updateUserRole(userId: string, role: string) {
  return apiFetch(`/auth/users/${userId}/role`, {
    method: "PUT",
    body: JSON.stringify({ role }),
  });
}

export async function deleteUser(userId: string) {
  return apiFetch(`/auth/users/${userId}`, { method: "DELETE" });
}

// Branding
export async function getBranding() {
  return apiFetch<any>("/branding");
}

export async function saveBranding(data: {
  app_name: string;
  app_subtitle: string;
  logo_url: string | null;
  primary_color: string;
  accent_color: string;
}) {
  return apiFetch<any>("/branding", {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function uploadLogo(file: File): Promise<{ logo_url: string }> {
  const url = `${API_BASE}/branding/logo`;
  const tokens = getTokens();
  const formData = new FormData();
  formData.append("logo", file);

  const headers: Record<string, string> = {};
  if (tokens?.accessToken) {
    headers["Authorization"] = `Bearer ${tokens.accessToken}`;
  }

  const res = await fetch(url, { method: "POST", headers, body: formData });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: "Erro de rede" }));
    throw new Error(body.error || `HTTP ${res.status}`);
  }
  return res.json();
}

// Discovery
export interface DiscoveryResult {
  ip: string;
  port: number;
  service: string;
  tool: string | null;
  version: string | null;
  banner: string;
}

export async function discoveryScan(cidr: string, ports?: number[]) {
  return apiFetch<{
    total_hosts: number;
    total_ports_scanned: number;
    results: DiscoveryResult[];
  }>("/discovery/scan", {
    method: "POST",
    body: JSON.stringify({ cidr, ports }),
  });
}

export interface DiscoveryScanHistory {
  id: string;
  cidr: string;
  total_hosts: number;
  total_ports_scanned: number;
  results: DiscoveryResult[];
  created_at: string;
}

export async function getDiscoveryHistory() {
  return apiFetch<DiscoveryScanHistory[]>("/discovery/history");
}

// Znuny Integration
export interface ZnunySettings {
  id?: string;
  enabled: boolean;
  base_url: string;
  username: string;
  password: string;
  queue: string;
  priority: string;
  ticket_type: string;
  customer_user: string;
}

export async function getZnunySettings() {
  return apiFetch<ZnunySettings>("/znuny");
}

export async function saveZnunySettings(data: ZnunySettings) {
  return apiFetch<ZnunySettings>("/znuny", {
    method: "PUT",
    body: JSON.stringify(data),
  });
}

export async function testZnunyConnection(data: { base_url: string; username: string; password: string }) {
  return apiFetch<{ success: boolean; message: string }>("/znuny/test", {
    method: "POST",
    body: JSON.stringify(data),
  });
}

export async function createZnunyTicket(toolName: string, version: string, cves: any[]) {
  return apiFetch<{ success: boolean; ticketId?: string; ticketNumber?: string; message: string }>("/znuny/create-ticket", {
    method: "POST",
    body: JSON.stringify({ toolName, version, cves }),
  });
}

export { getTokens, setTokens, clearTokens };
