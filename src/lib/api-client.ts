// API client for the custom Express backend
// Replaces all Supabase SDK calls

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:3010/api";

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
  const tokens = getTokens();
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(options.headers as Record<string, string> || {}),
  };

  if (tokens?.accessToken) {
    headers["Authorization"] = `Bearer ${tokens.accessToken}`;
  }

  let res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  // Try refresh on 401
  if (res.status === 401 && tokens?.refreshToken) {
    const newToken = await refreshAccessToken();
    if (newToken) {
      headers["Authorization"] = `Bearer ${newToken}`;
      res = await fetch(`${API_BASE}${path}`, { ...options, headers });
    }
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: "Erro de rede" }));
    throw new Error(body.error || `HTTP ${res.status}`);
  }

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

export { getTokens, setTokens, clearTokens };
