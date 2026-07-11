"use client";

const ACCESS_KEY = "vulnint.access_token";
const REFRESH_KEY = "vulnint.refresh_token";
const USER_KEY = "vulnint.me";

export type CurrentUser = {
  id: string;
  email: string;
  full_name?: string | null;
  is_superuser: boolean;
  permissions: string[];
};

export const auth = {
  getAccess: () => (typeof window !== "undefined" ? localStorage.getItem(ACCESS_KEY) : null),
  getRefresh: () => (typeof window !== "undefined" ? localStorage.getItem(REFRESH_KEY) : null),
  setTokens: (access: string, refresh: string) => {
    localStorage.setItem(ACCESS_KEY, access);
    localStorage.setItem(REFRESH_KEY, refresh);
  },
  setUser: (u: CurrentUser) => localStorage.setItem(USER_KEY, JSON.stringify(u)),
  getUser: (): CurrentUser | null => {
    if (typeof window === "undefined") return null;
    const raw = localStorage.getItem(USER_KEY);
    return raw ? JSON.parse(raw) : null;
  },
  clear: () => {
    localStorage.removeItem(ACCESS_KEY);
    localStorage.removeItem(REFRESH_KEY);
    localStorage.removeItem(USER_KEY);
  },
};

const API_BASE = "/api/v1";

export class ApiError extends Error {
  status: number;
  detail: any;
  constructor(status: number, detail: any) {
    super(typeof detail === "string" ? detail : detail?.detail || `HTTP ${status}`);
    this.status = status;
    this.detail = detail;
  }
}

async function refreshAccess(): Promise<string | null> {
  const r = auth.getRefresh();
  if (!r) return null;
  const res = await fetch(`${API_BASE}/auth/refresh`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ refresh_token: r }),
  });
  if (!res.ok) {
    auth.clear();
    return null;
  }
  const data = await res.json();
  auth.setTokens(data.access_token, data.refresh_token);
  return data.access_token;
}

export async function api<T = any>(
  path: string,
  init: RequestInit & { json?: any } = {}
): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...((init.headers as Record<string, string>) || {}),
  };
  let token = auth.getAccess();
  if (token) headers["Authorization"] = `Bearer ${token}`;

  const opts: RequestInit = { ...init, headers };
  if (init.json !== undefined) {
    opts.body = JSON.stringify(init.json);
  }

  let res = await fetch(`${API_BASE}${path}`, opts);

  if (res.status === 401 && token) {
    const newToken = await refreshAccess();
    if (newToken) {
      headers["Authorization"] = `Bearer ${newToken}`;
      res = await fetch(`${API_BASE}${path}`, { ...opts, headers });
    } else if (typeof window !== "undefined") {
      window.location.href = "/login";
    }
  }

  const text = await res.text();
  const data = text ? safeJson(text) : null;
  if (!res.ok) throw new ApiError(res.status, data || text);
  return data as T;
}

function safeJson(s: string) {
  try { return JSON.parse(s); } catch { return s; }
}

export async function login(email: string, password: string) {
  const data = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  }).then(async (r) => {
    if (!r.ok) throw new ApiError(r.status, await r.json().catch(() => null));
    return r.json();
  });
  auth.setTokens(data.access_token, data.refresh_token);
  const me = await api<CurrentUser>("/auth/me");
  auth.setUser(me);
  return me;
}

export function logout() {
  auth.clear();
  if (typeof window !== "undefined") window.location.href = "/login";
}

export const fetcher = <T = any>(url: string) => api<T>(url);
