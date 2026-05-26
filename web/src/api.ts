export const BASE = (import.meta.env.VITE_API_URL as string) || "http://localhost:8000";

export function token(): string | null {
  return localStorage.getItem("token");
}

export function refreshToken(): string | null {
  return localStorage.getItem("refresh_token");
}

export function storeTokens(access: string, refresh: string) {
  localStorage.setItem("token", access);
  localStorage.setItem("refresh_token", refresh);
}

export function clearTokens() {
  localStorage.removeItem("token");
  localStorage.removeItem("refresh_token");
}

let _refreshing: Promise<string | null> | null = null;

async function tryRefresh(): Promise<string | null> {
  if (_refreshing) return _refreshing;
  const rt = refreshToken();
  if (!rt) return null;
  _refreshing = (async () => {
    try {
      const res = await fetch(`${BASE}/v1/auth/refresh`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ refresh_token: rt }),
      });
      if (!res.ok) return null;
      const data = await res.json();
      storeTokens(data.access_token, data.refresh_token);
      return data.access_token as string;
    } catch {
      return null;
    } finally {
      _refreshing = null;
    }
  })();
  return _refreshing;
}

export async function api<T = unknown>(path: string, init: RequestInit = {}): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init.headers as Record<string, string> | undefined),
  };
  const t = token();
  if (t) headers["Authorization"] = `Bearer ${t}`;
  const res = await fetch(`${BASE}${path}`, { ...init, headers });

  if (res.status === 401) {
    const newToken = await tryRefresh();
    if (newToken) {
      const retryHeaders = { ...headers, Authorization: `Bearer ${newToken}` };
      const retry = await fetch(`${BASE}${path}`, { ...init, headers: retryHeaders });
      if (retry.status === 401) {
        clearTokens();
        window.location.href = "/login";
        throw new Error("session expired");
      }
      if (!retry.ok) {
        const body = await retry.text();
        throw new Error(`${retry.status}: ${body}`);
      }
      if (retry.status === 204) return undefined as T;
      return retry.json();
    }
    clearTokens();
    window.location.href = "/login";
    throw new Error("session expired");
  }

  if (!res.ok) {
    const body = await res.text();
    throw new Error(`${res.status}: ${body}`);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}
