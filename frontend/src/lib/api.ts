// Lightweight API client for the SecureSight360 FastAPI backend.
// Reads token from localStorage and attaches Authorization: Bearer <token>.

export const API_BASE =
  (import.meta as any).env?.VITE_API_BASE_URL || "http://localhost:8000";

const TOKEN_KEY = "cs360-token";
const USER_KEY = "cs360-user";

export interface BackendUser {
  id: number;
  email: string;
  role: "admin" | "user" | string;
  full_name?: string | null;
  company_domain?: string | null;
  created_at?: string | null;
  updated_at?: string | null;
  last_login_at?: string | null;
}

export function getToken(): string | null {
  try {
    return localStorage.getItem(TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setToken(t: string | null) {
  try {
    if (t) localStorage.setItem(TOKEN_KEY, t);
    else localStorage.removeItem(TOKEN_KEY);
  } catch {}
}

export function getStoredUser(): BackendUser | null {
  try {
    const raw = localStorage.getItem(USER_KEY);
    return raw ? (JSON.parse(raw) as BackendUser) : null;
  } catch {
    return null;
  }
}

export function setStoredUser(u: BackendUser | null) {
  try {
    if (u) localStorage.setItem(USER_KEY, JSON.stringify(u));
    else localStorage.removeItem(USER_KEY);
  } catch {}
}

export class ApiError extends Error {
  status: number;
  data: any;

  constructor(message: string, status: number, data?: any) {
    super(message);
    this.status = status;
    this.data = data;
  }
}

export async function apiFetch<T = any>(
  path: string,
  init: RequestInit = {}
): Promise<T> {
  const url = path.startsWith("http") ? path : `${API_BASE}${path}`;

  const headers = new Headers(init.headers || {});

  if (!headers.has("Content-Type") && init.body && typeof init.body === "string") {
    headers.set("Content-Type", "application/json");
  }

  const tok = getToken();

  if (tok && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${tok}`);
  }

  const res = await fetch(url, { ...init, headers });

  let data: any = null;
  const text = await res.text();

  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!res.ok) {
    const msg =
      (data && (data.detail || data.message)) ||
      res.statusText ||
      `Request failed (${res.status})`;

    throw new ApiError(
      typeof msg === "string" ? msg : "Request failed",
      res.status,
      data
    );
  }

  return data as T;
}

export interface LoginResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  user: BackendUser;
}

export interface RegisterRequest {
  email: string;
  password: string;
  full_name?: string | null;
  company_name?: string | null;
}

export async function loginRequest(
  email: string,
  password: string
): Promise<LoginResponse> {
  return apiFetch<LoginResponse>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });
}

export async function registerRequest(
  payload: RegisterRequest
): Promise<LoginResponse> {
  return apiFetch<LoginResponse>("/api/v1/auth/register", {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

export async function fetchMe(): Promise<BackendUser> {
  return apiFetch<BackendUser>("/api/v1/auth/me");
}