import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import {
  type BackendUser,
  type RegisterRequest,
  fetchMe,
  getStoredUser,
  getToken,
  loginRequest,
  registerRequest,
  setStoredUser,
  setToken,
} from "./api";

interface AuthContextValue {
  user: BackendUser | null;
  token: string | null;
  loading: boolean;
  isAuthenticated: boolean;
  isAdmin: boolean;
  login: (email: string, password: string) => Promise<BackendUser>;
  register: (payload: RegisterRequest) => Promise<BackendUser>;
  logout: () => void;
  refresh: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<BackendUser | null>(() => getStoredUser());
  const [token, setTok] = useState<string | null>(() => getToken());
  const [loading, setLoading] = useState<boolean>(!!getToken());

  useEffect(() => {
    let cancelled = false;

    if (!getToken()) {
      setLoading(false);
      return;
    }

    (async () => {
      try {
        const me = await fetchMe();

        if (cancelled) return;

        setUser(me);
        setStoredUser(me);
      } catch {
        if (cancelled) return;

        setToken(null);
        setStoredUser(null);
        setTok(null);
        setUser(null);
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const login = useCallback(async (email: string, password: string) => {
    const res = await loginRequest(email, password);

    setToken(res.access_token);
    setStoredUser(res.user);
    setTok(res.access_token);
    setUser(res.user);

    return res.user;
  }, []);

  const register = useCallback(async (payload: RegisterRequest) => {
    const res = await registerRequest(payload);

    setToken(res.access_token);
    setStoredUser(res.user);
    setTok(res.access_token);
    setUser(res.user);

    return res.user;
  }, []);

  const logout = useCallback(() => {
    setToken(null);
    setStoredUser(null);
    setTok(null);
    setUser(null);
  }, []);

  const refresh = useCallback(async () => {
    try {
      const me = await fetchMe();

      setUser(me);
      setStoredUser(me);
    } catch {
      // Ignore refresh errors.
    }
  }, []);

  const value = useMemo<AuthContextValue>(
    () => ({
      user,
      token,
      loading,
      isAuthenticated: !!token && !!user,
      isAdmin: user?.role === "admin",
      login,
      register,
      logout,
      refresh,
    }),
    [user, token, loading, login, register, logout, refresh]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);

  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }

  return ctx;
}