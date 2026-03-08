import { createContext, useContext, useState, useEffect, useCallback, type ReactNode } from "react";
import { AUTH_STORAGE_KEY } from "../../shared/appConfig";

interface AuthState {
  token: string | null;
  username: string | null;
  isAuthenticated: boolean;
}

interface AuthContextType extends AuthState {
  login: (username: string, password: string) => Promise<boolean>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextType | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [auth, setAuth] = useState<AuthState>(() => {
    // Load from localStorage on init
    const stored = localStorage.getItem(AUTH_STORAGE_KEY);
    if (stored) {
      try {
        const parsed = JSON.parse(stored);
        return {
          token: parsed.token || null,
          username: parsed.username || null,
          isAuthenticated: !!parsed.token
        };
      } catch {
        // Invalid stored data
      }
    }
    return { token: null, username: null, isAuthenticated: false };
  });

  // Persist to localStorage
  useEffect(() => {
    if (auth.isAuthenticated) {
      localStorage.setItem(AUTH_STORAGE_KEY, JSON.stringify({
        token: auth.token,
        username: auth.username
      }));
    } else {
      localStorage.removeItem(AUTH_STORAGE_KEY);
    }
  }, [auth]);

  const login = useCallback(async (username: string, password: string): Promise<boolean> => {
    try {
      const response = await fetch("/api/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password })
      });

      if (!response.ok) {
        return false;
      }

      const data = await response.json();
      setAuth({
        token: data.token,
        username: data.username,
        isAuthenticated: true
      });
      return true;
    } catch {
      return false;
    }
  }, []);

  const logout = useCallback(() => {
    setAuth({ token: null, username: null, isAuthenticated: false });
  }, []);

  return (
    <AuthContext.Provider value={{ ...auth, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within AuthProvider");
  }
  return context;
}

// Helper to get auth headers
export function getAuthHeaders(): HeadersInit {
  const stored = localStorage.getItem(AUTH_STORAGE_KEY);
  if (stored) {
    try {
      const { token } = JSON.parse(stored);
      if (token) {
        return { Authorization: `Bearer ${token}` };
      }
    } catch {
      // Invalid
    }
  }
  return {};
}
