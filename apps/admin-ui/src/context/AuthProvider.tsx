import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { useNavigate } from 'react-router-dom';

import { refreshClient } from '../api/client';
import {
  setAccessTokenGetter,
  setAccessTokenUpdater,
  setUnauthorizedHandler,
} from '../api/tokenAccessor';

import { AuthContext, type AuthContextValue } from './auth-context';

const ACCESS_TOKEN_KEY = 'shieldgate_access_token';

/** Access tokens expire in 15m; refresh before expiry so polling does not 401. */
const PROACTIVE_REFRESH_MS = 10 * 60 * 1000;

function readStoredToken(): string | null {
  try {
    return sessionStorage.getItem(ACCESS_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(readStoredToken);
  const navigate = useNavigate();
  const tokenRef = useRef<string | null>(null);
  tokenRef.current = token;

  useEffect(() => {
    setAccessTokenGetter(() => tokenRef.current);
  }, [token]);

  useEffect(() => {
    setAccessTokenUpdater((access: string) => {
      try {
        sessionStorage.setItem(ACCESS_TOKEN_KEY, access);
      } catch {
        /* ignore */
      }
      setToken(access);
    });
    return () => setAccessTokenUpdater(() => {});
  }, []);

  useEffect(() => {
    setUnauthorizedHandler(() => {
      try {
        sessionStorage.removeItem(ACCESS_TOKEN_KEY);
      } catch {
        /* ignore */
      }
      setToken(null);
      navigate('/login', { replace: true });
    });
    return () => setUnauthorizedHandler(null);
  }, [navigate]);

  useEffect(() => {
    if (!token) return undefined;

    const id = window.setInterval(async () => {
      try {
        const { data } = await refreshClient.post<{ access_token: string }>(
          '/auth/refresh',
          {}
        );
        try {
          sessionStorage.setItem(ACCESS_TOKEN_KEY, data.access_token);
        } catch {
          /* ignore */
        }
        setToken(data.access_token);
      } catch {
        /* next API call will 401-intercept or fail; avoid logout loop here */
      }
    }, PROACTIVE_REFRESH_MS);

    return () => window.clearInterval(id);
  }, [token]);

  const login = useCallback(async (email: string, password: string) => {
    const res = await refreshClient.post<{ access_token: string }>('/auth/login', {
      email,
      password,
    });
    const access = res.data.access_token;
    try {
      sessionStorage.setItem(ACCESS_TOKEN_KEY, access);
    } catch {
      /* ignore quota / private mode */
    }
    setToken(access);
  }, []);

  const logout = useCallback(() => {
    try {
      sessionStorage.removeItem(ACCESS_TOKEN_KEY);
    } catch {
      /* ignore */
    }
    setToken(null);
    navigate('/login', { replace: true });
  }, [navigate]);

  const value = useMemo(
    (): AuthContextValue => ({
      token,
      login,
      logout,
      isAuthenticated: !!token,
    }),
    [token, login, logout]
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
