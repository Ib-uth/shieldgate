import React, {
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
} from 'react';
import { useNavigate } from 'react-router-dom';

import apiClient from '../api/client';
import { setAccessTokenGetter, setUnauthorizedHandler } from '../api/tokenAccessor';

import { AuthContext, type AuthContextValue } from './auth-context';

const ACCESS_TOKEN_KEY = 'shieldgate_access_token';

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

  const login = useCallback(async (email: string, password: string) => {
    const res = await apiClient.post<{ access_token: string }>('/auth/login', {
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
