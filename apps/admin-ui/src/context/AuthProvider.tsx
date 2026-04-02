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

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [token, setToken] = useState<string | null>(null);
  const navigate = useNavigate();
  const tokenRef = useRef<string | null>(null);
  tokenRef.current = token;

  useEffect(() => {
    setAccessTokenGetter(() => tokenRef.current);
  }, [token]);

  useEffect(() => {
    setUnauthorizedHandler(() => {
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
    setToken(res.data.access_token);
  }, []);

  const logout = useCallback(() => {
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
