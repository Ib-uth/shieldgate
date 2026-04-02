import { createContext } from 'react';

export interface AuthContextValue {
  token: string | null;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
  isAuthenticated: boolean;
}

export const AuthContext = createContext<AuthContextValue | null>(null);
