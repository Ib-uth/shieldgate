import React, { useState } from 'react';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';

import { useAuth } from '../context/useAuth';

function formatLoginError(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const detail = err.response?.data as { detail?: unknown } | undefined;
    if (typeof detail?.detail === 'string') return detail.detail;
    if (Array.isArray(detail?.detail)) {
      return detail.detail.map((d: { msg?: string }) => d.msg ?? '').join(', ');
    }
    if (err.message) return err.message;
  }
  return 'Login failed';
}

export function LoginPage() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);

  React.useEffect(() => {
    if (isAuthenticated) {
      navigate('/', { replace: true });
    }
  }, [isAuthenticated, navigate]);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await login(email, password);
      navigate('/', { replace: true });
    } catch (err: unknown) {
      setError(formatLoginError(err));
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="min-h-screen flex flex-col bg-slate-100">
      <header className="bg-slate-900 text-white py-4 px-6 shadow-md">
        <div className="max-w-md mx-auto flex items-center gap-2">
          <span className="text-xl font-semibold tracking-tight">ShieldGate</span>
          <span className="text-slate-400 text-sm">Admin</span>
        </div>
      </header>

      <div className="flex-1 flex items-center justify-center p-6">
        <div className="w-full max-w-md bg-white rounded-lg shadow-lg border border-slate-200 overflow-hidden">
          <div className="bg-slate-900 px-6 py-4">
            <h1 className="text-lg font-semibold text-white">Sign in</h1>
            <p className="text-slate-400 text-sm mt-1">
              Use an email containing &quot;admin&quot; for admin access (demo mode).
            </p>
          </div>
          <form onSubmit={handleSubmit} className="p-6 space-y-4">
            {error && (
              <div
                className="rounded-md bg-red-50 text-red-800 text-sm px-3 py-2 border border-red-200"
                role="alert"
              >
                {error}
              </div>
            )}
            <div>
              <label htmlFor="email" className="block text-sm font-medium text-slate-700">
                Email
              </label>
              <input
                id="email"
                name="email"
                type="email"
                autoComplete="username"
                required
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 shadow-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500"
              />
            </div>
            <div>
              <label htmlFor="password" className="block text-sm font-medium text-slate-700">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                className="mt-1 block w-full rounded-md border border-slate-300 px-3 py-2 shadow-sm focus:border-slate-500 focus:outline-none focus:ring-1 focus:ring-slate-500"
              />
            </div>
            <button
              type="submit"
              disabled={submitting}
              className="w-full flex justify-center py-2.5 px-4 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-slate-900 hover:bg-slate-800 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-slate-500 disabled:opacity-50"
            >
              {submitting ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
