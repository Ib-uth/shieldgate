import axios from 'axios';

import {
  applyRefreshedAccessToken,
  getAccessToken,
  triggerUnauthorized,
} from './tokenAccessor';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const timeoutMs = Number(import.meta.env.VITE_API_TIMEOUT_MS) || 60000;

/** Used for POST /auth/refresh without tripping the 401 interceptor loop. */
export const refreshClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: timeoutMs,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: timeoutMs,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
  },
});

apiClient.interceptors.request.use((config) => {
  const token = getAccessToken();
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

apiClient.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config as typeof error.config & {
      _retry?: boolean;
    };
    const status = error.response?.status;

    if (status === 401 && originalRequest && !originalRequest._retry) {
      const url = String(originalRequest.url ?? '');
      if (!url.includes('/auth/login') && !url.includes('/auth/refresh')) {
        originalRequest._retry = true;
        try {
          const { data } = await refreshClient.post<{ access_token: string }>(
            '/auth/refresh',
            {}
          );
          applyRefreshedAccessToken(data.access_token);
          originalRequest.headers.Authorization = `Bearer ${data.access_token}`;
          return apiClient(originalRequest);
        } catch {
          triggerUnauthorized();
        }
      }
    }

    if (status !== 401 || String(originalRequest?.url ?? '').includes('/auth/')) {
      console.error('API Error:', error);
    }
    return Promise.reject(error);
  }
);

export default apiClient;
