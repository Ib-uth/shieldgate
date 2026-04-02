import axios from 'axios';

import { getAccessToken, triggerUnauthorized } from './tokenAccessor';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const timeoutMs = Number(import.meta.env.VITE_API_TIMEOUT_MS) || 60000;

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: timeoutMs,
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
  (error) => {
    if (error.response?.status === 401) {
      const url = String(error.config?.url ?? '');
      if (!url.includes('/auth/login') && !url.includes('/auth/refresh')) {
        triggerUnauthorized();
      }
    }
    console.error('API Error:', error);
    return Promise.reject(error);
  }
);

export default apiClient;
