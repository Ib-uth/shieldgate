import axios from 'axios';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

const timeoutMs = Number(import.meta.env.VITE_API_TIMEOUT_MS) || 60000;

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  timeout: timeoutMs,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Request interceptor for error handling
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    console.error('API Error:', error);
    return Promise.reject(error);
  }
);

export default apiClient;
