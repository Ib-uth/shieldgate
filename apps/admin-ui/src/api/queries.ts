import { useQuery } from 'react-query';
import apiClient from './client';
import { HealthStatus, MetricsData, RequestLog, AdminStats, ThreatScoreDistribution } from '../types/api';

export const useHealthStatus = () => {
  return useQuery<HealthStatus>(
    'health',
    async () => {
      const response = await apiClient.get('/health');
      return response.data;
    },
    {
      refetchInterval: 30000, // Health check every 30 seconds
    }
  );
};

export const useMetrics = (hours: number = 1) => {
  return useQuery<MetricsData>(
    ['metrics', hours],
    async () => {
      const response = await apiClient.get(`/metrics?hours=${hours}`);
      return response.data;
    },
    {
      refetchInterval: 10000, // Refresh every 10 seconds
    }
  );
};

export const useRecentRequests = (limit: number = 50, blockedOnly: boolean = false) => {
  return useQuery<RequestLog[]>(
    ['requests', limit, blockedOnly],
    async () => {
      const params = new URLSearchParams({
        limit: limit.toString(),
        blocked_only: blockedOnly.toString(),
      });
      const response = await apiClient.get(`/metrics/requests?${params}`);
      return response.data;
    },
    {
      refetchInterval: 5000, // Refresh every 5 seconds
    }
  );
};

export const useBlockedIPs = (limit: number = 100) => {
  return useQuery(
    ['blocked-ips', limit],
    async () => {
      const response = await apiClient.get(`/metrics/blocked-ips?limit=${limit}`);
      return response.data;
    },
    {
      refetchInterval: 15000, // Refresh every 15 seconds
    }
  );
};

export const useAdminStats = () => {
  return useQuery<AdminStats>(
    'admin-stats',
    async () => {
      const response = await apiClient.get('/admin/stats');
      return response.data;
    },
    {
      refetchInterval: 10000, // Admin stats every 10 seconds
    }
  );
};

export const useThreatScores = (hours: number = 24) => {
  return useQuery<ThreatScoreDistribution>(
    ['threat-scores', hours],
    async () => {
      const response = await apiClient.get(`/admin/threat-scores?hours=${hours}`);
      return response.data;
    },
    {
      refetchInterval: 30000, // Refresh every 30 seconds
    }
  );
};
