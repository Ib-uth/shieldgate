import { useQuery } from 'react-query';
import apiClient from './client';
import {
  AdminStats,
  BlockedIPDetails,
  HealthStatus,
  MetricsData,
  RequestLog,
  ThreatScoreDistribution,
} from '../types/api';

/** Stop interval refetch while the query is in error (avoids timeout/retry storms). */
function pollUnlessError(intervalMs: number) {
  return (
    _data: unknown,
    query: { state: { status: string } }
  ): number | false => (query.state.status === 'error' ? false : intervalMs);
}

export const useHealthStatus = () => {
  return useQuery<HealthStatus>(
    'health',
    async () => {
      const response = await apiClient.get('/health');
      return response.data;
    },
    {
      refetchInterval: pollUnlessError(30000),
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
      refetchInterval: pollUnlessError(20000),
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
      refetchInterval: pollUnlessError(15000),
    }
  );
};

export const useBlockedIPs = (limit: number = 100) => {
  return useQuery<BlockedIPDetails[]>(
    ['blocked-ips', limit],
    async () => {
      const response = await apiClient.get(`/metrics/blocked-ips?limit=${limit}`);
      return response.data;
    },
    {
      refetchInterval: pollUnlessError(20000),
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
      refetchInterval: pollUnlessError(20000),
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
      refetchInterval: pollUnlessError(30000),
    }
  );
};
