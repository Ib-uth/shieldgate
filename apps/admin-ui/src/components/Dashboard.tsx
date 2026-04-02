import React from 'react';

import { useAuth } from '../context/useAuth';
import {
  useAdminStats,
  useHealthStatus,
  useMetrics,
  useRecentRequests,
} from '../api/queries';
import { HealthCard } from './HealthCard';
import { MetricsCard } from './MetricsCard';
import { RequestLogTable } from './RequestLogTable';
import { ThreatScoreChart } from './ThreatScoreChart';
import { BlockedIPsList } from './BlockedIPsList';

function StatCardSkeleton() {
  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4 animate-pulse">
      <div className="h-3 bg-gray-200 rounded w-24 mb-3" />
      <div className="h-8 bg-gray-200 rounded w-16" />
    </div>
  );
}

function DashboardSkeleton() {
  return (
    <div className="min-h-screen">
      <nav className="bg-slate-900 text-white px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center animate-pulse">
        <div className="h-6 bg-slate-700 rounded w-40" />
        <div className="h-9 bg-slate-700 rounded w-20" />
      </nav>
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        <div className="h-8 bg-gray-200 rounded w-64 animate-pulse" />
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          <StatCardSkeleton />
          <StatCardSkeleton />
          <StatCardSkeleton />
          <StatCardSkeleton />
        </div>
        <div className="h-40 bg-gray-200 rounded animate-pulse" />
        <div className="h-64 bg-gray-200 rounded animate-pulse" />
      </div>
    </div>
  );
}

export const Dashboard: React.FC = () => {
  const { logout } = useAuth();
  const {
    data: healthData,
    isLoading: healthLoading,
    isError: healthError,
  } = useHealthStatus();
  const {
    data: metricsData,
    isLoading: metricsLoading,
    isError: metricsError,
  } = useMetrics();
  const {
    data: adminStats,
    isLoading: adminStatsLoading,
    isError: adminStatsError,
  } = useAdminStats();
  const { data: recentRequests } = useRecentRequests(50, false);

  const loading = healthLoading || metricsLoading || adminStatsLoading;

  const lastHour = adminStats?.statistics?.last_hour;
  const totalLastHour = lastHour?.total_requests ?? 0;
  const showSummaryCards = !!adminStats && !adminStatsError;
  const hasNoActivity =
    !loading &&
    !adminStatsError &&
    totalLastHour === 0 &&
    (recentRequests?.length ?? 0) === 0;

  if (loading) {
    return <DashboardSkeleton />;
  }

  const showGlobalError = healthError || metricsError || adminStatsError;

  return (
    <div className="min-h-screen flex flex-col">
      <nav className="bg-slate-900 text-white shadow-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-4 flex justify-between items-center">
          <div className="flex items-center gap-2">
            <span className="text-xl font-semibold tracking-tight">ShieldGate</span>
            <span className="text-slate-400 text-sm hidden sm:inline">Dashboard</span>
          </div>
          <button
            type="button"
            onClick={() => logout()}
            className="text-sm font-medium px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 border border-slate-600"
          >
            Log out
          </button>
        </div>
      </nav>

      <div className="flex-1 max-w-7xl mx-auto w-full px-4 sm:px-6 lg:px-8 py-8 space-y-6">
        <div>
          <h1 className="text-3xl font-bold text-gray-900">ShieldGate Dashboard</h1>
          <p className="text-gray-600">Monitor API gateway performance and security</p>
        </div>

        {showGlobalError && (
          <div
            className="rounded-lg border border-red-200 bg-red-50 text-red-800 px-4 py-3 text-sm"
            role="alert"
          >
            Some data failed to load. Check your connection and gateway configuration.
          </div>
        )}

        {hasNoActivity && !showGlobalError && (
          <div className="rounded-lg border border-slate-200 bg-slate-50 text-slate-700 px-4 py-3 text-sm">
            No data yet — send some requests through the gateway to see activity.
          </div>
        )}

        {showSummaryCards && (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            <div className="bg-white rounded-lg border border-gray-200 p-4 shadow-sm">
              <p className="text-sm text-gray-500">Total requests (last hour)</p>
              <p className="text-2xl font-semibold text-gray-900">
                {(lastHour?.total_requests ?? 0).toLocaleString()}
              </p>
            </div>
            <div className="bg-white rounded-lg border border-gray-200 p-4 shadow-sm">
              <p className="text-sm text-gray-500">Blocked requests</p>
              <p className="text-2xl font-semibold text-gray-900">
                {(lastHour?.blocked_requests ?? 0).toLocaleString()}
              </p>
            </div>
            <div className="bg-white rounded-lg border border-gray-200 p-4 shadow-sm">
              <p className="text-sm text-gray-500">Avg threat score</p>
              <p className="text-2xl font-semibold text-gray-900">
                {(lastHour?.avg_threat_score ?? 0).toFixed(2)}
              </p>
            </div>
            <div className="bg-white rounded-lg border border-gray-200 p-4 shadow-sm">
              <p className="text-sm text-gray-500">Active unique IPs</p>
              <p className="text-2xl font-semibold text-gray-900">
                {(lastHour?.unique_ips ?? 0).toLocaleString()}
              </p>
            </div>
          </div>
        )}

        {healthData && <HealthCard health={healthData} />}

        {metricsData && <MetricsCard metrics={metricsData} />}

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="lg:col-span-2">
            <RequestLogTable />
          </div>

          {metricsData && (
            <ThreatScoreChart threatDistribution={metricsData.threat_score_distribution} />
          )}

          <BlockedIPsList />
        </div>
      </div>
    </div>
  );
};
