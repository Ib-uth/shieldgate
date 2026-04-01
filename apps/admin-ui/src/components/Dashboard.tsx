import React from 'react';
import { useHealthStatus, useMetrics, useAdminStats } from '../api/queries';
import { HealthCard } from './HealthCard';
import { MetricsCard } from './MetricsCard';
import { RequestLogTable } from './RequestLogTable';
import { ThreatScoreChart } from './ThreatScoreChart';
import { BlockedIPsList } from './BlockedIPsList';

export const Dashboard: React.FC = () => {
  const { data: healthData, isLoading: healthLoading } = useHealthStatus();
  const { data: metricsData, isLoading: metricsLoading } = useMetrics();
  const { isLoading: adminStatsLoading } = useAdminStats();

  if (healthLoading || metricsLoading || adminStatsLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-lg text-gray-600">Loading dashboard...</div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className="text-3xl font-bold text-gray-900">ShieldGate Dashboard</h1>
        <p className="text-gray-600">Monitor API gateway performance and security</p>
      </div>

      {/* Health Status */}
      {healthData && <HealthCard health={healthData} />}

      {/* Key Metrics */}
      {metricsData && <MetricsCard metrics={metricsData} />}

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Request Log Table */}
        <div className="lg:col-span-2">
          <RequestLogTable />
        </div>

        {/* Threat Score Chart */}
        {metricsData && (
          <ThreatScoreChart threatDistribution={metricsData.threat_score_distribution} />
        )}

        {/* Blocked IPs List */}
        <BlockedIPsList />
      </div>
    </div>
  );
};
