import React from 'react';
import { MetricsData } from '../types/api';

interface MetricsCardProps {
  metrics: MetricsData;
}

export const MetricsCard: React.FC<MetricsCardProps> = ({ metrics }) => {
  const formatNumber = (num: number) => {
    if (num >= 1000000) {
      return (num / 1000000).toFixed(1) + 'M';
    } else if (num >= 1000) {
      return (num / 1000).toFixed(1) + 'K';
    }
    return num.toString();
  };

  const getErrorRateColor = (rate: number) => {
    if (rate < 1) return 'text-success-600';
    if (rate < 5) return 'text-warning-600';
    return 'text-danger-600';
  };

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-6">
        <h2 className="text-lg font-semibold text-gray-900">Request Metrics</h2>
        <span className="text-sm text-gray-500">
          Last {metrics.period_hours} hour{metrics.period_hours > 1 ? 's' : ''}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        {/* Total Requests */}
        <div className="text-center">
          <div className="text-2xl font-bold text-gray-900">
            {formatNumber(metrics.total_requests)}
          </div>
          <div className="text-sm text-gray-500">Total Requests</div>
        </div>

        {/* Error Rate */}
        <div className="text-center">
          <div className={`text-2xl font-bold ${getErrorRateColor(metrics.error_rate)}`}>
            {metrics.error_rate.toFixed(1)}%
          </div>
          <div className="text-sm text-gray-500">Error Rate</div>
        </div>

        {/* Avg Latency */}
        <div className="text-center">
          <div className="text-2xl font-bold text-gray-900">
            {metrics.top_endpoints.length > 0 
              ? (metrics.top_endpoints[0].avg_latency_ms).toFixed(0)
              : '0'
            }ms
          </div>
          <div className="text-sm text-gray-500">Avg Latency</div>
        </div>

        {/* Top Endpoint */}
        <div className="text-center">
          <div className="text-lg font-bold text-gray-900 truncate">
            {metrics.top_endpoints.length > 0 
              ? metrics.top_endpoints[0].path
              : 'N/A'
            }
          </div>
          <div className="text-sm text-gray-500">Top Endpoint</div>
        </div>
      </div>

      {/* Top Endpoints */}
      {metrics.top_endpoints.length > 0 && (
        <div className="mt-6">
          <h3 className="text-sm font-medium text-gray-900 mb-3">Top Endpoints</h3>
          <div className="space-y-2">
            {metrics.top_endpoints.slice(0, 3).map((endpoint, index) => (
              <div key={index} className="flex justify-between items-center text-sm">
                <div className="font-mono text-gray-600 truncate flex-1">
                  {endpoint.path}
                </div>
                <div className="flex items-center space-x-4 ml-4">
                  <span className="text-gray-500">
                    {formatNumber(endpoint.request_count)} req
                  </span>
                  <span className="text-gray-500">
                    {endpoint.avg_latency_ms.toFixed(0)}ms
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Threat Score Distribution */}
      {Object.keys(metrics.threat_score_distribution).length > 0 && (
        <div className="mt-6">
          <h3 className="text-sm font-medium text-gray-900 mb-3">Threat Score Distribution</h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
            {Object.entries(metrics.threat_score_distribution).map(([level, count]) => (
              <div key={level} className="text-center">
                <div className="text-lg font-semibold text-gray-900">
                  {formatNumber(count)}
                </div>
                <div className="text-xs text-gray-500 capitalize">{level}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mt-4 text-sm text-gray-500">
        Last updated: {new Date(metrics.timestamp).toLocaleString()}
      </div>
    </div>
  );
};
