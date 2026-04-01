import React from 'react';
import { HealthStatus } from '../types/api';

interface HealthCardProps {
  health: HealthStatus;
}

export const HealthCard: React.FC<HealthCardProps> = ({ health }) => {
  const getServiceStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'bg-success-100 text-success-800';
      case 'degraded':
        return 'bg-warning-100 text-warning-800';
      case 'unhealthy':
      case 'unreachable':
        return 'bg-danger-100 text-danger-800';
      default:
        return 'bg-gray-100 text-gray-800';
    }
  };

  const getOverallStatusColor = (status: string) => {
    switch (status) {
      case 'healthy':
        return 'text-success-600';
      case 'degraded':
        return 'text-warning-600';
      default:
        return 'text-danger-600';
    }
  };

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-gray-900">System Health</h2>
        <span className={`px-3 py-1 rounded-full text-sm font-medium ${getServiceStatusColor(health.status)}`}>
          {health.status.toUpperCase()}
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        {/* Redis */}
        <div className="flex items-center space-x-3">
          <div className={`w-3 h-3 rounded-full ${
            health.services.redis.status === 'healthy' ? 'bg-success-500' : 'bg-danger-500'
          }`} />
          <div>
            <div className="font-medium text-gray-900">Redis</div>
            <div className="text-sm text-gray-500">
              {health.services.redis.response_time_ms 
                ? `${health.services.redis.response_time_ms.toFixed(1)}ms`
                : health.services.redis.error || 'Unknown'
              }
            </div>
          </div>
        </div>

        {/* Database */}
        <div className="flex items-center space-x-3">
          <div className={`w-3 h-3 rounded-full ${
            health.services.database.status === 'healthy' ? 'bg-success-500' : 'bg-danger-500'
          }`} />
          <div>
            <div className="font-medium text-gray-900">Database</div>
            <div className="text-sm text-gray-500">
              {health.services.database.response_time_ms 
                ? `${health.services.database.response_time_ms.toFixed(1)}ms`
                : health.services.database.error || 'Unknown'
              }
            </div>
          </div>
        </div>

        {/* Downstream */}
        <div className="flex items-center space-x-3">
          <div className={`w-3 h-3 rounded-full ${
            health.services.downstream.status === 'healthy' ? 'bg-success-500' : 'bg-danger-500'
          }`} />
          <div>
            <div className="font-medium text-gray-900">Downstream</div>
            <div className="text-sm text-gray-500">
              {health.services.downstream.response_time_ms 
                ? `${health.services.downstream.response_time_ms.toFixed(1)}ms`
                : health.services.downstream.error || 'Unknown'
              }
            </div>
          </div>
        </div>
      </div>

      <div className="mt-4 text-sm text-gray-500">
        Last updated: {new Date(health.timestamp).toLocaleString()}
      </div>
    </div>
  );
};
