import React, { useState } from 'react';
import { useBlockedIPs } from '../api/queries';
import apiClient from '../api/client';
import type { BlockedIPDetails } from '../types/api';

export const BlockedIPsList: React.FC = () => {
  const { data: blockedIPs, isLoading, error, refetch } = useBlockedIPs(20);
  const [unblockingIP, setUnblockingIP] = useState<string | null>(null);

  const handleUnblockIP = async (ip: string) => {
    setUnblockingIP(ip);
    try {
      await apiClient.post(`/metrics/unblock-ip/${ip}`);
      await refetch(); // Refresh the list
    } catch (error) {
      console.error('Failed to unblock IP:', error);
      alert('Failed to unblock IP');
    } finally {
      setUnblockingIP(null);
    }
  };

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  if (isLoading) {
    return (
      <div className="card">
        <div className="flex items-center justify-center h-32">
          <div className="text-gray-600">Loading blocked IPs...</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <div className="text-center text-danger-600">
          Failed to load blocked IPs
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-gray-900">Blocked IPs</h2>
        <button
          onClick={() => refetch()}
          className="btn-secondary text-sm"
        >
          Refresh
        </button>
      </div>

      {blockedIPs?.length === 0 ? (
        <div className="text-center text-gray-500 py-8">
          <div className="text-lg font-medium mb-2">No blocked IPs</div>
          <div className="text-sm">All IPs are currently allowed</div>
        </div>
      ) : (
        <div className="space-y-3">
          {blockedIPs?.map((blockedIP: BlockedIPDetails) => (
            <div
              key={blockedIP.ip}
              className="flex items-center justify-between p-3 bg-gray-50 rounded-lg"
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center space-x-2">
                  <span className="font-mono text-sm font-medium text-gray-900">
                    {blockedIP.ip}
                  </span>
                  <span className="badge-danger">BLOCKED</span>
                </div>
                
                <div className="mt-1 text-xs text-gray-500">
                  Blocked {formatTimestamp(blockedIP.blocked_at)}
                  {blockedIP.reason && (
                    <span className="ml-2">
                      Reason: {blockedIP.reason}
                    </span>
                  )}
                  {blockedIP.threat_score && (
                    <span className="ml-2">
                      Threat: {(blockedIP.threat_score * 100).toFixed(0)}%
                    </span>
                  )}
                </div>
              </div>

              <button
                onClick={() => handleUnblockIP(blockedIP.ip)}
                disabled={unblockingIP === blockedIP.ip}
                className="btn-primary text-sm px-3 py-1"
              >
                {unblockingIP === blockedIP.ip ? (
                  <span className="flex items-center space-x-1">
                    <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                    </svg>
                    <span>Unblocking...</span>
                  </span>
                ) : (
                  'Unblock'
                )}
              </button>
            </div>
          ))}
        </div>
      )}

      {blockedIPs && blockedIPs.length > 0 && (
        <div className="mt-4 text-sm text-gray-500">
          Showing {blockedIPs.length} most recently blocked IPs
        </div>
      )}
    </div>
  );
};
