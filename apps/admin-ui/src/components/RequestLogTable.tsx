import React, { useState, useEffect } from 'react';
import { useRecentRequests } from '../api/queries';
import { RequestLog } from '../types/api';

export const RequestLogTable: React.FC = () => {
  const [blockedOnly, setBlockedOnly] = useState(false);
  const { data: requests, isLoading, error, dataUpdatedAt } = useRecentRequests(50, blockedOnly);
  const [secondsAgo, setSecondsAgo] = useState(0);

  const getStatusCodeColor = (status: number) => {
    if (status >= 200 && status < 300) return 'text-success-600';
    if (status >= 300 && status < 400) return 'text-warning-600';
    if (status >= 400 && status < 500) return 'text-warning-600';
    return 'text-danger-600';
  };

  const getThreatScoreColor = (score: number) => {
    if (score >= 0.9) return 'text-danger-600 font-bold';
    if (score >= 0.7) return 'text-warning-600 font-semibold';
    if (score >= 0.5) return 'text-warning-600';
    return 'text-gray-600';
  };

  // Update seconds ago counter
  useEffect(() => {
    const interval = setInterval(() => {
      if (dataUpdatedAt) {
        const now = Date.now();
        const updated = new Date(dataUpdatedAt).getTime();
        const diff = Math.floor((now - updated) / 1000);
        setSecondsAgo(diff);
      }
    }, 1000);

    return () => clearInterval(interval);
  }, [dataUpdatedAt]);

  const formatTimestamp = (timestamp: string) => {
    return new Date(timestamp).toLocaleString();
  };

  const truncateUserAgent = (userAgent: string) => {
    return userAgent.length > 50 ? userAgent.substring(0, 50) + '...' : userAgent;
  };

  if (isLoading) {
    return (
      <div className="card">
        <div className="flex items-center justify-center h-32">
          <div className="text-gray-600">Loading requests...</div>
        </div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="card">
        <div className="text-center text-danger-600">
          Failed to load request logs
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-semibold text-gray-900">Recent Requests</h2>
        <div className="flex items-center space-x-4">
          <label className="flex items-center space-x-2 text-sm">
            <input
              type="checkbox"
              checked={blockedOnly}
              onChange={(e) => setBlockedOnly(e.target.checked)}
              className="rounded border-gray-300 text-primary-600 focus:ring-primary-500"
            />
            <span>Blocked only</span>
          </label>
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="table">
          <thead className="table-header">
            <tr>
              <th className="table-header-cell">Time</th>
              <th className="table-header-cell">Method</th>
              <th className="table-header-cell">Path</th>
              <th className="table-header-cell">Status</th>
              <th className="table-header-cell">Latency</th>
              <th className="table-header-cell">IP</th>
              <th className="table-header-cell">User</th>
              <th className="table-header-cell">Threat</th>
              <th className="table-header-cell">Blocked</th>
            </tr>
          </thead>
          <tbody className="table-body">
            {requests?.length === 0 ? (
              <tr>
                <td colSpan={9} className="table-cell text-center text-gray-500">
                  No requests found
                </td>
              </tr>
            ) : (
              requests?.map((request: RequestLog) => (
                <tr key={request.request_id} className="hover:bg-gray-50">
                  <td className="table-cell">
                    <div className="text-sm text-gray-900">
                      {formatTimestamp(request.timestamp)}
                    </div>
                  </td>
                  <td className="table-cell">
                    <span className={`px-2 py-1 text-xs font-medium rounded ${
                      request.method === 'GET' ? 'bg-success-100 text-success-800' :
                      request.method === 'POST' ? 'bg-primary-100 text-primary-800' :
                      request.method === 'PUT' ? 'bg-warning-100 text-warning-800' :
                      request.method === 'DELETE' ? 'bg-danger-100 text-danger-800' :
                      'bg-gray-100 text-gray-800'
                    }`}>
                      {request.method}
                    </span>
                  </td>
                  <td className="table-cell">
                    <div className="font-mono text-sm text-gray-900 truncate max-w-xs">
                      {request.path}
                    </div>
                  </td>
                  <td className="table-cell">
                    <span className={`font-medium ${getStatusCodeColor(request.status_code)}`}>
                      {request.status_code}
                    </span>
                  </td>
                  <td className="table-cell">
                    <div className="text-sm text-gray-900">
                      {request.latency_ms.toFixed(0)}ms
                    </div>
                  </td>
                  <td className="table-cell">
                    <div className="font-mono text-sm text-gray-900">
                      {request.ip}
                    </div>
                  </td>
                  <td className="table-cell">
                    <div className="text-sm text-gray-900">
                      {request.user_id || 'Anonymous'}
                    </div>
                  </td>
                  <td className="table-cell">
                    <div className={`text-sm ${getThreatScoreColor(request.threat_score)}`}>
                      {(request.threat_score * 100).toFixed(0)}%
                    </div>
                  </td>
                  <td className="table-cell">
                    {request.blocked ? (
                      <span className="badge-danger">BLOCKED</span>
                    ) : (
                      <span className="badge-success">ALLOWED</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {requests && requests.length > 0 && (
        <div className="mt-4 text-sm text-gray-500">
          Last updated: {secondsAgo} {secondsAgo === 1 ? 'second' : 'seconds'} ago
        </div>
      )}

      {requests && requests.length > 0 ? (
        <div className="mt-4 text-sm text-gray-500">
          Showing {requests.length} most recent requests
        </div>
      )}
    </div>
  );
};
