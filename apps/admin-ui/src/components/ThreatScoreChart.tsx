import React from 'react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

interface ThreatScoreChartProps {
  threatDistribution: Record<string, number>;
}

export const ThreatScoreChart: React.FC<ThreatScoreChartProps> = ({ threatDistribution }) => {
  const getBarColor = (level: string) => {
    switch (level) {
      case 'critical':
        return '#dc2626'; // danger-600
      case 'high':
        return '#f59e0b'; // warning-500
      case 'medium':
        return '#3b82f6'; // primary-500
      case 'low':
        return '#22c55e'; // success-500
      case 'minimal':
        return '#6b7280'; // gray-500
      default:
        return '#6b7280';
    }
  };

  const chartData = Object.entries(threatDistribution).map(([level, count]) => ({
    level: level.charAt(0).toUpperCase() + level.slice(1),
    count,
    fill: getBarColor(level),
  }));

  const CustomTooltip = ({ active, payload }: any) => {
    if (active && payload && payload.length) {
      const data = payload[0];
      return (
        <div className="bg-white p-3 border border-gray-200 rounded shadow-lg">
          <p className="font-medium text-gray-900">{data.payload.level}</p>
          <p className="text-sm text-gray-600">Count: {data.value}</p>
        </div>
      );
    }
    return null;
  };

  return (
    <div className="card">
      <div className="mb-4">
        <h2 className="text-lg font-semibold text-gray-900">Threat Score Distribution</h2>
        <p className="text-sm text-gray-500">Request threat levels</p>
      </div>

      {chartData.length === 0 ? (
        <div className="flex items-center justify-center h-64">
          <div className="text-gray-500">No threat data available</div>
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={250}>
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis 
              dataKey="level" 
              tick={{ fill: '#6b7280', fontSize: 12 }}
              axisLine={{ stroke: '#e5e7eb' }}
            />
            <YAxis 
              tick={{ fill: '#6b7280', fontSize: 12 }}
              axisLine={{ stroke: '#e5e7eb' }}
            />
            <Tooltip content={<CustomTooltip />} />
            <Bar 
              dataKey="count" 
              fill={(entry: any) => entry.fill}
              radius={[4, 4, 0, 0]}
            />
          </BarChart>
        </ResponsiveContainer>
      )}

      {/* Legend */}
      <div className="mt-4 grid grid-cols-2 gap-2 text-xs">
        {chartData.map((item) => (
          <div key={item.level} className="flex items-center space-x-2">
            <div 
              className="w-3 h-3 rounded"
              style={{ backgroundColor: item.fill }}
            />
            <span className="text-gray-600">{item.level}: {item.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
};
