export interface HealthStatus {
  status: string;
  timestamp: string;
  version: string;
  services: {
    redis: ServiceHealth;
    database: ServiceHealth;
    downstream: ServiceHealth;
  };
}

export interface ServiceHealth {
  status: string;
  response_time_ms?: number;
  error?: string;
  timestamp: string;
}

export interface MetricsData {
  timestamp: string;
  period_hours: number;
  total_requests: number;
  error_rate: number;
  top_blocked_ips: BlockedIP[];
  threat_score_distribution: Record<string, number>;
  top_endpoints: TopEndpoint[];
}

export interface BlockedIP {
  ip: string;
  blocked_count: number;
}

export interface TopEndpoint {
  path: string;
  request_count: number;
  avg_latency_ms: number;
}

export interface RequestLog {
  request_id: string;
  timestamp: string;
  method: string;
  path: string;
  status_code: number;
  latency_ms: number;
  user_id?: string;
  ip: string;
  user_agent: string;
  threat_score: number;
  blocked: boolean;
}

export interface AdminStats {
  timestamp: string;
  statistics: {
    [key: string]: {
      total_requests: number;
      error_requests: number;
      blocked_requests: number;
      unique_ips: number;
      avg_latency_ms: number;
      avg_threat_score: number;
      error_rate: number;
      block_rate: number;
    };
  };
  top_threat_actors: ThreatActor[];
  recent_blocked_ips: BlockedIPDetails[];
}

export interface ThreatActor {
  ip: string;
  avg_threat_score: number;
  request_count: number;
  blocked_count: number;
}

export interface BlockedIPDetails {
  ip: string;
  blocked_at: string;
  reason?: string;
  threat_score?: number;
}

export interface ThreatScoreDistribution {
  period_hours: number;
  threat_distribution: {
    threat_level: string;
    count: number;
    avg_score: number;
  }[];
  high_threat_requests: {
    request_id: string;
    timestamp: string;
    ip: string;
    path: string;
    threat_score: number;
    blocked: boolean;
    user_agent?: string;
  }[];
}
