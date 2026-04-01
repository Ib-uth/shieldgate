-- Initialize ShieldGate database
-- This script runs automatically when PostgreSQL container starts

-- Create additional indexes for performance
CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp_status ON request_logs(timestamp, status_code);
CREATE INDEX IF NOT EXISTS idx_request_logs_ip_blocked ON request_logs(ip, blocked);
CREATE INDEX IF NOT EXISTS idx_request_logs_user_timestamp ON request_logs(user_id, timestamp) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_request_logs_threat_blocked ON request_logs(threat_score, blocked) WHERE blocked = true;

-- Create metrics aggregation function for better performance
CREATE OR REPLACE FUNCTION aggregate_request_metrics(
    p_start_time TIMESTAMP,
    p_end_time TIMESTAMP
) RETURNS TABLE (
    total_requests BIGINT,
    error_requests BIGINT,
    blocked_requests BIGINT,
    unique_ips BIGINT,
    avg_latency_ms FLOAT,
    avg_threat_score FLOAT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        COUNT(*) as total_requests,
        COUNT(*) FILTER (WHERE status_code >= 400) as error_requests,
        COUNT(*) FILTER (WHERE blocked = true) as blocked_requests,
        COUNT(DISTINCT ip) as unique_ips,
        AVG(latency_ms) as avg_latency_ms,
        AVG(threat_score) as avg_threat_score
    FROM request_logs
    WHERE timestamp BETWEEN p_start_time AND p_end_time;
END;
$$ LANGUAGE plpgsql;

-- Create function to get top endpoints
CREATE OR REPLACE FUNCTION get_top_endpoints(
    p_start_time TIMESTAMP,
    p_end_time TIMESTAMP,
    p_limit INTEGER DEFAULT 10
) RETURNS TABLE (
    path VARCHAR(500),
    request_count BIGINT,
    avg_latency_ms FLOAT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        path,
        COUNT(*) as request_count,
        AVG(latency_ms) as avg_latency_ms
    FROM request_logs
    WHERE timestamp BETWEEN p_start_time AND p_end_time
    GROUP BY path
    ORDER BY COUNT(*) DESC
    LIMIT p_limit;
END;
$$ LANGUAGE plpgsql;

-- Create function to get threat score distribution
CREATE OR REPLACE FUNCTION get_threat_distribution(
    p_start_time TIMESTAMP,
    p_end_time TIMESTAMP
) RETURNS TABLE (
    threat_level VARCHAR(20),
    count BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        CASE
            WHEN threat_score >= 0.9 THEN 'critical'
            WHEN threat_score >= 0.7 THEN 'high'
            WHEN threat_score >= 0.5 THEN 'medium'
            WHEN threat_score >= 0.3 THEN 'low'
            ELSE 'minimal'
        END as threat_level,
        COUNT(*) as count
    FROM request_logs
    WHERE timestamp BETWEEN p_start_time AND p_end_time
    GROUP BY threat_level
    ORDER BY 
        CASE threat_level
            WHEN 'critical' THEN 1
            WHEN 'high' THEN 2
            WHEN 'medium' THEN 3
            WHEN 'low' THEN 4
            WHEN 'minimal' THEN 5
        END;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions to the shieldgate user
GRANT EXECUTE ON FUNCTION aggregate_request_metrics TO shieldgate;
GRANT EXECUTE ON FUNCTION get_top_endpoints TO shieldgate;
GRANT EXECUTE ON FUNCTION get_threat_distribution TO shieldgate;
