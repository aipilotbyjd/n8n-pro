-- Migration: 001_create_audit_events_table
-- Description: Create audit_events table for comprehensive audit logging
-- Author: System
-- Date: 2024-01-01

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "btree_gin";

-- Create audit_events table
CREATE TABLE IF NOT EXISTS audit_events (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL,
    actor_type VARCHAR(50) NOT NULL CHECK (actor_type IN ('user', 'system', 'api', 'service')),
    actor_id VARCHAR(255),
    event_type VARCHAR(100) NOT NULL,
    resource_type VARCHAR(100) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    details JSONB,
    ip_address INET,
    user_agent TEXT,
    success BOOLEAN NOT NULL DEFAULT true,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    session_id VARCHAR(255),
    request_id VARCHAR(255),
    severity VARCHAR(20) NOT NULL DEFAULT 'medium' CHECK (severity IN ('low', 'medium', 'high', 'critical'))
);

-- Create indexes for optimal query performance
-- Primary index on organization and created_at for time-based queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_org_created_at 
ON audit_events (organization_id, created_at DESC);

-- Index for event type filtering
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_event_type 
ON audit_events (organization_id, event_type, created_at DESC);

-- Index for actor-based queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_actor 
ON audit_events (organization_id, actor_id, created_at DESC) 
WHERE actor_id IS NOT NULL;

-- Index for resource-based queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_resource 
ON audit_events (organization_id, resource_type, resource_id, created_at DESC);

-- Index for success/failure analysis
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_success 
ON audit_events (organization_id, success, created_at DESC);

-- Index for severity-based queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_severity 
ON audit_events (organization_id, severity, created_at DESC);

-- Index for IP-based queries (security analysis)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_ip 
ON audit_events (organization_id, ip_address, created_at DESC)
WHERE ip_address IS NOT NULL;

-- Composite index for complex queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_composite 
ON audit_events (organization_id, event_type, success, severity, created_at DESC);

-- Index for cleanup operations (retention policy)
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_cleanup 
ON audit_events (created_at) 
WHERE created_at < NOW() - INTERVAL '1 year';

-- Index for session-based queries
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_session 
ON audit_events (session_id, created_at DESC) 
WHERE session_id IS NOT NULL;

-- Index for request tracing
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_request 
ON audit_events (request_id, created_at DESC) 
WHERE request_id IS NOT NULL;

-- GIN index for JSON details search
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_audit_events_details_gin 
ON audit_events USING GIN (details);

-- Create audit_events_archive table for long-term storage
CREATE TABLE IF NOT EXISTS audit_events_archive (
    LIKE audit_events INCLUDING ALL
);

-- Add table comments for documentation
COMMENT ON TABLE audit_events IS 'Comprehensive audit log for all system events and user actions';
COMMENT ON COLUMN audit_events.id IS 'Unique identifier for the audit event';
COMMENT ON COLUMN audit_events.organization_id IS 'Organization identifier for data isolation';
COMMENT ON COLUMN audit_events.actor_type IS 'Type of entity performing the action';
COMMENT ON COLUMN audit_events.actor_id IS 'Identifier of the entity performing the action';
COMMENT ON COLUMN audit_events.event_type IS 'Specific type of event being logged';
COMMENT ON COLUMN audit_events.resource_type IS 'Type of resource being acted upon';
COMMENT ON COLUMN audit_events.resource_id IS 'Identifier of the resource being acted upon';
COMMENT ON COLUMN audit_events.details IS 'Additional event details in JSON format';
COMMENT ON COLUMN audit_events.ip_address IS 'IP address of the client making the request';
COMMENT ON COLUMN audit_events.user_agent IS 'User agent string of the client';
COMMENT ON COLUMN audit_events.success IS 'Whether the action was successful';
COMMENT ON COLUMN audit_events.error_message IS 'Error message if the action failed';
COMMENT ON COLUMN audit_events.session_id IS 'Session identifier for request correlation';
COMMENT ON COLUMN audit_events.request_id IS 'Request identifier for distributed tracing';
COMMENT ON COLUMN audit_events.severity IS 'Severity level of the event';

-- Create function to automatically set created_at
CREATE OR REPLACE FUNCTION update_audit_events_created_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.created_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to ensure created_at is always set
CREATE TRIGGER trigger_audit_events_created_at
    BEFORE INSERT ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION update_audit_events_created_at();

-- Create function for audit event retention cleanup
CREATE OR REPLACE FUNCTION cleanup_old_audit_events(retention_days INTEGER DEFAULT 365)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
    cutoff_date TIMESTAMP WITH TIME ZONE;
BEGIN
    cutoff_date := NOW() - INTERVAL '1 day' * retention_days;
    
    -- Move old records to archive
    INSERT INTO audit_events_archive 
    SELECT * FROM audit_events 
    WHERE created_at < cutoff_date;
    
    -- Delete old records from main table
    DELETE FROM audit_events 
    WHERE created_at < cutoff_date;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Create function to get audit statistics
CREATE OR REPLACE FUNCTION get_audit_statistics(
    org_id VARCHAR(255),
    start_date TIMESTAMP WITH TIME ZONE DEFAULT NOW() - INTERVAL '30 days',
    end_date TIMESTAMP WITH TIME ZONE DEFAULT NOW()
)
RETURNS TABLE(
    total_events BIGINT,
    successful_events BIGINT,
    failed_events BIGINT,
    unique_users BIGINT,
    unique_ips BIGINT,
    events_by_type JSONB,
    events_by_severity JSONB
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        COUNT(*) as total_events,
        COUNT(*) FILTER (WHERE success = true) as successful_events,
        COUNT(*) FILTER (WHERE success = false) as failed_events,
        COUNT(DISTINCT actor_id) FILTER (WHERE actor_id IS NOT NULL) as unique_users,
        COUNT(DISTINCT ip_address) FILTER (WHERE ip_address IS NOT NULL) as unique_ips,
        jsonb_object_agg(event_type, type_count) as events_by_type,
        jsonb_object_agg(severity, severity_count) as events_by_severity
    FROM (
        SELECT 
            event_type,
            severity,
            COUNT(*) OVER (PARTITION BY event_type) as type_count,
            COUNT(*) OVER (PARTITION BY severity) as severity_count
        FROM audit_events 
        WHERE organization_id = org_id 
        AND created_at >= start_date 
        AND created_at <= end_date
    ) stats
    LIMIT 1;
END;
$$ LANGUAGE plpgsql;

-- Grant appropriate permissions
GRANT SELECT, INSERT ON audit_events TO n8n_app_user;
GRANT SELECT ON audit_events_archive TO n8n_app_user;
GRANT EXECUTE ON FUNCTION cleanup_old_audit_events TO n8n_maintenance_user;
GRANT EXECUTE ON FUNCTION get_audit_statistics TO n8n_app_user;

-- Create row level security policies for multi-tenancy
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;

-- Policy for organization isolation
CREATE POLICY audit_events_org_isolation ON audit_events
    FOR ALL
    TO n8n_app_user
    USING (organization_id = current_setting('app.current_organization_id', true));

-- Policy for system access
CREATE POLICY audit_events_system_access ON audit_events
    FOR ALL
    TO n8n_system_user
    USING (true);

-- Create materialized view for audit dashboard
CREATE MATERIALIZED VIEW IF NOT EXISTS audit_events_daily_summary AS
SELECT 
    organization_id,
    DATE(created_at) as event_date,
    event_type,
    severity,
    COUNT(*) as event_count,
    COUNT(*) FILTER (WHERE success = true) as successful_count,
    COUNT(*) FILTER (WHERE success = false) as failed_count,
    COUNT(DISTINCT actor_id) as unique_actors,
    COUNT(DISTINCT ip_address) as unique_ips
FROM audit_events 
WHERE created_at >= NOW() - INTERVAL '90 days'
GROUP BY organization_id, DATE(created_at), event_type, severity
ORDER BY event_date DESC, organization_id, event_type;

-- Create unique index on materialized view
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_daily_summary_unique 
ON audit_events_daily_summary (organization_id, event_date, event_type, severity);

-- Create index for faster queries on materialized view
CREATE INDEX IF NOT EXISTS idx_audit_daily_summary_org_date 
ON audit_events_daily_summary (organization_id, event_date DESC);

-- Grant permissions on materialized view
GRANT SELECT ON audit_events_daily_summary TO n8n_app_user;

-- Set up automatic refresh of materialized view (requires pg_cron extension)
-- This would be configured separately based on the PostgreSQL setup
-- SELECT cron.schedule('refresh-audit-summary', '0 1 * * *', 'REFRESH MATERIALIZED VIEW CONCURRENTLY audit_events_daily_summary;');

-- Create notification function for critical events
CREATE OR REPLACE FUNCTION notify_critical_audit_event()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.severity = 'critical' THEN
        PERFORM pg_notify(
            'critical_audit_event',
            json_build_object(
                'id', NEW.id,
                'organization_id', NEW.organization_id,
                'event_type', NEW.event_type,
                'actor_id', NEW.actor_id,
                'created_at', NEW.created_at
            )::text
        );
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for critical event notifications
CREATE TRIGGER trigger_notify_critical_audit_event
    AFTER INSERT ON audit_events
    FOR EACH ROW
    EXECUTE FUNCTION notify_critical_audit_event();

-- Add constraint to ensure valid event types (can be updated as needed)
-- This would be managed through application logic and migrations
ALTER TABLE audit_events ADD CONSTRAINT chk_valid_event_type 
CHECK (event_type ~ '^[a-zA-Z_][a-zA-Z0-9_]*\.[a-zA-Z_][a-zA-Z0-9_]*$');

-- Validate the table structure
DO $$
BEGIN
    -- Verify all required indexes exist
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'audit_events' AND indexname = 'idx_audit_events_org_created_at') THEN
        RAISE EXCEPTION 'Required index idx_audit_events_org_created_at not found';
    END IF;
    
    -- Verify RLS is enabled
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'audit_events' AND rowsecurity = true) THEN
        RAISE EXCEPTION 'Row Level Security not enabled on audit_events table';
    END IF;
    
    RAISE NOTICE 'Audit events table validation completed successfully';
END $$;