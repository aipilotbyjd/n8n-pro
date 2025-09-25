-- Migration: 001_create_audit_events_table (ROLLBACK)
-- Description: Rollback audit_events table and related objects
-- Author: System
-- Date: 2024-01-01

-- Drop triggers first
DROP TRIGGER IF EXISTS trigger_notify_critical_audit_event ON audit_events;
DROP TRIGGER IF EXISTS trigger_audit_events_created_at ON audit_events;

-- Drop functions
DROP FUNCTION IF EXISTS notify_critical_audit_event();
DROP FUNCTION IF EXISTS update_audit_events_created_at();
DROP FUNCTION IF EXISTS cleanup_old_audit_events(INTEGER);
DROP FUNCTION IF EXISTS get_audit_statistics(VARCHAR(255), TIMESTAMP WITH TIME ZONE, TIMESTAMP WITH TIME ZONE);

-- Drop materialized view and its indexes
DROP INDEX IF EXISTS idx_audit_daily_summary_org_date;
DROP INDEX IF EXISTS idx_audit_daily_summary_unique;
DROP MATERIALIZED VIEW IF EXISTS audit_events_daily_summary;

-- Drop policies (RLS)
DROP POLICY IF EXISTS audit_events_system_access ON audit_events;
DROP POLICY IF EXISTS audit_events_org_isolation ON audit_events;

-- Drop indexes
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_details_gin;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_request;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_session;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_cleanup;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_composite;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_ip;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_severity;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_success;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_resource;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_actor;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_event_type;
DROP INDEX CONCURRENTLY IF EXISTS idx_audit_events_org_created_at;

-- Drop tables
DROP TABLE IF EXISTS audit_events_archive;
DROP TABLE IF EXISTS audit_events;