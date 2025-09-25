-- Migration: 002_create_enterprise_configs_table (ROLLBACK)
-- Description: Rollback enterprise_configs table and related objects
-- Author: System
-- Date: 2024-01-01

-- Drop views
DROP VIEW IF EXISTS enterprise_config_summary;
DROP VIEW IF EXISTS active_enterprise_configs;

-- Drop triggers
DROP TRIGGER IF EXISTS trigger_track_enterprise_config_history ON enterprise_configs;
DROP TRIGGER IF EXISTS trigger_log_enterprise_config_change ON enterprise_configs;
DROP TRIGGER IF EXISTS trigger_validate_enterprise_config ON enterprise_configs;
DROP TRIGGER IF EXISTS trigger_enterprise_configs_updated_at ON enterprise_configs;

-- Drop functions
DROP FUNCTION IF EXISTS get_config_statistics(VARCHAR(255));
DROP FUNCTION IF EXISTS cleanup_old_config_history(INTEGER);
DROP FUNCTION IF EXISTS track_enterprise_config_history();
DROP FUNCTION IF EXISTS log_enterprise_config_change();
DROP FUNCTION IF EXISTS validate_enterprise_config();
DROP FUNCTION IF EXISTS update_enterprise_configs_updated_at();

-- Drop policies (RLS)
DROP POLICY IF EXISTS enterprise_config_history_system_access ON enterprise_config_history;
DROP POLICY IF EXISTS enterprise_configs_system_access ON enterprise_configs;
DROP POLICY IF EXISTS enterprise_config_history_org_isolation ON enterprise_config_history;
DROP POLICY IF EXISTS enterprise_configs_org_isolation ON enterprise_configs;

-- Drop indexes from history table
DROP INDEX CONCURRENTLY IF EXISTS idx_enterprise_config_history_changed_by;
DROP INDEX CONCURRENTLY IF EXISTS idx_enterprise_config_history_org;
DROP INDEX CONCURRENTLY IF EXISTS idx_enterprise_config_history_config_id;

-- Drop indexes from main table
DROP INDEX CONCURRENTLY IF EXISTS idx_enterprise_configs_org_type_name_unique;
DROP INDEX CONCURRENTLY IF EXISTS idx_enterprise_configs_updated_at;
DROP INDEX CONCURRENTLY IF EXISTS idx_enterprise_configs_created_by;
DROP INDEX CONCURRENTLY IF EXISTS idx_enterprise_configs_type_enabled;
DROP INDEX CONCURRENTLY IF EXISTS idx_enterprise_configs_org_enabled;
DROP INDEX CONCURRENTLY IF EXISTS idx_enterprise_configs_org_type;

-- Drop tables
DROP TABLE IF EXISTS enterprise_config_history;
DROP TABLE IF EXISTS enterprise_configs;