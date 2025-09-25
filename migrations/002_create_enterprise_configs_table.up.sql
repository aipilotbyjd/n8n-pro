-- Migration: 002_create_enterprise_configs_table
-- Description: Create enterprise_configs table for SAML/LDAP configurations with encrypted storage
-- Author: System
-- Date: 2024-01-01

-- Create enterprise_configs table
CREATE TABLE IF NOT EXISTS enterprise_configs (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL,
    config_type VARCHAR(50) NOT NULL CHECK (config_type IN ('saml', 'ldap', 'oauth', 'scim')),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_enabled BOOLEAN NOT NULL DEFAULT true,
    encrypted_data BYTEA NOT NULL, -- Encrypted configuration data
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_by VARCHAR(255) NOT NULL,
    updated_by VARCHAR(255) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1
);

-- Create indexes for enterprise configurations
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_enterprise_configs_org_type 
ON enterprise_configs (organization_id, config_type, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_enterprise_configs_org_enabled 
ON enterprise_configs (organization_id, is_enabled, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_enterprise_configs_type_enabled 
ON enterprise_configs (config_type, is_enabled, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_enterprise_configs_created_by 
ON enterprise_configs (created_by, created_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_enterprise_configs_updated_at 
ON enterprise_configs (updated_at DESC);

-- Create unique constraint to prevent duplicate active configs of same type per org
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_enterprise_configs_org_type_name_unique 
ON enterprise_configs (organization_id, config_type, name) 
WHERE is_enabled = true;

-- Add table comments
COMMENT ON TABLE enterprise_configs IS 'Enterprise authentication configurations with encrypted storage';
COMMENT ON COLUMN enterprise_configs.id IS 'Unique identifier for the configuration';
COMMENT ON COLUMN enterprise_configs.organization_id IS 'Organization identifier for data isolation';
COMMENT ON COLUMN enterprise_configs.config_type IS 'Type of enterprise configuration (saml, ldap, oauth, scim)';
COMMENT ON COLUMN enterprise_configs.name IS 'Human-readable name for the configuration';
COMMENT ON COLUMN enterprise_configs.description IS 'Optional description of the configuration';
COMMENT ON COLUMN enterprise_configs.is_enabled IS 'Whether the configuration is active';
COMMENT ON COLUMN enterprise_configs.encrypted_data IS 'Encrypted configuration data (AES-GCM)';
COMMENT ON COLUMN enterprise_configs.created_by IS 'User ID who created the configuration';
COMMENT ON COLUMN enterprise_configs.updated_by IS 'User ID who last updated the configuration';
COMMENT ON COLUMN enterprise_configs.version IS 'Version number for optimistic locking';

-- Create function to automatically update updated_at timestamp
CREATE OR REPLACE FUNCTION update_enterprise_configs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger to automatically update updated_at
CREATE TRIGGER trigger_enterprise_configs_updated_at
    BEFORE UPDATE ON enterprise_configs
    FOR EACH ROW
    EXECUTE FUNCTION update_enterprise_configs_updated_at();

-- Create function to validate configuration data structure
CREATE OR REPLACE FUNCTION validate_enterprise_config()
RETURNS TRIGGER AS $$
BEGIN
    -- Ensure name is not empty and contains only valid characters
    IF NEW.name IS NULL OR NEW.name = '' OR LENGTH(NEW.name) > 255 THEN
        RAISE EXCEPTION 'Configuration name must be non-empty and less than 255 characters';
    END IF;
    
    -- Ensure encrypted_data is not empty
    IF NEW.encrypted_data IS NULL OR LENGTH(NEW.encrypted_data) = 0 THEN
        RAISE EXCEPTION 'Encrypted configuration data cannot be empty';
    END IF;
    
    -- Ensure version is incremented on updates
    IF TG_OP = 'UPDATE' AND NEW.version <= OLD.version THEN
        NEW.version = OLD.version + 1;
    END IF;
    
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for validation
CREATE TRIGGER trigger_validate_enterprise_config
    BEFORE INSERT OR UPDATE ON enterprise_configs
    FOR EACH ROW
    EXECUTE FUNCTION validate_enterprise_config();

-- Create audit log function for enterprise config changes
CREATE OR REPLACE FUNCTION log_enterprise_config_change()
RETURNS TRIGGER AS $$
DECLARE
    event_type VARCHAR(100);
    details JSONB;
BEGIN
    -- Determine event type
    CASE TG_OP
        WHEN 'INSERT' THEN event_type = 'enterprise_config.created';
        WHEN 'UPDATE' THEN event_type = 'enterprise_config.updated';
        WHEN 'DELETE' THEN event_type = 'enterprise_config.deleted';
    END CASE;
    
    -- Build details object
    IF TG_OP = 'DELETE' THEN
        details = jsonb_build_object(
            'config_type', OLD.config_type,
            'name', OLD.name,
            'version', OLD.version
        );
    ELSE
        details = jsonb_build_object(
            'config_type', NEW.config_type,
            'name', NEW.name,
            'version', NEW.version,
            'is_enabled', NEW.is_enabled
        );
        
        -- Add change details for updates
        IF TG_OP = 'UPDATE' THEN
            details = details || jsonb_build_object(
                'changes', jsonb_build_object(
                    'name_changed', OLD.name != NEW.name,
                    'enabled_changed', OLD.is_enabled != NEW.is_enabled,
                    'config_changed', OLD.encrypted_data != NEW.encrypted_data,
                    'old_version', OLD.version
                )
            );
        END IF;
    END IF;
    
    -- Insert into audit_events table if it exists
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'audit_events') THEN
        INSERT INTO audit_events (
            id,
            organization_id,
            actor_type,
            actor_id,
            event_type,
            resource_type,
            resource_id,
            details,
            success,
            created_at,
            severity
        ) VALUES (
            'config_' || extract(epoch from now())::text || '_' || floor(random() * 1000)::text,
            COALESCE(NEW.organization_id, OLD.organization_id),
            'user',
            COALESCE(NEW.updated_by, NEW.created_by, OLD.updated_by),
            event_type,
            'enterprise_config',
            COALESCE(NEW.id, OLD.id),
            details,
            true,
            NOW(),
            'medium'
        );
    END IF;
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Create trigger for audit logging
CREATE TRIGGER trigger_log_enterprise_config_change
    AFTER INSERT OR UPDATE OR DELETE ON enterprise_configs
    FOR EACH ROW
    EXECUTE FUNCTION log_enterprise_config_change();

-- Create configuration history table for change tracking
CREATE TABLE IF NOT EXISTS enterprise_config_history (
    id BIGSERIAL PRIMARY KEY,
    config_id VARCHAR(255) NOT NULL,
    organization_id VARCHAR(255) NOT NULL,
    config_type VARCHAR(50) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    is_enabled BOOLEAN NOT NULL,
    encrypted_data BYTEA NOT NULL,
    version INTEGER NOT NULL,
    operation VARCHAR(20) NOT NULL CHECK (operation IN ('INSERT', 'UPDATE', 'DELETE')),
    changed_by VARCHAR(255) NOT NULL,
    changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    changes JSONB -- Specific fields that changed
);

-- Create indexes for configuration history
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_enterprise_config_history_config_id 
ON enterprise_config_history (config_id, changed_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_enterprise_config_history_org 
ON enterprise_config_history (organization_id, changed_at DESC);

CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_enterprise_config_history_changed_by 
ON enterprise_config_history (changed_by, changed_at DESC);

-- Create function to track configuration history
CREATE OR REPLACE FUNCTION track_enterprise_config_history()
RETURNS TRIGGER AS $$
DECLARE
    operation_type VARCHAR(20);
    changes_json JSONB := '{}';
BEGIN
    operation_type = TG_OP;
    
    -- For updates, track what changed
    IF TG_OP = 'UPDATE' THEN
        IF OLD.name != NEW.name THEN
            changes_json = changes_json || jsonb_build_object('name', jsonb_build_object('from', OLD.name, 'to', NEW.name));
        END IF;
        IF OLD.description != NEW.description THEN
            changes_json = changes_json || jsonb_build_object('description', jsonb_build_object('from', OLD.description, 'to', NEW.description));
        END IF;
        IF OLD.is_enabled != NEW.is_enabled THEN
            changes_json = changes_json || jsonb_build_object('is_enabled', jsonb_build_object('from', OLD.is_enabled, 'to', NEW.is_enabled));
        END IF;
        IF OLD.encrypted_data != NEW.encrypted_data THEN
            changes_json = changes_json || jsonb_build_object('config_data', 'modified');
        END IF;
    END IF;
    
    -- Insert history record
    INSERT INTO enterprise_config_history (
        config_id,
        organization_id,
        config_type,
        name,
        description,
        is_enabled,
        encrypted_data,
        version,
        operation,
        changed_by,
        changes
    ) VALUES (
        COALESCE(NEW.id, OLD.id),
        COALESCE(NEW.organization_id, OLD.organization_id),
        COALESCE(NEW.config_type, OLD.config_type),
        COALESCE(NEW.name, OLD.name),
        COALESCE(NEW.description, OLD.description),
        COALESCE(NEW.is_enabled, OLD.is_enabled),
        COALESCE(NEW.encrypted_data, OLD.encrypted_data),
        COALESCE(NEW.version, OLD.version),
        operation_type,
        COALESCE(NEW.updated_by, NEW.created_by, OLD.updated_by),
        changes_json
    );
    
    RETURN COALESCE(NEW, OLD);
END;
$$ LANGUAGE plpgsql;

-- Create trigger for history tracking
CREATE TRIGGER trigger_track_enterprise_config_history
    AFTER INSERT OR UPDATE OR DELETE ON enterprise_configs
    FOR EACH ROW
    EXECUTE FUNCTION track_enterprise_config_history();

-- Create view for active configurations
CREATE VIEW active_enterprise_configs AS
SELECT 
    id,
    organization_id,
    config_type,
    name,
    description,
    created_at,
    updated_at,
    created_by,
    updated_by,
    version
FROM enterprise_configs 
WHERE is_enabled = true;

-- Create view for configuration summary
CREATE VIEW enterprise_config_summary AS
SELECT 
    organization_id,
    config_type,
    COUNT(*) as total_configs,
    COUNT(*) FILTER (WHERE is_enabled = true) as active_configs,
    MAX(updated_at) as last_updated
FROM enterprise_configs 
GROUP BY organization_id, config_type;

-- Grant permissions
GRANT SELECT, INSERT, UPDATE ON enterprise_configs TO n8n_app_user;
GRANT SELECT ON enterprise_config_history TO n8n_app_user;
GRANT SELECT ON active_enterprise_configs TO n8n_app_user;
GRANT SELECT ON enterprise_config_summary TO n8n_app_user;

GRANT EXECUTE ON FUNCTION update_enterprise_configs_updated_at TO n8n_app_user;
GRANT EXECUTE ON FUNCTION validate_enterprise_config TO n8n_app_user;

-- Enable row level security
ALTER TABLE enterprise_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE enterprise_config_history ENABLE ROW LEVEL SECURITY;

-- Create RLS policies for organization isolation
CREATE POLICY enterprise_configs_org_isolation ON enterprise_configs
    FOR ALL
    TO n8n_app_user
    USING (organization_id = current_setting('app.current_organization_id', true));

CREATE POLICY enterprise_config_history_org_isolation ON enterprise_config_history
    FOR SELECT
    TO n8n_app_user
    USING (organization_id = current_setting('app.current_organization_id', true));

-- Create policy for system access
CREATE POLICY enterprise_configs_system_access ON enterprise_configs
    FOR ALL
    TO n8n_system_user
    USING (true);

CREATE POLICY enterprise_config_history_system_access ON enterprise_config_history
    FOR ALL
    TO n8n_system_user
    USING (true);

-- Create function to cleanup old history records
CREATE OR REPLACE FUNCTION cleanup_old_config_history(retention_days INTEGER DEFAULT 730)
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
    cutoff_date TIMESTAMP WITH TIME ZONE;
BEGIN
    cutoff_date := NOW() - INTERVAL '1 day' * retention_days;
    
    DELETE FROM enterprise_config_history 
    WHERE changed_at < cutoff_date;
    
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Grant execute permission on cleanup function
GRANT EXECUTE ON FUNCTION cleanup_old_config_history TO n8n_maintenance_user;

-- Create function to get configuration statistics
CREATE OR REPLACE FUNCTION get_config_statistics(org_id VARCHAR(255))
RETURNS TABLE(
    config_type VARCHAR(50),
    total_configs BIGINT,
    active_configs BIGINT,
    last_updated TIMESTAMP WITH TIME ZONE,
    created_this_month BIGINT,
    updated_this_month BIGINT
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        ec.config_type,
        COUNT(*) as total_configs,
        COUNT(*) FILTER (WHERE ec.is_enabled = true) as active_configs,
        MAX(ec.updated_at) as last_updated,
        COUNT(*) FILTER (WHERE ec.created_at >= DATE_TRUNC('month', NOW())) as created_this_month,
        COUNT(*) FILTER (WHERE ec.updated_at >= DATE_TRUNC('month', NOW()) AND ec.created_at < DATE_TRUNC('month', NOW())) as updated_this_month
    FROM enterprise_configs ec
    WHERE ec.organization_id = org_id
    GROUP BY ec.config_type
    ORDER BY ec.config_type;
END;
$$ LANGUAGE plpgsql;

-- Grant execute permission
GRANT EXECUTE ON FUNCTION get_config_statistics TO n8n_app_user;

-- Validate the table structure
DO $$
BEGIN
    -- Verify required indexes exist
    IF NOT EXISTS (SELECT 1 FROM pg_indexes WHERE tablename = 'enterprise_configs' AND indexname = 'idx_enterprise_configs_org_type') THEN
        RAISE EXCEPTION 'Required index idx_enterprise_configs_org_type not found';
    END IF;
    
    -- Verify RLS is enabled
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'enterprise_configs' AND rowsecurity = true) THEN
        RAISE EXCEPTION 'Row Level Security not enabled on enterprise_configs table';
    END IF;
    
    -- Verify history table exists
    IF NOT EXISTS (SELECT 1 FROM pg_tables WHERE tablename = 'enterprise_config_history') THEN
        RAISE EXCEPTION 'enterprise_config_history table not found';
    END IF;
    
    RAISE NOTICE 'Enterprise configs table validation completed successfully';
END $$;