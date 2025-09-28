-- Create node_execution_logs table for detailed execution logging
CREATE TABLE IF NOT EXISTS node_execution_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_execution_id UUID NOT NULL,
    node_id VARCHAR(255) NOT NULL,
    node_name VARCHAR(255) NOT NULL,
    node_type VARCHAR(100) NOT NULL,
    
    -- Execution details
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    duration INTEGER, -- milliseconds
    
    -- Data
    input_data JSONB,
    output_data JSONB,
    error_data JSONB,
    
    -- Performance metrics
    memory_used BIGINT, -- bytes
    cpu_time INTEGER,   -- milliseconds
    
    -- Retry information
    retry_count INTEGER DEFAULT 0,
    parent_execution_id UUID, -- For retry tracking
    
    -- Metadata
    execution_order INTEGER,
    metadata JSONB DEFAULT '{}',
    
    -- Constraints
    CONSTRAINT valid_node_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'skipped', 'cancelled'))
);

-- Create api_keys table for API authentication
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    key_prefix VARCHAR(20) NOT NULL, -- First few characters for identification
    
    -- Ownership
    user_id UUID NOT NULL,
    team_id UUID,
    
    -- Permissions and scope
    scopes TEXT[] DEFAULT ARRAY['workflows:read'],
    permissions JSONB DEFAULT '{}',
    
    -- Security
    ip_whitelist TEXT[],
    rate_limit INTEGER DEFAULT 1000, -- requests per hour
    
    -- Usage tracking
    last_used_at TIMESTAMPTZ,
    usage_count INTEGER DEFAULT 0,
    
    -- Status
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMPTZ,
    
    -- Metadata
    description TEXT,
    
    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ
);

-- Create audit_logs table for system audit trail
CREATE TABLE IF NOT EXISTS audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Actor information
    user_id UUID,
    api_key_id UUID,
    team_id UUID,
    
    -- Action details
    action VARCHAR(100) NOT NULL, -- create, update, delete, execute, etc.
    resource_type VARCHAR(100) NOT NULL, -- workflow, user, team, etc.
    resource_id VARCHAR(255),
    
    -- Request context
    ip_address INET,
    user_agent TEXT,
    request_id VARCHAR(255),
    
    -- Change details
    old_values JSONB,
    new_values JSONB,
    changes JSONB,
    
    -- Outcome
    success BOOLEAN NOT NULL,
    error_message TEXT,
    
    -- Additional context
    metadata JSONB DEFAULT '{}',
    
    -- Timestamp
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create system_settings table for application configuration
CREATE TABLE IF NOT EXISTS system_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key VARCHAR(255) NOT NULL UNIQUE,
    value JSONB NOT NULL,
    description TEXT,
    category VARCHAR(100) DEFAULT 'general', -- general, security, notifications, etc.
    
    -- Validation
    value_type VARCHAR(50) NOT NULL DEFAULT 'string', -- string, number, boolean, json, array
    validation_rules JSONB,
    is_sensitive BOOLEAN DEFAULT false,
    
    -- Audit fields
    updated_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create notifications table for system notifications
CREATE TABLE IF NOT EXISTS notifications (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    
    -- Recipients
    user_id UUID,
    team_id UUID, -- For team-wide notifications
    
    -- Notification content
    title VARCHAR(255) NOT NULL,
    message TEXT NOT NULL,
    type VARCHAR(50) NOT NULL DEFAULT 'info', -- info, warning, error, success
    category VARCHAR(100) DEFAULT 'system', -- system, workflow, security, billing
    
    -- Action details
    action_url VARCHAR(500),
    action_text VARCHAR(100),
    
    -- Status
    is_read BOOLEAN DEFAULT false,
    read_at TIMESTAMPTZ,
    
    -- Delivery
    delivery_channels TEXT[] DEFAULT ARRAY['app'], -- app, email, slack, webhook
    delivered_at TIMESTAMPTZ,
    
    -- Expiration
    expires_at TIMESTAMPTZ,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT valid_notification_type CHECK (type IN ('info', 'warning', 'error', 'success'))
);

-- Create indexes for node_execution_logs
CREATE INDEX IF NOT EXISTS idx_node_logs_workflow_execution_id ON node_execution_logs(workflow_execution_id);
CREATE INDEX IF NOT EXISTS idx_node_logs_node_id ON node_execution_logs(node_id);
CREATE INDEX IF NOT EXISTS idx_node_logs_status ON node_execution_logs(status);
CREATE INDEX IF NOT EXISTS idx_node_logs_start_time ON node_execution_logs(start_time);
CREATE INDEX IF NOT EXISTS idx_node_logs_node_type ON node_execution_logs(node_type);

-- Create indexes for api_keys
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_team_id ON api_keys(team_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_revoked_at ON api_keys(revoked_at);

-- Create indexes for audit_logs
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_team_id ON audit_logs(team_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON audit_logs(resource_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_id ON audit_logs(resource_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address ON audit_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_success ON audit_logs(success);

-- Create indexes for system_settings
CREATE INDEX IF NOT EXISTS idx_system_settings_category ON system_settings(category);
CREATE INDEX IF NOT EXISTS idx_system_settings_is_sensitive ON system_settings(is_sensitive);

-- Create indexes for notifications
CREATE INDEX IF NOT EXISTS idx_notifications_user_id ON notifications(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_team_id ON notifications(team_id);
CREATE INDEX IF NOT EXISTS idx_notifications_type ON notifications(type);
CREATE INDEX IF NOT EXISTS idx_notifications_category ON notifications(category);
CREATE INDEX IF NOT EXISTS idx_notifications_is_read ON notifications(is_read);
CREATE INDEX IF NOT EXISTS idx_notifications_created_at ON notifications(created_at);
CREATE INDEX IF NOT EXISTS idx_notifications_expires_at ON notifications(expires_at);

-- Add triggers for automatic updated_at updates
CREATE TRIGGER update_api_keys_updated_at BEFORE UPDATE ON api_keys
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_system_settings_updated_at BEFORE UPDATE ON system_settings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_notifications_updated_at BEFORE UPDATE ON notifications
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();