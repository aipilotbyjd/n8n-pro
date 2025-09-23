-- Create webhooks table
CREATE TABLE IF NOT EXISTS webhooks (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    workflow_id UUID NOT NULL,
    webhook_id VARCHAR(255) NOT NULL UNIQUE, -- The URL path identifier
    method VARCHAR(10) NOT NULL DEFAULT 'POST',
    path VARCHAR(500) NOT NULL,
    is_test BOOLEAN DEFAULT false,
    response_mode VARCHAR(50) DEFAULT 'first_entrant', -- first_entrant, all_entrants, last_node
    response_data TEXT,
    response_headers JSONB DEFAULT '{}',
    response_status_code INTEGER DEFAULT 200,
    
    -- Authentication
    auth_enabled BOOLEAN DEFAULT false,
    auth_type VARCHAR(50), -- basic, bearer, query, header
    auth_credentials JSONB DEFAULT '{}',
    
    -- CORS settings
    cors_enabled BOOLEAN DEFAULT false,
    cors_origins TEXT[],
    cors_methods TEXT[],
    cors_headers TEXT[],
    
    -- Rate limiting
    rate_limit_enabled BOOLEAN DEFAULT false,
    rate_limit_requests INTEGER DEFAULT 100,
    rate_limit_window INTEGER DEFAULT 3600, -- seconds
    
    -- Request filtering
    allowed_ips TEXT[],
    blocked_ips TEXT[],
    
    -- Activity tracking
    last_called_at TIMESTAMPTZ,
    call_count INTEGER DEFAULT 0,
    
    -- Configuration
    timeout INTEGER DEFAULT 30, -- seconds
    max_body_size BIGINT DEFAULT 1048576, -- 1MB in bytes
    
    -- Metadata
    description TEXT,
    tags JSONB DEFAULT '[]',
    settings JSONB DEFAULT '{}',
    
    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT valid_method CHECK (method IN ('GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS')),
    CONSTRAINT valid_response_mode CHECK (response_mode IN ('first_entrant', 'all_entrants', 'last_node')),
    CONSTRAINT valid_auth_type CHECK (auth_type IS NULL OR auth_type IN ('basic', 'bearer', 'query', 'header')),
    CONSTRAINT valid_timeout CHECK (timeout > 0 AND timeout <= 300)
);

-- Create webhook_executions table for tracking webhook calls
CREATE TABLE IF NOT EXISTS webhook_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    webhook_id UUID NOT NULL,
    workflow_execution_id UUID,
    
    -- Request details
    method VARCHAR(10) NOT NULL,
    url TEXT NOT NULL,
    headers JSONB DEFAULT '{}',
    query_params JSONB DEFAULT '{}',
    body TEXT,
    body_size BIGINT DEFAULT 0,
    
    -- Response details
    response_status INTEGER,
    response_headers JSONB DEFAULT '{}',
    response_body TEXT,
    response_size BIGINT DEFAULT 0,
    
    -- Client information
    ip_address INET,
    user_agent TEXT,
    referer TEXT,
    
    -- Execution details
    execution_time INTEGER, -- milliseconds
    success BOOLEAN DEFAULT false,
    error_message TEXT,
    
    -- Timestamps
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    completed_at TIMESTAMPTZ,
    
    -- Foreign key constraints
    FOREIGN KEY (webhook_id) REFERENCES webhooks(id) ON DELETE CASCADE
);

-- Create indexes for webhooks table
CREATE INDEX IF NOT EXISTS idx_webhooks_webhook_id ON webhooks(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_workflow_id ON webhooks(workflow_id);
CREATE INDEX IF NOT EXISTS idx_webhooks_path ON webhooks(path);
CREATE INDEX IF NOT EXISTS idx_webhooks_method ON webhooks(method);
CREATE INDEX IF NOT EXISTS idx_webhooks_is_test ON webhooks(is_test);
CREATE INDEX IF NOT EXISTS idx_webhooks_deleted_at ON webhooks(deleted_at);
CREATE INDEX IF NOT EXISTS idx_webhooks_created_at ON webhooks(created_at);
CREATE INDEX IF NOT EXISTS idx_webhooks_tags ON webhooks USING GIN(tags);

-- Create indexes for webhook_executions table
CREATE INDEX IF NOT EXISTS idx_webhook_executions_webhook_id ON webhook_executions(webhook_id);
CREATE INDEX IF NOT EXISTS idx_webhook_executions_workflow_execution_id ON webhook_executions(workflow_execution_id);
CREATE INDEX IF NOT EXISTS idx_webhook_executions_ip_address ON webhook_executions(ip_address);
CREATE INDEX IF NOT EXISTS idx_webhook_executions_started_at ON webhook_executions(started_at);
CREATE INDEX IF NOT EXISTS idx_webhook_executions_success ON webhook_executions(success);

-- Add trigger for automatic updated_at update
CREATE TRIGGER update_webhooks_updated_at BEFORE UPDATE ON webhooks
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();