-- Fill in missing columns and ensure database schema consistency

-- Ensure workflows table has all required columns
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'draft';
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS team_id UUID;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS owner_id UUID;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS variables JSONB DEFAULT '[]';
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS settings JSONB DEFAULT '{}';
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS is_template BOOLEAN DEFAULT false;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '[]';

-- Add missing constraints if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'valid_workflow_status') THEN
        ALTER TABLE workflows ADD CONSTRAINT valid_workflow_status 
        CHECK (status IN ('draft', 'active', 'inactive', 'archived'));
    END IF;
END $$;

-- Ensure workflow_executions table exists and has all required columns
CREATE TABLE IF NOT EXISTS workflow_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL,
    team_id UUID,
    
    -- Execution details
    status VARCHAR(50) NOT NULL DEFAULT 'running',
    mode VARCHAR(50) DEFAULT 'manual',
    start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    duration INTEGER, -- milliseconds
    
    -- Trigger information
    trigger_type VARCHAR(50) DEFAULT 'manual',
    trigger_data JSONB DEFAULT '{}',
    
    -- Input/Output
    input_data JSONB DEFAULT '{}',
    output_data JSONB DEFAULT '{}',
    error_data JSONB,
    
    -- Progress tracking
    total_nodes INTEGER DEFAULT 0,
    completed_nodes INTEGER DEFAULT 0,
    failed_nodes INTEGER DEFAULT 0,
    skipped_nodes INTEGER DEFAULT 0,
    
    -- Resource usage
    memory_usage BIGINT DEFAULT 0,
    cpu_time INTEGER DEFAULT 0,
    
    -- Retry information
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    parent_execution_id UUID,
    
    -- Context
    user_id UUID,
    user_agent TEXT,
    ip_address INET,
    
    -- Metadata
    metadata JSONB DEFAULT '{}',
    
    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT valid_execution_status CHECK (status IN ('pending', 'running', 'completed', 'failed', 'cancelled', 'paused')),
    CONSTRAINT valid_execution_mode CHECK (mode IN ('manual', 'webhook', 'schedule', 'test', 'retry'))
);

-- Add missing indexes
CREATE INDEX IF NOT EXISTS idx_workflow_executions_workflow_id ON workflow_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_status ON workflow_executions(status);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_team_id ON workflow_executions(team_id);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_user_id ON workflow_executions(user_id);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_start_time ON workflow_executions(start_time);
CREATE INDEX IF NOT EXISTS idx_workflow_executions_deleted_at ON workflow_executions(deleted_at);

-- Add updated_at trigger for workflow_executions if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_workflow_executions_updated_at') THEN
        CREATE TRIGGER update_workflow_executions_updated_at BEFORE UPDATE ON workflow_executions
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

-- Add updated_at trigger for workflows if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'update_workflows_updated_at') THEN
        CREATE TRIGGER update_workflows_updated_at BEFORE UPDATE ON workflows
            FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
    END IF;
END $$;

-- Add foreign key constraints if they don't exist
DO $$
BEGIN
    -- workflow_executions -> workflows
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_workflow_executions_workflow_id') THEN
        ALTER TABLE workflow_executions ADD CONSTRAINT fk_workflow_executions_workflow_id 
        FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE;
    END IF;
    
    -- workflow_executions -> users
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_workflow_executions_user_id') THEN
        ALTER TABLE workflow_executions ADD CONSTRAINT fk_workflow_executions_user_id 
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL;
    END IF;
    
    -- workflows -> teams
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_workflows_team_id') THEN
        ALTER TABLE workflows ADD CONSTRAINT fk_workflows_team_id 
        FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL;
    END IF;
    
    -- workflows -> users (owner)
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_workflows_owner_id') THEN
        ALTER TABLE workflows ADD CONSTRAINT fk_workflows_owner_id 
        FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE SET NULL;
    END IF;
    
    -- credentials -> users
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_credentials_owner_id') THEN
        ALTER TABLE credentials ADD CONSTRAINT fk_credentials_owner_id 
        FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE;
    END IF;
    
    -- credentials -> teams
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_credentials_team_id') THEN
        ALTER TABLE credentials ADD CONSTRAINT fk_credentials_team_id 
        FOREIGN KEY (team_id) REFERENCES teams(id) ON DELETE SET NULL;
    END IF;
    
    -- webhooks -> workflows
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'fk_webhooks_workflow_id') THEN
        ALTER TABLE webhooks ADD CONSTRAINT fk_webhooks_workflow_id 
        FOREIGN KEY (workflow_id) REFERENCES workflows(id) ON DELETE CASCADE;
    END IF;
END $$;