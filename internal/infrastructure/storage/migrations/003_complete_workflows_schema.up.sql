-- Add missing columns to workflows table to match the repository expectations

-- Add workflow metadata columns
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS description TEXT;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'draft';
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS team_id UUID;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS owner_id UUID;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS version INTEGER DEFAULT 1;

-- Add template support
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS is_template BOOLEAN DEFAULT false;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS template_id UUID;

-- Add workflow configuration
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS variables JSONB DEFAULT '[]';
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS triggers JSONB DEFAULT '[]';
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS config JSONB DEFAULT '{}';
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS tags JSONB DEFAULT '[]';
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS metadata JSONB DEFAULT '{}';

-- Add execution tracking
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS execution_count INTEGER DEFAULT 0;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS last_executed_at TIMESTAMPTZ;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS last_execution_id UUID;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS success_rate DECIMAL(5,2) DEFAULT 0.0;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS average_runtime INTEGER DEFAULT 0; -- in milliseconds

-- Add audit fields
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS created_by UUID;
ALTER TABLE workflows ADD COLUMN IF NOT EXISTS updated_by UUID;

-- Add indexes for performance
CREATE INDEX IF NOT EXISTS idx_workflows_status ON workflows(status);
CREATE INDEX IF NOT EXISTS idx_workflows_team_id ON workflows(team_id);
CREATE INDEX IF NOT EXISTS idx_workflows_owner_id ON workflows(owner_id);
CREATE INDEX IF NOT EXISTS idx_workflows_is_template ON workflows(is_template);
CREATE INDEX IF NOT EXISTS idx_workflows_deleted_at ON workflows(deleted_at);
CREATE INDEX IF NOT EXISTS idx_workflows_created_at ON workflows(created_at);
CREATE INDEX IF NOT EXISTS idx_workflows_last_executed ON workflows(last_executed_at);

-- Create workflow_executions table for execution tracking
CREATE TABLE IF NOT EXISTS workflow_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL REFERENCES workflows(id) ON DELETE CASCADE,
    workflow_name VARCHAR(255) NOT NULL,
    team_id UUID,
    trigger_id UUID,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    mode VARCHAR(50) DEFAULT 'manual',
    
    -- Execution data
    trigger_data JSONB,
    input_data JSONB,
    output_data JSONB,
    
    -- Error handling
    error_message TEXT,
    error_stack TEXT,
    error_node_id VARCHAR(255),
    
    -- Timing
    start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    duration INTEGER DEFAULT 0, -- in milliseconds
    
    -- Progress tracking
    nodes_executed INTEGER DEFAULT 0,
    nodes_total INTEGER DEFAULT 0,
    
    -- Retry logic
    retry_count INTEGER DEFAULT 0,
    max_retries INTEGER DEFAULT 3,
    parent_execution_id UUID,
    
    -- Resource usage
    memory_usage BIGINT DEFAULT 0, -- in bytes
    cpu_time INTEGER DEFAULT 0,    -- in milliseconds
    
    -- Request context
    user_agent TEXT,
    ip_address INET,
    
    -- Additional metadata
    metadata JSONB DEFAULT '{}',
    
    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ
);

-- Add indexes for workflow_executions
CREATE INDEX IF NOT EXISTS idx_executions_workflow_id ON workflow_executions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_executions_status ON workflow_executions(status);
CREATE INDEX IF NOT EXISTS idx_executions_team_id ON workflow_executions(team_id);
CREATE INDEX IF NOT EXISTS idx_executions_start_time ON workflow_executions(start_time);
CREATE INDEX IF NOT EXISTS idx_executions_deleted_at ON workflow_executions(deleted_at);
CREATE INDEX IF NOT EXISTS idx_executions_parent_id ON workflow_executions(parent_execution_id);

-- Update existing workflows to have valid status
UPDATE workflows SET status = 'draft' WHERE status IS NULL;