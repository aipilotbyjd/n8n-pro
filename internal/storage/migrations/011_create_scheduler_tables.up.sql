-- Migration: Create scheduler tables
-- Version: 011
-- Description: Create tables for scheduled jobs and job executions

-- Create scheduled_jobs table
CREATE TABLE IF NOT EXISTS scheduled_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL,
    team_id UUID NOT NULL,
    name VARCHAR(255) NOT NULL,
    cron_expression VARCHAR(100) NOT NULL,
    timezone VARCHAR(50) NOT NULL DEFAULT 'UTC',
    enabled BOOLEAN NOT NULL DEFAULT true,
    next_run_time TIMESTAMPTZ,
    last_run_time TIMESTAMPTZ,
    last_run_status VARCHAR(50) DEFAULT 'pending',
    run_count BIGINT NOT NULL DEFAULT 0,
    failure_count BIGINT NOT NULL DEFAULT 0,
    parameters JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID NOT NULL,
    deleted_at TIMESTAMPTZ
);

-- Create indexes for scheduled_jobs
CREATE INDEX idx_scheduled_jobs_workflow_id ON scheduled_jobs(workflow_id);
CREATE INDEX idx_scheduled_jobs_team_id ON scheduled_jobs(team_id);
CREATE INDEX idx_scheduled_jobs_enabled ON scheduled_jobs(enabled);
CREATE INDEX idx_scheduled_jobs_next_run_time ON scheduled_jobs(next_run_time);
CREATE INDEX idx_scheduled_jobs_deleted_at ON scheduled_jobs(deleted_at);

-- Create job_executions table
CREATE TABLE IF NOT EXISTS job_executions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    job_id UUID NOT NULL REFERENCES scheduled_jobs(id) ON DELETE CASCADE,
    workflow_id UUID NOT NULL,
    team_id UUID NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    start_time TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    end_time TIMESTAMPTZ,
    duration BIGINT, -- Duration in milliseconds
    error TEXT,
    trigger_data JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Create indexes for job_executions
CREATE INDEX idx_job_executions_job_id ON job_executions(job_id);
CREATE INDEX idx_job_executions_workflow_id ON job_executions(workflow_id);
CREATE INDEX idx_job_executions_team_id ON job_executions(team_id);
CREATE INDEX idx_job_executions_status ON job_executions(status);
CREATE INDEX idx_job_executions_created_at ON job_executions(created_at);

-- Create updated_at trigger function for scheduled_jobs
CREATE OR REPLACE FUNCTION update_scheduled_jobs_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create trigger for updated_at on scheduled_jobs
DROP TRIGGER IF EXISTS trigger_scheduled_jobs_updated_at ON scheduled_jobs;
CREATE TRIGGER trigger_scheduled_jobs_updated_at
    BEFORE UPDATE ON scheduled_jobs
    FOR EACH ROW
    EXECUTE FUNCTION update_scheduled_jobs_updated_at();

-- Add comments for documentation
COMMENT ON TABLE scheduled_jobs IS 'Stores scheduled workflow jobs with cron expressions';
COMMENT ON TABLE job_executions IS 'Stores execution history of scheduled jobs';

COMMENT ON COLUMN scheduled_jobs.cron_expression IS 'Cron expression for job scheduling';
COMMENT ON COLUMN scheduled_jobs.timezone IS 'Timezone for cron expression evaluation';
COMMENT ON COLUMN scheduled_jobs.parameters IS 'Additional parameters passed to workflow';
COMMENT ON COLUMN job_executions.duration IS 'Job execution duration in milliseconds';
COMMENT ON COLUMN job_executions.trigger_data IS 'Data passed to workflow execution';