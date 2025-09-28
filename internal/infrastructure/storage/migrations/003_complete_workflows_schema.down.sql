-- Drop workflow-related tables and indexes
-- This is the down migration for 003_complete_workflows_schema.up.sql

-- Drop indexes first
DROP INDEX IF EXISTS idx_executions_workflow_id;
DROP INDEX IF EXISTS idx_executions_status;
DROP INDEX IF EXISTS idx_executions_user_id;
DROP INDEX IF EXISTS idx_executions_team_id;
DROP INDEX IF EXISTS idx_executions_started_at;
DROP INDEX IF EXISTS idx_executions_finished_at;

DROP INDEX IF EXISTS idx_execution_data_execution_id;
DROP INDEX IF EXISTS idx_execution_data_node_name;

-- Drop tables
DROP TABLE IF EXISTS execution_data;
DROP TABLE IF EXISTS executions;