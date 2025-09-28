-- Drop workflows table and related indexes
-- This is the down migration for 002_create_workflows_table.up.sql

DROP INDEX IF EXISTS idx_workflows_team_id;
DROP INDEX IF EXISTS idx_workflows_user_id;
DROP INDEX IF EXISTS idx_workflows_active;
DROP INDEX IF EXISTS idx_workflows_created_at;
DROP INDEX IF EXISTS idx_workflows_updated_at;

DROP TABLE IF EXISTS workflows;