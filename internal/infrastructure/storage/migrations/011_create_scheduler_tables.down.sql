-- Migration: Drop scheduler tables
-- Version: 011
-- Description: Remove tables for scheduled jobs and job executions

-- Drop tables in reverse order (child tables first)
DROP TABLE IF EXISTS job_executions CASCADE;
DROP TABLE IF EXISTS scheduled_jobs CASCADE;

-- Drop the trigger function
DROP FUNCTION IF EXISTS update_scheduled_jobs_updated_at() CASCADE;