-- PostgreSQL initialization script for n8n Pro
-- This script creates the necessary extensions and initial database structure

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Create schema for migrations
CREATE SCHEMA IF NOT EXISTS public;

-- Grant permissions to the user
GRANT ALL PRIVILEGES ON DATABASE n8n_clone TO "user";
GRANT ALL PRIVILEGES ON SCHEMA public TO "user";
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO "user";
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO "user";
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO "user";

-- Set default privileges for future objects
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO "user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO "user";
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON FUNCTIONS TO "user";

-- Create a function to generate UUIDs (fallback if uuid-ossp is not available)
CREATE OR REPLACE FUNCTION generate_uuid() RETURNS uuid AS $$
BEGIN
    RETURN gen_random_uuid();
EXCEPTION
    WHEN undefined_function THEN
        RETURN uuid_generate_v4();
END;
$$ LANGUAGE plpgsql;

-- Optimize PostgreSQL settings for n8n Pro workload
ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';
ALTER SYSTEM SET log_statement = 'none';
ALTER SYSTEM SET log_min_duration_statement = 1000;
ALTER SYSTEM SET checkpoint_completion_target = 0.9;
ALTER SYSTEM SET wal_buffers = '16MB';
ALTER SYSTEM SET default_statistics_target = 100;

-- Create indexes that will be commonly used
-- These will be overridden by migrations, but provide a starting point