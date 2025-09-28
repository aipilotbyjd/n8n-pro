-- Migration: Enhanced Authentication Security Features
-- Version: 005
-- Description: Adds password history, enhanced sessions, email tokens, and security features

-- ============================================================================
-- Password History Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS password_history (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Indexes
    CONSTRAINT password_history_user_id_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_password_history_user_id ON password_history(user_id);
CREATE INDEX IF NOT EXISTS idx_password_history_created_at ON password_history(created_at);

-- ============================================================================
-- Enhanced Sessions Table (if not exists, create; otherwise alter)
-- ============================================================================
-- Drop and recreate with enhanced structure
DROP TABLE IF EXISTS sessions CASCADE;

CREATE TABLE sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL UNIQUE,
    access_token_hash VARCHAR(255),
    
    -- Device information
    device_id VARCHAR(255),
    device_name VARCHAR(255),
    device_type VARCHAR(50), -- mobile, desktop, tablet, other
    browser VARCHAR(100),
    browser_version VARCHAR(50),
    os VARCHAR(100),
    os_version VARCHAR(50),
    
    -- Location and network
    ip_address VARCHAR(45) NOT NULL, -- IPv6 max length
    ip_location VARCHAR(255),
    country_code VARCHAR(2),
    city VARCHAR(255),
    
    -- Session metadata
    user_agent TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    is_trusted BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_verified BOOLEAN NOT NULL DEFAULT FALSE,
    
    -- Timestamps
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    last_activity_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_reason VARCHAR(255),
    
    -- Constraints
    CONSTRAINT sessions_refresh_token_hash_not_empty CHECK (refresh_token_hash != ''),
    CONSTRAINT sessions_ip_address_not_empty CHECK (ip_address != ''),
    CONSTRAINT sessions_user_agent_not_empty CHECK (user_agent != '')
);

-- Create indexes for sessions
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_hash ON sessions(refresh_token_hash) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_access_token_hash ON sessions(access_token_hash) WHERE access_token_hash IS NOT NULL AND revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id) WHERE device_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_activity_at ON sessions(last_activity_at);
CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_ip_address ON sessions(ip_address);

-- ============================================================================
-- Email Tokens Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS email_tokens (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_type VARCHAR(50) NOT NULL CHECK (token_type IN ('verification', 'password_reset', 'email_change', 'magic_link')),
    token_hash VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL,
    new_email VARCHAR(255), -- For email change tokens
    
    -- Metadata
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    
    -- Timestamps
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT email_tokens_token_hash_not_empty CHECK (token_hash != ''),
    CONSTRAINT email_tokens_email_not_empty CHECK (email != '')
);

-- Create indexes for email tokens
CREATE INDEX IF NOT EXISTS idx_email_tokens_user_id ON email_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_email_tokens_token_hash ON email_tokens(token_hash) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_email_tokens_token_type ON email_tokens(token_type);
CREATE INDEX IF NOT EXISTS idx_email_tokens_email ON email_tokens(email);
CREATE INDEX IF NOT EXISTS idx_email_tokens_expires_at ON email_tokens(expires_at);
CREATE INDEX IF NOT EXISTS idx_email_tokens_created_at ON email_tokens(created_at);

-- ============================================================================
-- Login Attempts Table (for detailed tracking)
-- ============================================================================
CREATE TABLE IF NOT EXISTS login_attempts (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) REFERENCES users(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    
    -- Attempt details
    attempt_type VARCHAR(50) NOT NULL DEFAULT 'password' CHECK (attempt_type IN ('password', 'mfa', 'social', 'magic_link', 'api_key')),
    status VARCHAR(50) NOT NULL CHECK (status IN ('success', 'failed', 'blocked', 'suspicious')),
    failure_reason VARCHAR(255),
    
    -- Risk assessment
    risk_score INTEGER DEFAULT 0 CHECK (risk_score >= 0 AND risk_score <= 100),
    risk_factors JSONB,
    
    -- Metadata
    device_fingerprint VARCHAR(255),
    location VARCHAR(255),
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT login_attempts_email_not_empty CHECK (email != ''),
    CONSTRAINT login_attempts_ip_not_empty CHECK (ip_address != '')
);

-- Create indexes for login attempts
CREATE INDEX IF NOT EXISTS idx_login_attempts_user_id ON login_attempts(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_login_attempts_email ON login_attempts(email);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip_address ON login_attempts(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_attempts_status ON login_attempts(status);
CREATE INDEX IF NOT EXISTS idx_login_attempts_created_at ON login_attempts(created_at);
CREATE INDEX IF NOT EXISTS idx_login_attempts_risk_score ON login_attempts(risk_score) WHERE risk_score > 50;

-- ============================================================================
-- MFA Backup Codes Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS mfa_backup_codes (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT mfa_backup_codes_unique_code_per_user UNIQUE (user_id, code_hash)
);

-- Create indexes for MFA backup codes
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_user_id ON mfa_backup_codes(user_id);
CREATE INDEX IF NOT EXISTS idx_mfa_backup_codes_code_hash ON mfa_backup_codes(code_hash) WHERE used_at IS NULL;

-- ============================================================================
-- Trusted Devices Table
-- ============================================================================
CREATE TABLE IF NOT EXISTS trusted_devices (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    
    -- Trust information
    trust_token_hash VARCHAR(255) NOT NULL UNIQUE,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    
    -- Device details
    device_type VARCHAR(50),
    browser VARCHAR(100),
    os VARCHAR(100),
    last_ip_address VARCHAR(45),
    last_location VARCHAR(255),
    
    -- Timestamps
    last_used_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT trusted_devices_unique_device_per_user UNIQUE (user_id, device_fingerprint)
);

-- Create indexes for trusted devices
CREATE INDEX IF NOT EXISTS idx_trusted_devices_user_id ON trusted_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_device_fingerprint ON trusted_devices(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_trust_token_hash ON trusted_devices(trust_token_hash) WHERE is_active = TRUE;
CREATE INDEX IF NOT EXISTS idx_trusted_devices_expires_at ON trusted_devices(expires_at);

-- ============================================================================
-- Security Events Table (for advanced tracking)
-- ============================================================================
CREATE TABLE IF NOT EXISTS security_events (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) REFERENCES users(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    event_category VARCHAR(50) NOT NULL CHECK (event_category IN ('auth', 'access', 'modification', 'security', 'compliance')),
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('info', 'warning', 'error', 'critical')),
    
    -- Event details
    description TEXT NOT NULL,
    details JSONB,
    
    -- Context
    ip_address VARCHAR(45),
    user_agent TEXT,
    session_id VARCHAR(255),
    
    -- Response
    action_taken VARCHAR(255),
    alert_sent BOOLEAN NOT NULL DEFAULT FALSE,
    
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT security_events_event_type_not_empty CHECK (event_type != ''),
    CONSTRAINT security_events_description_not_empty CHECK (description != '')
);

-- Create indexes for security events
CREATE INDEX IF NOT EXISTS idx_security_events_user_id ON security_events(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_security_events_event_type ON security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_security_events_event_category ON security_events(event_category);
CREATE INDEX IF NOT EXISTS idx_security_events_severity ON security_events(severity);
CREATE INDEX IF NOT EXISTS idx_security_events_created_at ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_security_events_session_id ON security_events(session_id) WHERE session_id IS NOT NULL;

-- ============================================================================
-- Rate Limit Buckets Table (for persistent rate limiting)
-- ============================================================================
CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    id VARCHAR(255) PRIMARY KEY,
    bucket_key VARCHAR(255) NOT NULL UNIQUE, -- e.g., "login:ip:192.168.1.1" or "api:user:123"
    bucket_type VARCHAR(50) NOT NULL,
    
    -- Token bucket algorithm
    tokens INTEGER NOT NULL DEFAULT 0,
    max_tokens INTEGER NOT NULL,
    refill_rate INTEGER NOT NULL, -- tokens per minute
    last_refill_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Metadata
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT rate_limit_buckets_key_not_empty CHECK (bucket_key != '')
);

-- Create indexes for rate limit buckets
CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_bucket_key ON rate_limit_buckets(bucket_key);
CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_bucket_type ON rate_limit_buckets(bucket_type);
CREATE INDEX IF NOT EXISTS idx_rate_limit_buckets_updated_at ON rate_limit_buckets(updated_at);

-- ============================================================================
-- Add new columns to users table if they don't exist
-- ============================================================================
DO $$ 
BEGIN
    -- Add suspended_at column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='suspended_at') THEN
        ALTER TABLE users ADD COLUMN suspended_at TIMESTAMP WITH TIME ZONE;
    END IF;
    
    -- Add suspension_reason column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='suspension_reason') THEN
        ALTER TABLE users ADD COLUMN suspension_reason VARCHAR(255);
    END IF;
    
    -- Add password_history_limit column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='password_history_limit') THEN
        ALTER TABLE users ADD COLUMN password_history_limit INTEGER NOT NULL DEFAULT 5;
    END IF;
    
    -- Add security_questions column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='security_questions') THEN
        ALTER TABLE users ADD COLUMN security_questions JSONB;
    END IF;
    
    -- Add trusted_ips column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='trusted_ips') THEN
        ALTER TABLE users ADD COLUMN trusted_ips JSONB DEFAULT '[]';
    END IF;
    
    -- Add requires_password_change column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='requires_password_change') THEN
        ALTER TABLE users ADD COLUMN requires_password_change BOOLEAN NOT NULL DEFAULT FALSE;
    END IF;
    
    -- Add session_timeout_minutes column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='session_timeout_minutes') THEN
        ALTER TABLE users ADD COLUMN session_timeout_minutes INTEGER;
    END IF;
    
    -- Add max_concurrent_sessions column
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='users' AND column_name='max_concurrent_sessions') THEN
        ALTER TABLE users ADD COLUMN max_concurrent_sessions INTEGER;
    END IF;
END $$;

-- ============================================================================
-- Create functions for security features
-- ============================================================================

-- Function to clean up expired tokens
CREATE OR REPLACE FUNCTION cleanup_expired_tokens() RETURNS void AS $$
BEGIN
    -- Delete expired email tokens
    DELETE FROM email_tokens WHERE expires_at < NOW() AND consumed_at IS NULL;
    
    -- Delete expired sessions
    UPDATE sessions SET is_active = FALSE WHERE expires_at < NOW() AND is_active = TRUE;
    
    -- Delete old login attempts (keep 30 days)
    DELETE FROM login_attempts WHERE created_at < NOW() - INTERVAL '30 days';
    
    -- Delete old security events (keep 90 days for non-critical events)
    DELETE FROM security_events 
    WHERE created_at < NOW() - INTERVAL '90 days' 
    AND severity != 'critical';
    
    -- Delete expired trusted devices
    DELETE FROM trusted_devices WHERE expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Function to check password history
CREATE OR REPLACE FUNCTION check_password_history(
    p_user_id VARCHAR(255),
    p_password_hash VARCHAR(255)
) RETURNS BOOLEAN AS $$
DECLARE
    v_limit INTEGER;
    v_count INTEGER;
BEGIN
    -- Get user's password history limit
    SELECT password_history_limit INTO v_limit
    FROM users WHERE id = p_user_id;
    
    IF v_limit IS NULL OR v_limit = 0 THEN
        RETURN TRUE; -- No history check required
    END IF;
    
    -- Check if password exists in recent history
    SELECT COUNT(*) INTO v_count
    FROM (
        SELECT password_hash 
        FROM password_history 
        WHERE user_id = p_user_id 
        ORDER BY created_at DESC 
        LIMIT v_limit
    ) recent_passwords
    WHERE password_hash = p_password_hash;
    
    RETURN v_count = 0; -- Return true if password not found in history
END;
$$ LANGUAGE plpgsql;

-- Function to record security event
CREATE OR REPLACE FUNCTION record_security_event(
    p_user_id VARCHAR(255),
    p_event_type VARCHAR(100),
    p_event_category VARCHAR(50),
    p_severity VARCHAR(20),
    p_description TEXT,
    p_details JSONB DEFAULT NULL,
    p_ip_address VARCHAR(45) DEFAULT NULL,
    p_user_agent TEXT DEFAULT NULL,
    p_session_id VARCHAR(255) DEFAULT NULL
) RETURNS VARCHAR(255) AS $$
DECLARE
    v_event_id VARCHAR(255);
BEGIN
    v_event_id := gen_random_uuid()::text;
    
    INSERT INTO security_events (
        id, user_id, event_type, event_category, severity,
        description, details, ip_address, user_agent, session_id
    ) VALUES (
        v_event_id, p_user_id, p_event_type, p_event_category, p_severity,
        p_description, p_details, p_ip_address, p_user_agent, p_session_id
    );
    
    -- Trigger alerts for critical events (would integrate with notification system)
    IF p_severity = 'critical' THEN
        UPDATE security_events SET alert_sent = TRUE WHERE id = v_event_id;
    END IF;
    
    RETURN v_event_id;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Create scheduled cleanup job (note: requires pg_cron extension or external scheduler)
-- ============================================================================
-- This is a placeholder for documentation. In production, you'd set up:
-- 1. pg_cron job: SELECT cron.schedule('cleanup-expired-tokens', '0 2 * * *', 'SELECT cleanup_expired_tokens();');
-- 2. Or external scheduler to call the cleanup function periodically