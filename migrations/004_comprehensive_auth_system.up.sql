-- Create enhanced organizations table
CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(255) NOT NULL UNIQUE,
    domain VARCHAR(255),
    logo_url TEXT,
    plan VARCHAR(50) NOT NULL DEFAULT 'free' CHECK (plan IN ('free', 'starter', 'pro', 'enterprise')),
    plan_limits JSONB NOT NULL DEFAULT '{}',
    settings JSONB NOT NULL DEFAULT '{}',
    status VARCHAR(50) NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'canceled', 'trial')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE NULL,
    
    -- Indexes
    CONSTRAINT organizations_slug_not_empty CHECK (slug != ''),
    CONSTRAINT organizations_name_not_empty CHECK (name != '')
);

-- Create indexes for organizations
CREATE INDEX IF NOT EXISTS idx_organizations_slug ON organizations(slug) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_organizations_domain ON organizations(domain) WHERE domain IS NOT NULL AND deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_organizations_status ON organizations(status);
CREATE INDEX IF NOT EXISTS idx_organizations_plan ON organizations(plan);
CREATE INDEX IF NOT EXISTS idx_organizations_created_at ON organizations(created_at);

-- Create enhanced teams table
CREATE TABLE IF NOT EXISTS teams (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE NULL,
    
    -- Constraints
    CONSTRAINT teams_name_not_empty CHECK (name != ''),
    CONSTRAINT teams_unique_name_per_org UNIQUE (organization_id, name, deleted_at)
);

-- Create indexes for teams
CREATE INDEX IF NOT EXISTS idx_teams_organization_id ON teams(organization_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_teams_name ON teams(name) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_teams_created_at ON teams(created_at);

-- Drop existing users table if it exists (we'll recreate it with enhanced schema)
DROP TABLE IF EXISTS users CASCADE;

-- Create enhanced users table
CREATE TABLE IF NOT EXISTS users (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    first_name VARCHAR(255) NOT NULL,
    last_name VARCHAR(255) NOT NULL,
    full_name VARCHAR(255) GENERATED ALWAYS AS (first_name || ' ' || last_name) STORED,
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'suspended', 'inactive', 'deleted')),
    role VARCHAR(50) NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member', 'viewer', 'guest', 'api_only')),
    profile JSONB NOT NULL DEFAULT '{}',
    settings JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE NULL,
    
    -- Security fields
    email_verified BOOLEAN NOT NULL DEFAULT FALSE,
    email_verification_token VARCHAR(255),
    email_verification_expires_at TIMESTAMP WITH TIME ZONE,
    password_reset_token VARCHAR(255),
    password_reset_expires_at TIMESTAMP WITH TIME ZONE,
    mfa_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    mfa_secret VARCHAR(255),
    mfa_backup_codes JSONB DEFAULT '[]',
    api_key VARCHAR(255),
    api_key_created_at TIMESTAMP WITH TIME ZONE,
    
    -- Activity tracking
    last_login_at TIMESTAMP WITH TIME ZONE,
    last_login_ip VARCHAR(45), -- IPv6 max length
    login_count INTEGER NOT NULL DEFAULT 0,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMP WITH TIME ZONE,
    password_changed_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT users_email_not_empty CHECK (email != ''),
    CONSTRAINT users_first_name_not_empty CHECK (first_name != ''),
    CONSTRAINT users_last_name_not_empty CHECK (last_name != ''),
    CONSTRAINT users_unique_email_per_org UNIQUE (organization_id, email, deleted_at),
    CONSTRAINT users_api_key_unique UNIQUE (api_key) DEFERRABLE INITIALLY DEFERRED
);

-- Create indexes for users
CREATE INDEX IF NOT EXISTS idx_users_organization_id ON users(organization_id) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email) WHERE deleted_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_users_status ON users(status);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_email_verified ON users(email_verified);
CREATE INDEX IF NOT EXISTS idx_users_mfa_enabled ON users(mfa_enabled);
CREATE INDEX IF NOT EXISTS idx_users_last_login_at ON users(last_login_at);
CREATE INDEX IF NOT EXISTS idx_users_created_at ON users(created_at);
CREATE INDEX IF NOT EXISTS idx_users_email_verification_token ON users(email_verification_token) WHERE email_verification_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_password_reset_token ON users(password_reset_token) WHERE password_reset_token IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_users_api_key ON users(api_key) WHERE api_key IS NOT NULL;

-- Create team memberships table
CREATE TABLE IF NOT EXISTS team_memberships (
    id VARCHAR(255) PRIMARY KEY,
    team_id VARCHAR(255) NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role VARCHAR(50) NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member', 'viewer', 'guest')),
    joined_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT team_memberships_unique UNIQUE (team_id, user_id)
);

-- Create indexes for team memberships
CREATE INDEX IF NOT EXISTS idx_team_memberships_team_id ON team_memberships(team_id);
CREATE INDEX IF NOT EXISTS idx_team_memberships_user_id ON team_memberships(user_id);
CREATE INDEX IF NOT EXISTS idx_team_memberships_role ON team_memberships(role);
CREATE INDEX IF NOT EXISTS idx_team_memberships_joined_at ON team_memberships(joined_at);

-- Create invitations table
CREATE TABLE IF NOT EXISTS invitations (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    team_id VARCHAR(255) REFERENCES teams(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'member' CHECK (role IN ('admin', 'member', 'viewer', 'guest')),
    invited_by VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token VARCHAR(255) NOT NULL UNIQUE,
    status VARCHAR(50) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'declined', 'expired', 'revoked')),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    accepted_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT invitations_email_not_empty CHECK (email != ''),
    CONSTRAINT invitations_token_not_empty CHECK (token != ''),
    CONSTRAINT invitations_unique_pending_email_org UNIQUE (organization_id, email, status) DEFERRABLE INITIALLY DEFERRED
);

-- Create indexes for invitations
CREATE INDEX IF NOT EXISTS idx_invitations_organization_id ON invitations(organization_id);
CREATE INDEX IF NOT EXISTS idx_invitations_team_id ON invitations(team_id) WHERE team_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_invitations_email ON invitations(email);
CREATE INDEX IF NOT EXISTS idx_invitations_invited_by ON invitations(invited_by);
CREATE INDEX IF NOT EXISTS idx_invitations_token ON invitations(token);
CREATE INDEX IF NOT EXISTS idx_invitations_status ON invitations(status);
CREATE INDEX IF NOT EXISTS idx_invitations_expires_at ON invitations(expires_at);
CREATE INDEX IF NOT EXISTS idx_invitations_created_at ON invitations(created_at);

-- Create API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    key_hash VARCHAR(255) NOT NULL UNIQUE,
    permissions JSONB NOT NULL DEFAULT '[]',
    last_used_at TIMESTAMP WITH TIME ZONE,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT api_keys_name_not_empty CHECK (name != ''),
    CONSTRAINT api_keys_key_hash_not_empty CHECK (key_hash != ''),
    CONSTRAINT api_keys_unique_name_per_user UNIQUE (user_id, name) DEFERRABLE INITIALLY DEFERRED
);

-- Create indexes for API keys
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_key_hash ON api_keys(key_hash) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_api_keys_last_used_at ON api_keys(last_used_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_expires_at ON api_keys(expires_at);
CREATE INDEX IF NOT EXISTS idx_api_keys_created_at ON api_keys(created_at);

-- Create audit logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(255) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(255) REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(255) NOT NULL,
    resource VARCHAR(255) NOT NULL,
    resource_id VARCHAR(255),
    details JSONB NOT NULL DEFAULT '{}',
    ip_address VARCHAR(45) NOT NULL, -- IPv6 max length
    user_agent TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT audit_logs_action_not_empty CHECK (action != ''),
    CONSTRAINT audit_logs_resource_not_empty CHECK (resource != ''),
    CONSTRAINT audit_logs_ip_address_not_empty CHECK (ip_address != ''),
    CONSTRAINT audit_logs_user_agent_not_empty CHECK (user_agent != '')
);

-- Create indexes for audit logs
CREATE INDEX IF NOT EXISTS idx_audit_logs_organization_id ON audit_logs(organization_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON audit_logs(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource ON audit_logs(resource);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_id ON audit_logs(resource_id) WHERE resource_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_audit_logs_ip_address ON audit_logs(ip_address);

-- Create sessions table
CREATE TABLE IF NOT EXISTS sessions (
    id VARCHAR(255) PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    refresh_token_hash VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45) NOT NULL, -- IPv6 max length
    user_agent TEXT NOT NULL,
    location VARCHAR(255),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMP WITH TIME ZONE,
    
    -- Constraints
    CONSTRAINT sessions_refresh_token_hash_not_empty CHECK (refresh_token_hash != ''),
    CONSTRAINT sessions_ip_address_not_empty CHECK (ip_address != ''),
    CONSTRAINT sessions_user_agent_not_empty CHECK (user_agent != '')
);

-- Create indexes for sessions
CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_refresh_token_hash ON sessions(refresh_token_hash) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_is_active ON sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_created_at ON sessions(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen_at ON sessions(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_sessions_ip_address ON sessions(ip_address);

-- Insert default data for development

-- Insert default organization
INSERT INTO organizations (
    id, name, slug, plan, plan_limits, settings, status
) VALUES (
    'org_default_development',
    'Default Organization',
    'default-org',
    'pro',
    '{"max_users": 100, "max_workflows": 500, "max_executions_per_month": 1000000, "max_execution_time_seconds": 1800, "api_calls_per_minute": 1000, "data_retention_days": 90, "custom_connections": true, "sso_enabled": true, "audit_logs_enabled": true, "priority_support": true, "advanced_security": true, "white_labeling": false}',
    '{"default_timezone": "UTC", "allow_registration": true, "require_email_verification": true, "enforce_password_policy": true, "password_policy": {"min_length": 8, "require_upper": true, "require_lower": true, "require_digit": true, "require_symbol": false, "max_age_days": 90, "prevent_reuse_count": 5}, "session_timeout_minutes": 480, "enable_mfa": false, "webhook_settings": {"max_retries": 3, "retry_delay_seconds": 5, "timeout_seconds": 30, "allowed_hosts": [], "blocked_hosts": [], "enable_rate_limit": true, "rate_limit_per_hour": 1000}, "security_settings": {"ip_whitelist": [], "ip_blacklist": [], "max_login_attempts": 5, "account_lockout_minutes": 30, "enable_audit_log": true, "data_encryption_enabled": true, "api_key_rotation_days": 90}, "notification_settings": {"email_workflow_success": true, "email_workflow_failure": true, "email_security_alerts": true, "slack_notifications": false}, "data_region": "us-east-1", "compliance_mode": "standard"}',
    'active'
) ON CONFLICT (id) DO NOTHING;

-- Insert default team
INSERT INTO teams (
    id, organization_id, name, description, settings
) VALUES (
    'team_default_development',
    'org_default_development',
    'Default Team',
    'Default team for development and testing',
    '{"default_role": "member", "allow_member_invite": true, "require_approval": false, "workflow_sharing": "team", "credential_sharing": "team"}'
) ON CONFLICT (id) DO NOTHING;

-- Insert default admin user (password: admin123!)
INSERT INTO users (
    id, organization_id, email, first_name, last_name, password_hash, 
    status, role, email_verified, profile, settings
) VALUES (
    'user_admin_development',
    'org_default_development',
    'admin@n8n-pro.local',
    'Admin',
    'User',
    '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewdnKm5vQJ5o8/EW', -- admin123!
    'active',
    'owner',
    TRUE,
    '{"avatar_url": null, "bio": "Default admin user for n8n Pro", "location": null, "website": null, "phone_number": null, "job_title": "System Administrator", "department": "IT"}',
    '{"timezone": "UTC", "language": "en", "theme": "light", "notification_settings": {"email_workflow_success": false, "email_workflow_failure": true, "email_security_alerts": true, "desktop_notifications": true}, "workflow_defaults": {}, "keyboard_shortcuts": {}, "privacy_settings": {"show_profile": true, "show_activity": false}}'
) ON CONFLICT (id) DO NOTHING;

-- Insert team membership for admin user
INSERT INTO team_memberships (
    id, team_id, user_id, role
) VALUES (
    'membership_admin_development',
    'team_default_development',
    'user_admin_development',
    'owner'
) ON CONFLICT (team_id, user_id) DO NOTHING;

-- Create triggers for updating updated_at timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Apply updated_at triggers to all tables that have updated_at column
DO $$ 
BEGIN
    -- Drop existing triggers if they exist
    DROP TRIGGER IF EXISTS update_organizations_updated_at ON organizations;
    DROP TRIGGER IF EXISTS update_teams_updated_at ON teams;
    DROP TRIGGER IF EXISTS update_users_updated_at ON users;
    
    -- Create new triggers
    CREATE TRIGGER update_organizations_updated_at 
        BEFORE UPDATE ON organizations 
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        
    CREATE TRIGGER update_teams_updated_at 
        BEFORE UPDATE ON teams 
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
        
    CREATE TRIGGER update_users_updated_at 
        BEFORE UPDATE ON users 
        FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
END $$;

-- Create function to clean up expired tokens and sessions
CREATE OR REPLACE FUNCTION cleanup_expired_auth_data()
RETURNS void AS $$
BEGIN
    -- Clean up expired email verification tokens
    UPDATE users SET 
        email_verification_token = NULL,
        email_verification_expires_at = NULL
    WHERE email_verification_expires_at < NOW();
    
    -- Clean up expired password reset tokens
    UPDATE users SET 
        password_reset_token = NULL,
        password_reset_expires_at = NULL
    WHERE password_reset_expires_at < NOW();
    
    -- Mark expired invitations
    UPDATE invitations SET 
        status = 'expired'
    WHERE status = 'pending' AND expires_at < NOW();
    
    -- Revoke expired sessions
    UPDATE sessions SET 
        is_active = FALSE,
        revoked_at = NOW()
    WHERE is_active = TRUE AND expires_at < NOW();
END;
$$ LANGUAGE plpgsql;

-- Create function to calculate organization usage stats
CREATE OR REPLACE FUNCTION get_organization_stats(org_id VARCHAR(255))
RETURNS TABLE (
    user_count INTEGER,
    team_count INTEGER,
    active_user_count INTEGER,
    this_month_logins INTEGER
) AS $$
BEGIN
    RETURN QUERY
    SELECT 
        (SELECT COUNT(*)::INTEGER FROM users WHERE organization_id = org_id AND deleted_at IS NULL),
        (SELECT COUNT(*)::INTEGER FROM teams WHERE organization_id = org_id AND deleted_at IS NULL),
        (SELECT COUNT(*)::INTEGER FROM users WHERE organization_id = org_id AND status = 'active' AND deleted_at IS NULL),
        (SELECT COUNT(*)::INTEGER FROM users WHERE organization_id = org_id AND last_login_at >= DATE_TRUNC('month', NOW()) AND deleted_at IS NULL);
END;
$$ LANGUAGE plpgsql;

-- Create function to validate password policy
CREATE OR REPLACE FUNCTION validate_password_policy(
    password_text TEXT,
    policy_json JSONB
) RETURNS BOOLEAN AS $$
DECLARE
    min_length INTEGER;
    require_upper BOOLEAN;
    require_lower BOOLEAN;
    require_digit BOOLEAN;
    require_symbol BOOLEAN;
BEGIN
    -- Extract policy requirements
    min_length := COALESCE((policy_json->>'min_length')::INTEGER, 8);
    require_upper := COALESCE((policy_json->>'require_upper')::BOOLEAN, false);
    require_lower := COALESCE((policy_json->>'require_lower')::BOOLEAN, false);
    require_digit := COALESCE((policy_json->>'require_digit')::BOOLEAN, false);
    require_symbol := COALESCE((policy_json->>'require_symbol')::BOOLEAN, false);
    
    -- Check minimum length
    IF LENGTH(password_text) < min_length THEN
        RETURN FALSE;
    END IF;
    
    -- Check uppercase requirement
    IF require_upper AND password_text !~ '[A-Z]' THEN
        RETURN FALSE;
    END IF;
    
    -- Check lowercase requirement
    IF require_lower AND password_text !~ '[a-z]' THEN
        RETURN FALSE;
    END IF;
    
    -- Check digit requirement
    IF require_digit AND password_text !~ '[0-9]' THEN
        RETURN FALSE;
    END IF;
    
    -- Check symbol requirement
    IF require_symbol AND password_text !~ '[^a-zA-Z0-9]' THEN
        RETURN FALSE;
    END IF;
    
    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

-- Grant necessary permissions (adjust based on your database user)
-- GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO your_app_user;
-- GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO your_app_user;
-- GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO your_app_user;