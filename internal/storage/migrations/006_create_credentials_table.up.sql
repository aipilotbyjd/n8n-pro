-- Create credentials table
CREATE TABLE IF NOT EXISTS credentials (
    id VARCHAR(255) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    type VARCHAR(100) NOT NULL,
    description TEXT,
    owner_id UUID NOT NULL,
    team_id UUID,
    sharing_level VARCHAR(50) NOT NULL DEFAULT 'private',
    encrypted_data TEXT NOT NULL,
    data_hash VARCHAR(255) NOT NULL,
    test_endpoint VARCHAR(500),
    last_used_at TIMESTAMPTZ,
    usage_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT true,
    expires_at TIMESTAMPTZ,
    tags JSONB DEFAULT '[]',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT valid_sharing_level CHECK (sharing_level IN ('private', 'team', 'public')),
    CONSTRAINT valid_credential_type CHECK (type IN (
        'api_key', 'oauth2', 'basic_auth', 'database', 'smtp', 'ssh', 
        'aws', 'gcp', 'azure', 'custom'
    ))
);

-- Create indexes for credentials table
CREATE INDEX IF NOT EXISTS idx_credentials_owner_id ON credentials(owner_id);
CREATE INDEX IF NOT EXISTS idx_credentials_team_id ON credentials(team_id);
CREATE INDEX IF NOT EXISTS idx_credentials_type ON credentials(type);
CREATE INDEX IF NOT EXISTS idx_credentials_active ON credentials(is_active);
CREATE INDEX IF NOT EXISTS idx_credentials_sharing ON credentials(sharing_level);
CREATE INDEX IF NOT EXISTS idx_credentials_tags ON credentials USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_credentials_expires_at ON credentials(expires_at);
CREATE INDEX IF NOT EXISTS idx_credentials_created_at ON credentials(created_at);