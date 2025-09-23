-- Create workflow_versions table for version history
CREATE TABLE IF NOT EXISTS workflow_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL,
    version_number INTEGER NOT NULL,
    
    -- Workflow data at this version
    name VARCHAR(255) NOT NULL,
    description TEXT,
    nodes JSONB NOT NULL,
    connections JSONB NOT NULL,
    variables JSONB DEFAULT '[]',
    settings JSONB DEFAULT '{}',
    
    -- Version metadata
    change_summary TEXT,
    changelog TEXT,
    is_major_version BOOLEAN DEFAULT false,
    
    -- Status tracking
    status VARCHAR(50) DEFAULT 'draft',
    published_at TIMESTAMPTZ,
    
    -- Audit fields
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    CONSTRAINT valid_version_status CHECK (status IN ('draft', 'published', 'archived')),
    UNIQUE(workflow_id, version_number)
);

-- Create workflow_templates table for reusable templates
CREATE TABLE IF NOT EXISTS workflow_templates (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    category VARCHAR(100),
    subcategory VARCHAR(100),
    
    -- Template data
    nodes JSONB NOT NULL,
    connections JSONB NOT NULL,
    variables JSONB DEFAULT '[]',
    settings JSONB DEFAULT '{}',
    
    -- Template metadata
    icon VARCHAR(100),
    color VARCHAR(50),
    tags JSONB DEFAULT '[]',
    use_cases TEXT[],
    difficulty_level VARCHAR(20) DEFAULT 'beginner', -- beginner, intermediate, advanced
    estimated_time INTEGER, -- minutes
    
    -- Requirements
    required_integrations TEXT[],
    required_credentials TEXT[],
    
    -- Statistics
    use_count INTEGER DEFAULT 0,
    rating_average DECIMAL(3,2) DEFAULT 0.0,
    rating_count INTEGER DEFAULT 0,
    
    -- Publication info
    is_public BOOLEAN DEFAULT false,
    is_featured BOOLEAN DEFAULT false,
    published_by UUID,
    published_at TIMESTAMPTZ,
    
    -- Source information
    source_workflow_id UUID,
    source_version INTEGER,
    
    -- Audit fields
    created_by UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    deleted_at TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT valid_difficulty CHECK (difficulty_level IN ('beginner', 'intermediate', 'advanced'))
);

-- Create workflow_shares table for sharing workflows
CREATE TABLE IF NOT EXISTS workflow_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workflow_id UUID NOT NULL,
    shared_by UUID NOT NULL,
    shared_with UUID, -- User ID, NULL for public shares
    share_type VARCHAR(50) NOT NULL DEFAULT 'view', -- view, edit, admin
    
    -- Share configuration
    expires_at TIMESTAMPTZ,
    is_public BOOLEAN DEFAULT false,
    share_token VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255), -- Optional password protection
    
    -- Access tracking
    access_count INTEGER DEFAULT 0,
    last_accessed_at TIMESTAMPTZ,
    
    -- Audit fields
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ,
    
    -- Constraints
    CONSTRAINT valid_share_type CHECK (share_type IN ('view', 'edit', 'admin'))
);

-- Create workflow_tags table for tagging workflows
CREATE TABLE IF NOT EXISTS workflow_tags (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(100) NOT NULL,
    color VARCHAR(50) DEFAULT '#6B7280',
    description TEXT,
    team_id UUID, -- NULL for global tags
    
    -- Usage statistics
    usage_count INTEGER DEFAULT 0,
    
    -- Audit fields
    created_by UUID,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    -- Constraints
    UNIQUE(name, team_id)
);

-- Create workflow_tag_associations table for many-to-many relationship
CREATE TABLE IF NOT EXISTS workflow_tag_associations (
    workflow_id UUID NOT NULL,
    tag_id UUID NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    
    PRIMARY KEY (workflow_id, tag_id),
    FOREIGN KEY (tag_id) REFERENCES workflow_tags(id) ON DELETE CASCADE
);

-- Create indexes for workflow_versions
CREATE INDEX IF NOT EXISTS idx_workflow_versions_workflow_id ON workflow_versions(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_versions_version_number ON workflow_versions(version_number);
CREATE INDEX IF NOT EXISTS idx_workflow_versions_status ON workflow_versions(status);
CREATE INDEX IF NOT EXISTS idx_workflow_versions_created_by ON workflow_versions(created_by);
CREATE INDEX IF NOT EXISTS idx_workflow_versions_created_at ON workflow_versions(created_at);

-- Create indexes for workflow_templates
CREATE INDEX IF NOT EXISTS idx_workflow_templates_category ON workflow_templates(category);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_subcategory ON workflow_templates(subcategory);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_is_public ON workflow_templates(is_public);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_is_featured ON workflow_templates(is_featured);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_difficulty ON workflow_templates(difficulty_level);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_created_by ON workflow_templates(created_by);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_tags ON workflow_templates USING GIN(tags);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_deleted_at ON workflow_templates(deleted_at);
CREATE INDEX IF NOT EXISTS idx_workflow_templates_use_count ON workflow_templates(use_count);

-- Create indexes for workflow_shares
CREATE INDEX IF NOT EXISTS idx_workflow_shares_workflow_id ON workflow_shares(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_shares_shared_with ON workflow_shares(shared_with);
CREATE INDEX IF NOT EXISTS idx_workflow_shares_share_token ON workflow_shares(share_token);
CREATE INDEX IF NOT EXISTS idx_workflow_shares_expires_at ON workflow_shares(expires_at);
CREATE INDEX IF NOT EXISTS idx_workflow_shares_is_public ON workflow_shares(is_public);
CREATE INDEX IF NOT EXISTS idx_workflow_shares_revoked_at ON workflow_shares(revoked_at);

-- Create indexes for workflow_tags
CREATE INDEX IF NOT EXISTS idx_workflow_tags_name ON workflow_tags(name);
CREATE INDEX IF NOT EXISTS idx_workflow_tags_team_id ON workflow_tags(team_id);
CREATE INDEX IF NOT EXISTS idx_workflow_tags_usage_count ON workflow_tags(usage_count);

-- Create indexes for workflow_tag_associations
CREATE INDEX IF NOT EXISTS idx_workflow_tag_assoc_workflow_id ON workflow_tag_associations(workflow_id);
CREATE INDEX IF NOT EXISTS idx_workflow_tag_assoc_tag_id ON workflow_tag_associations(tag_id);

-- Add triggers for automatic updated_at updates
CREATE TRIGGER update_workflow_templates_updated_at BEFORE UPDATE ON workflow_templates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_workflow_shares_updated_at BEFORE UPDATE ON workflow_shares
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_workflow_tags_updated_at BEFORE UPDATE ON workflow_tags
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();