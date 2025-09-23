-- Drop triggers
DROP TRIGGER IF EXISTS update_workflow_tags_updated_at ON workflow_tags;
DROP TRIGGER IF EXISTS update_workflow_shares_updated_at ON workflow_shares;
DROP TRIGGER IF EXISTS update_workflow_templates_updated_at ON workflow_templates;

-- Drop tables in reverse order
DROP TABLE IF EXISTS workflow_tag_associations;
DROP TABLE IF EXISTS workflow_tags;
DROP TABLE IF EXISTS workflow_shares;
DROP TABLE IF EXISTS workflow_templates;
DROP TABLE IF EXISTS workflow_versions;