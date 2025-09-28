-- This migration finalizes the schema, no down migration needed
-- Individual components should be rolled back using their specific migrations
SELECT 'Schema finalization cannot be rolled back - use specific component migrations' as message;