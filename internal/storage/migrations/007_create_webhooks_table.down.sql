-- Drop triggers
DROP TRIGGER IF EXISTS update_webhooks_updated_at ON webhooks;

-- Drop tables in reverse order
DROP TABLE IF EXISTS webhook_executions;
DROP TABLE IF EXISTS webhooks;