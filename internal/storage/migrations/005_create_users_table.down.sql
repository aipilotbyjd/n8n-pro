-- Drop triggers
DROP TRIGGER IF EXISTS update_team_members_updated_at ON team_members;
DROP TRIGGER IF EXISTS update_teams_updated_at ON teams;
DROP TRIGGER IF EXISTS update_users_updated_at ON users;

-- Drop function
DROP FUNCTION IF EXISTS update_updated_at_column();

-- Drop foreign key constraints
ALTER TABLE users DROP CONSTRAINT IF EXISTS fk_users_team_id;

-- Drop tables in reverse order
DROP TABLE IF EXISTS team_members;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS users;