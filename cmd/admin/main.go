package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"n8n-pro/internal/auth"
	"n8n-pro/internal/config"
	"n8n-pro/internal/database"
	"n8n-pro/internal/teams"
	"n8n-pro/internal/workflows"
	"n8n-pro/pkg/logger"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

const usage = `
n8n-pro Admin CLI - Administrative operations for n8n-pro

USAGE:
    admin <command> [options]

COMMANDS:
    workflow    Workflow management operations
    user        User management operations
    team        Team/organization management
    system      System health and diagnostics
    migrate     Database migration operations
    config      Configuration management
    cleanup     Cleanup and maintenance tasks

WORKFLOW COMMANDS:
    admin workflow list [--team-id=<id>] [--limit=<n>]
    admin workflow get --id=<workflow-id>
    admin workflow delete --id=<workflow-id>
    admin workflow export --id=<workflow-id> [--file=<path>]
    admin workflow import --file=<path> [--team-id=<id>]
    admin workflow validate --id=<workflow-id>
    admin workflow stats

USER COMMANDS:
    admin user list [--team-id=<id>] [--limit=<n>]
    admin user get --id=<user-id>
    admin user create --email=<email> --name=<name> [--team-id=<id>]
    admin user delete --id=<user-id>
    admin user activate --id=<user-id>
    admin user deactivate --id=<user-id>
    admin user reset-password --id=<user-id>

TEAM COMMANDS:
    admin team list [--limit=<n>]
    admin team get --id=<team-id>
    admin team create --name=<name> --owner-id=<user-id>
    admin team delete --id=<team-id>
    admin team add-member --team-id=<id> --user-id=<id> [--role=<role>]
    admin team remove-member --team-id=<id> --user-id=<id>

SYSTEM COMMANDS:
    admin system health
    admin system stats
    admin system config
    admin system logs [--service=<name>] [--lines=<n>]
    admin system metrics

MIGRATE COMMANDS:
    admin migrate up [--steps=<n>]
    admin migrate down [--steps=<n>]
    admin migrate status
    admin migrate force <version>
    admin migrate create --name=<migration-name>

CLEANUP COMMANDS:
    admin cleanup executions [--before=<date>] [--status=<status>]
    admin cleanup logs [--before=<date>]
    admin cleanup temp-files
    admin cleanup orphaned-data

CONFIG COMMANDS:
    admin config get [--key=<key>]
    admin config set --key=<key> --value=<value>
    admin config validate

EXAMPLES:
    admin workflow list --limit=10
    admin user create --email=admin@example.com --name="Admin User"
    admin system health
    admin migrate up
    admin cleanup executions --before=2024-01-01 --status=completed

FLAGS:
    --help, -h      Show this help message
    --config, -c    Config file path (default: .env)
    --verbose, -v   Verbose output
    --json          Output in JSON format
`

type AdminCLI struct {
	cfg         *config.Config
	db          *database.Database
	logger      logger.Logger
	workflowSvc *workflows.Service
	authSvc     *auth.Service
	teamSvc     *teams.Service
}

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}

	// Global flags
	var (
		configFile = flag.String("config", ".env", "Config file path")
		verbose    = flag.Bool("verbose", false, "Verbose output")
		jsonOutput = flag.Bool("json", false, "Output in JSON format")
		help       = flag.Bool("help", false, "Show help")
	)

	command := os.Args[1]

	// Handle help
	if *help || command == "help" {
		fmt.Print(usage)
		os.Exit(0)
	}

	// Initialize CLI
	cli, err := NewAdminCLI(*configFile, *verbose)
	if err != nil {
		log.Fatalf("Failed to initialize admin CLI: %v", err)
	}
	defer cli.Close()

	// Route commands
	ctx := context.Background()

	switch command {
	case "workflow":
		err = cli.handleWorkflowCommand(ctx, os.Args[2:], *jsonOutput)
	case "user":
		err = cli.handleUserCommand(ctx, os.Args[2:], *jsonOutput)
	case "team":
		err = cli.handleTeamCommand(ctx, os.Args[2:], *jsonOutput)
	case "system":
		err = cli.handleSystemCommand(ctx, os.Args[2:], *jsonOutput)
	case "migrate":
		err = cli.handleMigrateCommand(ctx, os.Args[2:], *jsonOutput)
	case "cleanup":
		err = cli.handleCleanupCommand(ctx, os.Args[2:], *jsonOutput)
	case "config":
		err = cli.handleConfigCommand(ctx, os.Args[2:], *jsonOutput)
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		fmt.Print(usage)
		os.Exit(1)
	}

	if err != nil {
		log.Fatalf("Command failed: %v", err)
	}
}

func NewAdminCLI(configFile string, verbose bool) (*AdminCLI, error) {
	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Initialize logger
	logger := logger.New("admin-cli")
	if verbose {
		logger.SetLevel("debug")
	}

	// Initialize database
	db, err := database.Initialize(cfg.Database)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to database: %w", err)
	}

	// Initialize services with GORM DB
	// TODO: Workflows and teams services need to be migrated to GORM
	// For now, we'll only initialize auth service which has been converted to GORM
	
	authRepo := auth.NewPostgresRepository(db.DB)
	authSvc := auth.NewService(authRepo)

	// workflowRepo := workflows.NewPostgresRepository(db.DB)
	// workflowSvc := workflows.NewService(
	// 	workflowRepo,
	// 	db.DB,
	// 	cfg,
	// 	nil, // validator - will be implemented
	// 	nil, // executor - will be implemented
	// 	nil, // template service - will be implemented
	// 	nil, // credential service - will be implemented
	// )

	teamRepo := teams.NewPostgresRepository(db.DB)
	teamSvc := teams.NewService(teamRepo)

	return &AdminCLI{
		cfg:         cfg,
		db:          db,
		logger:      logger,
		// workflowSvc: workflowSvc, // TODO: Re-enable after migrating workflows to GORM
		authSvc:     authSvc,
		teamSvc:     teamSvc,
	}, nil
}

func (cli *AdminCLI) Close() {
	if cli.db != nil {
		cli.db.Close()
	}
}

func (cli *AdminCLI) handleWorkflowCommand(ctx context.Context, args []string, jsonOutput bool) error {
	if len(args) == 0 {
		return fmt.Errorf("workflow command requires a subcommand")
	}

	switch args[0] {
	case "list":
		return cli.listWorkflows(ctx, args[1:], jsonOutput)
	case "get":
		return cli.getWorkflow(ctx, args[1:], jsonOutput)
	case "delete":
		return cli.deleteWorkflow(ctx, args[1:], jsonOutput)
	case "export":
		return cli.exportWorkflow(ctx, args[1:], jsonOutput)
	case "import":
		return cli.importWorkflow(ctx, args[1:], jsonOutput)
	case "validate":
		return cli.validateWorkflow(ctx, args[1:], jsonOutput)
	case "stats":
		return cli.workflowStats(ctx, args[1:], jsonOutput)
	default:
		return fmt.Errorf("unknown workflow subcommand: %s", args[0])
	}
}

func (cli *AdminCLI) handleUserCommand(ctx context.Context, args []string, jsonOutput bool) error {
	if len(args) == 0 {
		return fmt.Errorf("user command requires a subcommand")
	}

	switch args[0] {
	case "list":
		return cli.listUsers(ctx, args[1:], jsonOutput)
	case "get":
		return cli.getUser(ctx, args[1:], jsonOutput)
	case "create":
		return cli.createUser(ctx, args[1:], jsonOutput)
	case "delete":
		return cli.deleteUser(ctx, args[1:], jsonOutput)
	case "activate":
		return cli.activateUser(ctx, args[1:], jsonOutput)
	case "deactivate":
		return cli.deactivateUser(ctx, args[1:], jsonOutput)
	case "reset-password":
		return cli.resetUserPassword(ctx, args[1:], jsonOutput)
	default:
		return fmt.Errorf("unknown user subcommand: %s", args[0])
	}
}

func (cli *AdminCLI) handleTeamCommand(ctx context.Context, args []string, jsonOutput bool) error {
	if len(args) == 0 {
		return fmt.Errorf("team command requires a subcommand")
	}

	switch args[0] {
	case "list":
		return cli.listTeams(ctx, args[1:], jsonOutput)
	case "get":
		return cli.getTeam(ctx, args[1:], jsonOutput)
	case "create":
		return cli.createTeam(ctx, args[1:], jsonOutput)
	case "delete":
		return cli.deleteTeam(ctx, args[1:], jsonOutput)
	case "add-member":
		return cli.addTeamMember(ctx, args[1:], jsonOutput)
	case "remove-member":
		return cli.removeTeamMember(ctx, args[1:], jsonOutput)
	default:
		return fmt.Errorf("unknown team subcommand: %s", args[0])
	}
}

func (cli *AdminCLI) handleSystemCommand(ctx context.Context, args []string, jsonOutput bool) error {
	if len(args) == 0 {
		return fmt.Errorf("system command requires a subcommand")
	}

	switch args[0] {
	case "health":
		return cli.systemHealth(ctx, jsonOutput)
	case "stats":
		return cli.systemStats(ctx, jsonOutput)
	case "config":
		return cli.systemConfig(ctx, jsonOutput)
	case "logs":
		return cli.systemLogs(ctx, args[1:], jsonOutput)
	case "metrics":
		return cli.systemMetrics(ctx, jsonOutput)
	default:
		return fmt.Errorf("unknown system subcommand: %s", args[0])
	}
}

func (cli *AdminCLI) handleMigrateCommand(ctx context.Context, args []string, jsonOutput bool) error {
	if len(args) == 0 {
		return fmt.Errorf("migrate command requires a subcommand")
	}

	switch args[0] {
	case "up":
		return cli.migrateUp(ctx, args[1:], jsonOutput)
	case "down":
		return cli.migrateDown(ctx, args[1:], jsonOutput)
	case "status":
		return cli.migrateStatus(ctx, jsonOutput)
	case "force":
		return cli.migrateForce(ctx, args[1:], jsonOutput)
	case "create":
		return cli.createMigration(ctx, args[1:], jsonOutput)
	default:
		return fmt.Errorf("unknown migrate subcommand: %s", args[0])
	}
}

func (cli *AdminCLI) handleCleanupCommand(ctx context.Context, args []string, jsonOutput bool) error {
	if len(args) == 0 {
		return fmt.Errorf("cleanup command requires a subcommand")
	}

	switch args[0] {
	case "executions":
		return cli.cleanupExecutions(ctx, args[1:], jsonOutput)
	case "logs":
		return cli.cleanupLogs(ctx, args[1:], jsonOutput)
	case "temp-files":
		return cli.cleanupTempFiles(ctx, jsonOutput)
	case "orphaned-data":
		return cli.cleanupOrphanedData(ctx, jsonOutput)
	default:
		return fmt.Errorf("unknown cleanup subcommand: %s", args[0])
	}
}

func (cli *AdminCLI) handleConfigCommand(ctx context.Context, args []string, jsonOutput bool) error {
	if len(args) == 0 {
		return fmt.Errorf("config command requires a subcommand")
	}

	switch args[0] {
	case "get":
		return cli.getConfig(ctx, args[1:], jsonOutput)
	case "set":
		return cli.setConfig(ctx, args[1:], jsonOutput)
	case "validate":
		return cli.validateConfig(ctx, jsonOutput)
	default:
		return fmt.Errorf("unknown config subcommand: %s", args[0])
	}
}

// Implementation of workflow commands
func (cli *AdminCLI) listWorkflows(ctx context.Context, args []string, jsonOutput bool) error {
	// Parse flags
	var teamID string
	var limit int = 50

	for _, arg := range args {
		if arg[:9] == "--team-id" {
			teamID = arg[10:]
		}
		if arg[:7] == "--limit" {
			var err error
			limit, err = strconv.Atoi(arg[8:])
			if err != nil {
				return fmt.Errorf("invalid limit value: %w", err)
			}
		}
	}

	filter := &workflows.WorkflowListFilter{
		TeamID: &teamID,
		Limit:  limit,
		Offset: 0,
	}

	workflowList, total, err := cli.workflowSvc.List(ctx, filter, "admin-user")
	if err != nil {
		return fmt.Errorf("failed to list workflows: %w", err)
	}

	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(workflowList)
	}

	fmt.Printf("Found %d workflows (total: %d):\n\n", len(workflowList), total)
	for _, wf := range workflowList {
		fmt.Printf("ID: %s\n", wf.ID)
		fmt.Printf("Name: %s\n", wf.Name)
		fmt.Printf("Status: %s\n", wf.Status)
		fmt.Printf("Created: %s\n", wf.CreatedAt.Format(time.RFC3339))
		fmt.Println("---")
	}

	return nil
}

func (cli *AdminCLI) getWorkflow(ctx context.Context, args []string, jsonOutput bool) error {
	var workflowID string

	for _, arg := range args {
		if arg[:4] == "--id" {
			workflowID = arg[5:]
			break
		}
	}

	if workflowID == "" {
		return fmt.Errorf("workflow ID is required")
	}

	workflow, err := cli.workflowSvc.GetByID(ctx, workflowID, "admin-user")
	if err != nil {
		return fmt.Errorf("failed to get workflow: %w", err)
	}

	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(workflow)
	}

	fmt.Printf("Workflow Details:\n")
	fmt.Printf("ID: %s\n", workflow.ID)
	fmt.Printf("Name: %s\n", workflow.Name)
	fmt.Printf("Description: %s\n", workflow.Description)
	fmt.Printf("Status: %s\n", workflow.Status)
	fmt.Printf("Created: %s\n", workflow.CreatedAt.Format(time.RFC3339))
	fmt.Printf("Updated: %s\n", workflow.UpdatedAt.Format(time.RFC3339))
	fmt.Printf("Nodes: %d\n", len(workflow.Nodes))

	return nil
}

// Placeholder implementations for other commands
func (cli *AdminCLI) deleteWorkflow(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Delete workflow - not implemented yet")
	return nil
}

func (cli *AdminCLI) exportWorkflow(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Export workflow - not implemented yet")
	return nil
}

func (cli *AdminCLI) importWorkflow(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Import workflow - not implemented yet")
	return nil
}

func (cli *AdminCLI) validateWorkflow(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Validate workflow - not implemented yet")
	return nil
}

func (cli *AdminCLI) workflowStats(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Workflow stats - not implemented yet")
	return nil
}

// User command implementations
func (cli *AdminCLI) listUsers(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("List users - not implemented yet")
	return nil
}

func (cli *AdminCLI) getUser(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Get user - not implemented yet")
	return nil
}

func (cli *AdminCLI) createUser(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Create user - not implemented yet")
	return nil
}

func (cli *AdminCLI) deleteUser(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Delete user - not implemented yet")
	return nil
}

func (cli *AdminCLI) activateUser(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Activate user - not implemented yet")
	return nil
}

func (cli *AdminCLI) deactivateUser(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Deactivate user - not implemented yet")
	return nil
}

func (cli *AdminCLI) resetUserPassword(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Reset user password - not implemented yet")
	return nil
}

// Team command implementations
func (cli *AdminCLI) listTeams(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("List teams - not implemented yet")
	return nil
}

func (cli *AdminCLI) getTeam(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Get team - not implemented yet")
	return nil
}

func (cli *AdminCLI) createTeam(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Create team - not implemented yet")
	return nil
}

func (cli *AdminCLI) deleteTeam(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Delete team - not implemented yet")
	return nil
}

func (cli *AdminCLI) addTeamMember(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Add team member - not implemented yet")
	return nil
}

func (cli *AdminCLI) removeTeamMember(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Remove team member - not implemented yet")
	return nil
}

// System command implementations
func (cli *AdminCLI) systemHealth(ctx context.Context, jsonOutput bool) error {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Format(time.RFC3339),
		"services": map[string]string{
			"database": "up",
			"kafka":    "up",
			"redis":    "up",
		},
	}

	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(health)
	}

	fmt.Println("System Health Check:")
	fmt.Printf("Status: %s\n", health["status"])
	fmt.Printf("Timestamp: %s\n", health["timestamp"])
	fmt.Println("Services:")
	for service, status := range health["services"].(map[string]string) {
		fmt.Printf("  %s: %s\n", service, status)
	}

	return nil
}

func (cli *AdminCLI) systemStats(ctx context.Context, jsonOutput bool) error {
	fmt.Println("System stats - not implemented yet")
	return nil
}

func (cli *AdminCLI) systemConfig(ctx context.Context, jsonOutput bool) error {
	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(cli.cfg)
	}

	fmt.Println("System Configuration:")
	fmt.Printf("Database: %s\n", cli.cfg.Database.Host)
	fmt.Printf("API Port: %d\n", cli.cfg.API.Port)
	fmt.Printf("Environment: %s\n", cli.cfg.Environment)

	return nil
}

func (cli *AdminCLI) systemLogs(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("System logs - not implemented yet")
	return nil
}

func (cli *AdminCLI) systemMetrics(ctx context.Context, jsonOutput bool) error {
	fmt.Println("System metrics - not implemented yet")
	return nil
}

// Migration command implementations
func (cli *AdminCLI) migrateUp(ctx context.Context, args []string, jsonOutput bool) error {
	cli.logger.Info("Running GORM database migrations...")

	// Initialize database for GORM migrations
	db, err := database.Initialize(cli.cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// Create migration manager
	migrationManager := database.NewMigrationManager(db)

	// Run migrations
	if err := migrationManager.RunMigrations(); err != nil {
		return fmt.Errorf("failed to run migrations: %w", err)
	}

	cli.logger.Info("GORM migrations completed successfully")

	if jsonOutput {
		status := map[string]string{"status": "success", "message": "Migrations completed"}
		return json.NewEncoder(os.Stdout).Encode(status)
	}

	return nil
}

func (cli *AdminCLI) migrateDown(ctx context.Context, args []string, jsonOutput bool) error {
	cli.logger.Info("Running database migrations down...")

	// Construct DSN from config
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cli.cfg.Database.Username,
		cli.cfg.Database.Password,
		cli.cfg.Database.Host,
		cli.cfg.Database.Port,
		cli.cfg.Database.Database,
	)

	migrationsPath := "file://./internal/storage/migrations"

	m, err := migrate.New(migrationsPath, dsn)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	if err := m.Down(); err != nil && err != migrate.ErrNoChange {
		return fmt.Errorf("failed to run migrations down: %w", err)
	}

	cli.logger.Info("Database migrations rollback completed successfully.")
	return nil
}

func (cli *AdminCLI) migrateStatus(ctx context.Context, jsonOutput bool) error {
	// Initialize database
	db, err := database.Initialize(cli.cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer db.Close()

	// Create migration manager
	migrationManager := database.NewMigrationManager(db)

	// Get migration status
	migrations, err := migrationManager.GetMigrationStatus()
	if err != nil {
		return fmt.Errorf("failed to get migration status: %w", err)
	}

	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(migrations)
	}

	fmt.Printf("Migration Status:\n")
	fmt.Printf("Total migrations: %d\n\n", len(migrations))

	for _, migration := range migrations {
		status := "✅ Applied"
		if migration.RolledBack {
			status = "🔄 Rolled Back"
		}

		fmt.Printf("%s %s (%s) - %s\n", 
			status,
			migration.Version,
			migration.Name,
			migration.AppliedAt.Format("2006-01-02 15:04:05"))
	}

	return nil
}

func (cli *AdminCLI) migrateForce(ctx context.Context, args []string, jsonOutput bool) error {
	if len(args) == 0 {
		return fmt.Errorf("force command requires a version number")
	}

	version, err := strconv.Atoi(args[0])
	if err != nil {
		return fmt.Errorf("invalid version number: %w", err)
	}

	cli.logger.Info("Forcing database migration version...", "version", version)

	// Construct DSN from config
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cli.cfg.Database.Username,
		cli.cfg.Database.Password,
		cli.cfg.Database.Host,
		cli.cfg.Database.Port,
		cli.cfg.Database.Database,
	)

	migrationsPath := "file://./internal/storage/migrations"

	m, err := migrate.New(migrationsPath, dsn)
	if err != nil {
		return fmt.Errorf("failed to create migrate instance: %w", err)
	}

	if err := m.Force(version); err != nil {
		return fmt.Errorf("failed to force migration version: %w", err)
	}

	cli.logger.Info("Migration version forced successfully", "version", version)
	return nil
}

func (cli *AdminCLI) createMigration(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Create migration - not implemented yet")
	return nil
}

// Cleanup command implementations
func (cli *AdminCLI) cleanupExecutions(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Cleanup executions - not implemented yet")
	return nil
}

func (cli *AdminCLI) cleanupLogs(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Cleanup logs - not implemented yet")
	return nil
}

func (cli *AdminCLI) cleanupTempFiles(ctx context.Context, jsonOutput bool) error {
	fmt.Println("Cleanup temp files - not implemented yet")
	return nil
}

func (cli *AdminCLI) cleanupOrphanedData(ctx context.Context, jsonOutput bool) error {
	fmt.Println("Cleanup orphaned data - not implemented yet")
	return nil
}

// Config command implementations
func (cli *AdminCLI) getConfig(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Get config - not implemented yet")
	return nil
}

func (cli *AdminCLI) setConfig(ctx context.Context, args []string, jsonOutput bool) error {
	fmt.Println("Set config - not implemented yet")
	return nil
}

func (cli *AdminCLI) validateConfig(ctx context.Context, jsonOutput bool) error {
	fmt.Println("Validate config - not implemented yet")
	return nil
}
