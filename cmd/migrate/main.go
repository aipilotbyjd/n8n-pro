// Package main provides a dedicated CLI tool for database migrations
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"n8n-pro/internal/config"
	"n8n-pro/internal/database"
)

const usage = `
n8n-pro Database Migration Tool

USAGE:
    migrate <command> [options]

COMMANDS:
    up           Run all pending migrations
    status       Show migration status  
    rollback     Rollback last batch of migrations
    reset        Reset database (DEVELOPMENT ONLY)
    health       Check database health

OPTIONS:
    --config, -c    Config file path (default: .env)
    --json          Output in JSON format
    --help, -h      Show this help message

EXAMPLES:
    migrate up
    migrate status --json
    migrate rollback
    migrate health
`

func main() {
	if len(os.Args) < 2 {
		fmt.Print(usage)
		os.Exit(1)
	}

	// Parse flags
	var (
		jsonOutput = flag.Bool("json", false, "Output in JSON format")
		help       = flag.Bool("help", false, "Show help")
	)
	flag.Parse()

	command := os.Args[1]

	// Handle help
	if *help || command == "help" {
		fmt.Print(usage)
		os.Exit(0)
	}

	// Load configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Initialize database
	db, err := database.Initialize(cfg.Database)
	if err != nil {
		log.Fatalf("Failed to connect to database: %v", err)
	}
	defer db.Close()

	// Create migration manager
	migrationManager := database.NewMigrationManager(db)

	ctx := context.Background()

	// Route commands
	switch command {
	case "up":
		err = runMigrations(ctx, migrationManager, *jsonOutput)
	case "status":
		err = showStatus(ctx, migrationManager, *jsonOutput)
	case "rollback":
		err = rollbackMigrations(ctx, migrationManager, *jsonOutput)
	case "reset":
		err = resetDatabase(ctx, migrationManager, *jsonOutput, cfg.Environment)
	case "health":
		err = checkHealth(ctx, migrationManager, *jsonOutput)
	default:
		fmt.Printf("Unknown command: %s\n\n", command)
		fmt.Print(usage)
		os.Exit(1)
	}

	if err != nil {
		log.Fatalf("Command failed: %v", err)
	}
}

func runMigrations(ctx context.Context, manager *database.MigrationManager, jsonOutput bool) error {
	fmt.Println("🚀 Running database migrations...")

	if err := manager.RunMigrations(); err != nil {
		return fmt.Errorf("migration failed: %w", err)
	}

	if jsonOutput {
		result := map[string]string{"status": "success", "message": "Migrations completed successfully"}
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	fmt.Println("✅ All migrations completed successfully!")
	return nil
}

func showStatus(ctx context.Context, manager *database.MigrationManager, jsonOutput bool) error {
	migrations, err := manager.GetMigrationStatus()
	if err != nil {
		return fmt.Errorf("failed to get migration status: %w", err)
	}

	if jsonOutput {
		return json.NewEncoder(os.Stdout).Encode(migrations)
	}

	fmt.Printf("📊 Migration Status\n")
	fmt.Printf("===================\n")
	fmt.Printf("Total migrations: %d\n\n", len(migrations))

	if len(migrations) == 0 {
		fmt.Println("No migrations found.")
		return nil
	}

	for _, migration := range migrations {
		status := "✅ Applied"
		if migration.RolledBack {
			status = "🔄 Rolled Back"
		}

		fmt.Printf("%s %s\n", status, migration.Version)
		fmt.Printf("   Name: %s\n", migration.Name)
		fmt.Printf("   Applied: %s\n", migration.AppliedAt.Format("2006-01-02 15:04:05"))
		fmt.Printf("   Execution: %dms\n", migration.ExecutionTime)
		fmt.Println()
	}

	return nil
}

func rollbackMigrations(ctx context.Context, manager *database.MigrationManager, jsonOutput bool) error {
	fmt.Println("🔄 Rolling back last migration batch...")

	if err := manager.RollbackLastBatch(); err != nil {
		return fmt.Errorf("rollback failed: %w", err)
	}

	if jsonOutput {
		result := map[string]string{"status": "success", "message": "Rollback completed successfully"}
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	fmt.Println("✅ Rollback completed successfully!")
	return nil
}

func resetDatabase(ctx context.Context, manager *database.MigrationManager, jsonOutput bool, environment string) error {
	if environment == "production" {
		return fmt.Errorf("database reset is not allowed in production environment")
	}

	fmt.Println("⚠️  WARNING: This will delete ALL data in the database!")
	fmt.Print("Type 'yes' to confirm: ")

	var confirmation string
	fmt.Scanln(&confirmation)

	if confirmation != "yes" {
		fmt.Println("❌ Database reset cancelled")
		return nil
	}

	fmt.Println("🗑️  Resetting database...")

	if err := manager.ResetDatabase(); err != nil {
		return fmt.Errorf("database reset failed: %w", err)
	}

	if jsonOutput {
		result := map[string]string{"status": "success", "message": "Database reset completed successfully"}
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	fmt.Println("✅ Database reset completed successfully!")
	return nil
}

func checkHealth(ctx context.Context, manager *database.MigrationManager, jsonOutput bool) error {
	fmt.Println("🏥 Checking database health...")

	if err := manager.CheckDatabaseHealth(); err != nil {
		if jsonOutput {
			result := map[string]interface{}{"status": "unhealthy", "error": err.Error()}
			return json.NewEncoder(os.Stdout).Encode(result)
		}
		return fmt.Errorf("database health check failed: %w", err)
	}

	if jsonOutput {
		result := map[string]string{"status": "healthy", "message": "All required tables exist"}
		return json.NewEncoder(os.Stdout).Encode(result)
	}

	fmt.Println("✅ Database is healthy - all required tables exist!")
	return nil
}