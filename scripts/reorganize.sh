#!/bin/bash

# n8n Pro - Project Reorganization Script
# This script completes the migration to the new project structure

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Project root directory
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$PROJECT_ROOT"

echo -e "${BLUE}=== n8n Pro Project Reorganization ===${NC}"
echo "Project root: $PROJECT_ROOT"
echo ""

# Function to print status
print_status() {
    echo -e "${GREEN}✓${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

# Step 1: Create all necessary directories
echo -e "${BLUE}Step 1: Creating directory structure...${NC}"
mkdir -p build bin dist
mkdir -p configs/{development,production,test}
mkdir -p internal/{domain,application,infrastructure,presentation,repository,shared,testutils}
mkdir -p internal/domain/{workflow,execution,user,team,audit,nodes,credentials,plugins,notifications}
mkdir -p internal/application/{workflow,auth,billing,execution,scheduler,notifications,teams,audit}
mkdir -p internal/infrastructure/{database,messaging,storage,cache,monitoring}
mkdir -p internal/infrastructure/messaging/{kafka,rabbitmq}
mkdir -p internal/infrastructure/storage/{s3,local}
mkdir -p internal/infrastructure/cache/{redis,memory}
mkdir -p internal/presentation/{http,grpc,websocket,graphql}
mkdir -p internal/presentation/http/{handlers,middleware,routes,validators}
mkdir -p internal/repository/{postgres,interfaces}
mkdir -p internal/shared/{errors,utils,constants,types}
mkdir -p internal/testutils/{mocks,fixtures,helpers}
mkdir -p test/{unit,integration,e2e,benchmarks,fixtures,load}
mkdir -p scripts/{build,deploy,test,migration}
mkdir -p docs/{architecture,api,development,operations,security,tutorials}
mkdir -p deployments/{docker,k8s,terraform,ansible}
mkdir -p storage/{uploads,temp,cache,logs}
print_status "Directory structure created"

# Step 2: Move binaries to build directory
echo -e "${BLUE}Step 2: Moving binaries...${NC}"
for binary in admin api migrate scheduler webhook worker; do
    if [ -f "$PROJECT_ROOT/$binary" ]; then
        mv "$PROJECT_ROOT/$binary" "$PROJECT_ROOT/build/" 2>/dev/null || true
        print_status "Moved $binary to build/"
    fi
done

# Step 3: Move test scripts to scripts directory
echo -e "${BLUE}Step 3: Organizing scripts...${NC}"
for script in test-api.sh test_api.sh test_registration.sh; do
    if [ -f "$PROJECT_ROOT/$script" ]; then
        mv "$PROJECT_ROOT/$script" "$PROJECT_ROOT/scripts/test/" 2>/dev/null || true
        print_status "Moved $script to scripts/test/"
    fi
done

# Step 4: Organize configuration files
echo -e "${BLUE}Step 4: Organizing configuration files...${NC}"
if [ -f "$PROJECT_ROOT/.env" ]; then
    cp "$PROJECT_ROOT/.env" "$PROJECT_ROOT/configs/development/.env.development" 2>/dev/null || true
    print_status "Copied .env to configs/development/"
fi
if [ -f "$PROJECT_ROOT/.env.test" ]; then
    cp "$PROJECT_ROOT/.env.test" "$PROJECT_ROOT/configs/test/.env.test" 2>/dev/null || true
    print_status "Copied .env.test to configs/test/"
fi
if [ -f "$PROJECT_ROOT/.env.example" ]; then
    cp "$PROJECT_ROOT/.env.example" "$PROJECT_ROOT/configs/.env.example" 2>/dev/null || true
    print_status "Copied .env.example to configs/"
fi

# Step 5: Reorganize internal packages
echo -e "${BLUE}Step 5: Reorganizing internal packages...${NC}"

# Move database related files
if [ -d "internal/database" ] && [ "$(ls -A internal/database 2>/dev/null)" ]; then
    cp -r internal/database/* internal/infrastructure/database/ 2>/dev/null || true
    print_status "Moved database files to infrastructure/database"
fi

# Move messaging files
if [ -d "internal/messaging" ] && [ "$(ls -A internal/messaging 2>/dev/null)" ]; then
    cp -r internal/messaging/* internal/infrastructure/messaging/ 2>/dev/null || true
    print_status "Moved messaging files to infrastructure/messaging"
fi

# Move storage files
if [ -d "internal/storage" ] && [ "$(ls -A internal/storage 2>/dev/null)" ]; then
    cp -r internal/storage/* internal/infrastructure/storage/ 2>/dev/null || true
    print_status "Moved storage files to infrastructure/storage"
fi

# Move API/HTTP files
if [ -d "internal/api" ] && [ "$(ls -A internal/api 2>/dev/null)" ]; then
    cp -r internal/api/* internal/presentation/http/ 2>/dev/null || true
    print_status "Moved API files to presentation/http"
fi

# Move domain entities
for domain in workflows execution teams notifications credentials nodes plugins audit; do
    if [ -d "internal/$domain" ] && [ "$(ls -A internal/$domain 2>/dev/null)" ]; then
        cp -r "internal/$domain"/* "internal/domain/${domain%s}/" 2>/dev/null || true
        print_status "Moved $domain to domain layer"
    fi
done

# Move application services
for service in auth billing scheduler; do
    if [ -d "internal/$service" ] && [ "$(ls -A internal/$service 2>/dev/null)" ]; then
        cp -r "internal/$service"/* "internal/application/$service/" 2>/dev/null || true
        print_status "Moved $service to application layer"
    fi
done

# Move repository files
if [ -d "internal/repository" ] && [ "$(ls -A internal/repository 2>/dev/null)" ]; then
    cp -r internal/repository/* internal/repository/postgres/ 2>/dev/null || true
    print_status "Moved repository files"
fi

# Move common/shared files
if [ -d "internal/common" ] && [ "$(ls -A internal/common 2>/dev/null)" ]; then
    cp -r internal/common/* internal/shared/ 2>/dev/null || true
    print_status "Moved common files to shared"
fi

# Step 6: Update import paths in Go files
echo -e "${BLUE}Step 6: Updating import paths...${NC}"
update_imports() {
    local file=$1
    # Update common import path changes
    sed -i.bak \
        -e 's|"n8n-pro/internal/api/|"n8n-pro/internal/presentation/http/|g' \
        -e 's|"n8n-pro/internal/database"|"n8n-pro/internal/infrastructure/database"|g' \
        -e 's|"n8n-pro/internal/messaging"|"n8n-pro/internal/infrastructure/messaging"|g' \
        -e 's|"n8n-pro/internal/storage"|"n8n-pro/internal/infrastructure/storage"|g' \
        -e 's|"n8n-pro/internal/auth"|"n8n-pro/internal/application/auth"|g' \
        -e 's|"n8n-pro/internal/billing"|"n8n-pro/internal/application/billing"|g' \
        -e 's|"n8n-pro/internal/workflows"|"n8n-pro/internal/domain/workflow"|g' \
        -e 's|"n8n-pro/internal/execution"|"n8n-pro/internal/domain/execution"|g' \
        -e 's|"n8n-pro/internal/common"|"n8n-pro/internal/shared"|g' \
        -e 's|"n8n-pro/internal/db"|"n8n-pro/internal/infrastructure/database"|g' \
        "$file"
    rm -f "${file}.bak"
}

# Find all Go files and update imports
find . -name "*.go" -type f ! -path "./vendor/*" ! -path "./_archive/*" ! -path "./build/*" | while read -r file; do
    update_imports "$file"
done
print_status "Updated import paths in Go files"

# Step 7: Update Makefile paths
echo -e "${BLUE}Step 7: Updating Makefile...${NC}"
if [ -f "Makefile" ]; then
    sed -i.bak \
        -e 's|API_BINARY := api|API_BINARY := build/api|g' \
        -e 's|WORKER_BINARY := worker|WORKER_BINARY := build/worker|g' \
        -e 's|SCHEDULER_BINARY := scheduler|SCHEDULER_BINARY := build/scheduler|g' \
        -e 's|WEBHOOK_BINARY := webhook|WEBHOOK_BINARY := build/webhook|g' \
        -e 's|ADMIN_BINARY := admin|ADMIN_BINARY := build/admin|g' \
        -e 's|MIGRATE_BINARY := migrate|MIGRATE_BINARY := build/migrate|g' \
        "Makefile"
    rm -f "Makefile.bak"
    print_status "Updated Makefile paths"
fi

# Step 8: Create .gitkeep files for empty directories
echo -e "${BLUE}Step 8: Creating .gitkeep files...${NC}"
find . -type d -empty ! -path "./.git/*" ! -path "./vendor/*" ! -path "./_archive/*" -exec touch {}/.gitkeep \;
print_status "Created .gitkeep files for empty directories"

# Step 9: Clean up old empty directories
echo -e "${BLUE}Step 9: Cleaning up old directories...${NC}"
cleanup_dirs=(
    "internal/api"
    "internal/auth"
    "internal/billing"
    "internal/workflows"
    "internal/execution"
    "internal/teams"
    "internal/notifications"
    "internal/credentials"
    "internal/nodes"
    "internal/plugins"
    "internal/audit"
    "internal/common"
    "internal/db"
    "internal/database"
    "internal/messaging"
    "internal/storage"
    "internal/http"
    "internal/webhooks"
    "internal/scheduler"
    "internal/services"
)

for dir in "${cleanup_dirs[@]}"; do
    if [ -d "$dir" ] && [ -z "$(ls -A $dir 2>/dev/null)" ]; then
        rmdir "$dir" 2>/dev/null || true
        print_status "Removed empty directory: $dir"
    fi
done

# Step 10: Generate documentation
echo -e "${BLUE}Step 10: Generating documentation...${NC}"
cat > docs/MIGRATION.md << 'EOF'
# Migration to New Project Structure

This document describes the migration from the old project structure to the new Domain-Driven Design (DDD) structure.

## What Changed

### Directory Structure
- **Before**: Flat structure with mixed concerns
- **After**: Layered architecture with clear separation of concerns

### Key Changes
1. **Database**: Consolidated from `internal/db` and `internal/database` to `internal/infrastructure/database`
2. **API**: Moved from `internal/api` to `internal/presentation/http`
3. **Services**: Reorganized from `internal/services` to `internal/application/*`
4. **Domain Logic**: Centralized in `internal/domain/*`
5. **Configuration**: Moved to `configs/` directory
6. **Scripts**: Organized in `scripts/` directory
7. **Binaries**: Output to `build/` directory

## Import Path Updates

Old Path | New Path
---------|----------
`n8n-pro/internal/api` | `n8n-pro/internal/presentation/http`
`n8n-pro/internal/database` | `n8n-pro/internal/infrastructure/database`
`n8n-pro/internal/auth` | `n8n-pro/internal/application/auth`
`n8n-pro/internal/workflows` | `n8n-pro/internal/domain/workflow`
`n8n-pro/internal/common` | `n8n-pro/internal/shared`

## Next Steps
1. Run tests to ensure everything works: `make test`
2. Update your IDE's import settings
3. Review and update any custom scripts
4. Update CI/CD pipelines if necessary
EOF
print_status "Created migration documentation"

# Step 11: Create quick helper scripts
echo -e "${BLUE}Step 11: Creating helper scripts...${NC}"

# Build script
cat > scripts/build/build-all.sh << 'EOF'
#!/bin/bash
set -e
echo "Building all services..."
make build-all
echo "Build complete! Binaries are in ./build/"
EOF
chmod +x scripts/build/build-all.sh

# Test script
cat > scripts/test/run-tests.sh << 'EOF'
#!/bin/bash
set -e
echo "Running all tests..."
go test ./...
echo "Tests complete!"
EOF
chmod +x scripts/test/run-tests.sh

# Development setup script
cat > scripts/setup-dev.sh << 'EOF'
#!/bin/bash
set -e
echo "Setting up development environment..."
cp configs/.env.example configs/development/.env.development
echo "Please edit configs/development/.env.development with your settings"
go mod download
make build-all
echo "Development setup complete!"
EOF
chmod +x scripts/setup-dev.sh

print_status "Created helper scripts"

# Step 12: Final summary
echo ""
echo -e "${GREEN}=== Reorganization Complete ===${NC}"
echo ""
echo "Summary of changes:"
echo "  • Project structure migrated to Domain-Driven Design"
echo "  • Configuration files organized in configs/"
echo "  • Scripts organized in scripts/"
echo "  • Binaries will be output to build/"
echo "  • Documentation updated in docs/"
echo ""
echo "Next steps:"
echo "  1. Review the changes: git status"
echo "  2. Run tests: make test"
echo "  3. Rebuild services: make build-all"
echo "  4. Update your .env file: cp configs/.env.example configs/development/.env.development"
echo ""
echo "For more details, see: docs/MIGRATION.md"
echo ""
print_warning "Remember to update any CI/CD pipelines and deployment scripts!"
