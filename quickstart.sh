#!/bin/bash

# =============================================================================
# n8n Pro - Quickstart Script
# This script sets up everything you need to run n8n Pro
# =============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Project variables
PROJECT_NAME="n8n Pro"
MIN_GO_VERSION="1.22"
MIN_DOCKER_VERSION="20.10"
MIN_NODE_VERSION="18"

# Spinner function
spin() {
    spinner="/|\\-/|\\-"
    while :; do
        for i in $(seq 0 7); do
            echo -ne "${spinner:$i:1}"
            echo -ne "\010"
            sleep 0.1
        done
    done
}

# Function to print colored output
print_header() {
    echo ""
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${MAGENTA}   $1${NC}"
    echo -e "${MAGENTA}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo ""
}
print_info() { echo -e "${BLUE}ℹ ${NC} $1"; }
print_success() { echo -e "${GREEN}✓${NC} $1"; }
print_warning() { echo -e "${YELLOW}⚠${NC} $1"; }
print_error() { echo -e "${RED}✗${NC} $1"; }
print_step() { echo -e "${CYAN}▶${NC} $1"; }

# Check command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Compare versions
version_ge() {
    [ "$(printf '%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

# ASCII Art Banner
show_banner() {
    echo -e "${CYAN}"
    cat << "EOF"
    ╔══════════════════════════════════════════════════════════════╗
    ║                                                              ║
    ║  ███╗   ██╗ █████╗ ███╗   ██╗    ██████╗ ██████╗  ██████╗  ║
    ║  ████╗  ██║██╔══██╗████╗  ██║    ██╔══██╗██╔══██╗██╔═══██╗ ║
    ║  ██╔██╗ ██║╚█████╔╝██╔██╗ ██║    ██████╔╝██████╔╝██║   ██║ ║
    ║  ██║╚██╗██║██╔══██╗██║╚██╗██║    ██╔═══╝ ██╔══██╗██║   ██║ ║
    ║  ██║ ╚████║╚█████╔╝██║ ╚████║    ██║     ██║  ██║╚██████╔╝ ║
    ║  ╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═══╝    ╚═╝     ╚═╝  ╚═╝ ╚═════╝  ║
    ║                                                              ║
    ║         Enterprise Workflow Automation Platform             ║
    ╚══════════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
}

# Check prerequisites
check_prerequisites() {
    print_header "Checking Prerequisites"

    local all_good=true

    # Check Go
    if command_exists go; then
        GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
        if version_ge "$GO_VERSION" "$MIN_GO_VERSION"; then
            print_success "Go $GO_VERSION installed"
        else
            print_warning "Go $GO_VERSION installed (minimum required: $MIN_GO_VERSION)"
            all_good=false
        fi
    else
        print_error "Go is not installed"
        echo "  Install from: https://golang.org/dl/"
        all_good=false
    fi

    # Check Docker
    if command_exists docker; then
        DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "0.0")
        if version_ge "$DOCKER_VERSION" "$MIN_DOCKER_VERSION"; then
            print_success "Docker $DOCKER_VERSION installed"
        else
            print_warning "Docker $DOCKER_VERSION installed (minimum required: $MIN_DOCKER_VERSION)"
        fi
    else
        print_warning "Docker is not installed (optional but recommended)"
        echo "  Install from: https://docs.docker.com/get-docker/"
    fi

    # Check Docker Compose
    if command_exists docker-compose || docker compose version >/dev/null 2>&1; then
        print_success "Docker Compose installed"
    else
        print_warning "Docker Compose is not installed (optional but recommended)"
    fi

    # Check Make
    if command_exists make; then
        print_success "Make installed"
    else
        print_error "Make is not installed"
        echo "  Install: apt-get install make (Ubuntu) or brew install make (macOS)"
        all_good=false
    fi

    # Check Git
    if command_exists git; then
        print_success "Git installed"
    else
        print_error "Git is not installed"
        all_good=false
    fi

    # Check PostgreSQL client (optional)
    if command_exists psql; then
        print_success "PostgreSQL client installed"
    else
        print_warning "PostgreSQL client not installed (optional)"
    fi

    # Check Node.js (optional for frontend)
    if command_exists node; then
        NODE_VERSION=$(node -v | sed 's/v//')
        if version_ge "$NODE_VERSION" "$MIN_NODE_VERSION"; then
            print_success "Node.js $NODE_VERSION installed"
        else
            print_warning "Node.js $NODE_VERSION installed (minimum recommended: $MIN_NODE_VERSION)"
        fi
    else
        print_info "Node.js not installed (optional, needed for frontend development)"
    fi

    if [ "$all_good" = false ]; then
        print_error "Some prerequisites are missing. Please install them and run again."
        exit 1
    fi

    print_success "All required prerequisites are installed!"
}

# Setup environment
setup_environment() {
    print_header "Setting Up Environment"

    # Create necessary directories
    print_step "Creating directories..."
    mkdir -p build bin storage/uploads storage/temp storage/logs configs/development
    print_success "Directories created"

    # Copy environment file
    if [ ! -f configs/development/.env.development ]; then
        print_step "Creating environment configuration..."
        if [ -f configs/.env.example ]; then
            cp configs/.env.example configs/development/.env.development
        else
            # Create a basic .env file
            cat > configs/development/.env.development << 'EOF'
# Database Configuration
DB_HOST=localhost
DB_PORT=5432
DB_NAME=n8n_pro
DB_USER=postgres
DB_PASSWORD=postgres
DB_SSL_MODE=disable

# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=

# API Configuration
API_PORT=8080
API_HOST=0.0.0.0
ENV=development
LOG_LEVEL=debug

# JWT Configuration
JWT_SECRET=your-super-secret-jwt-key-change-this
JWT_EXPIRY=24h

# Storage Configuration
STORAGE_TYPE=local
STORAGE_PATH=./storage

# SMTP Configuration (optional)
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=
SMTP_PASSWORD=
SMTP_FROM=noreply@n8n-pro.local

# Monitoring (optional)
METRICS_ENABLED=true
TRACING_ENABLED=false
EOF
        fi
        print_success "Environment configuration created"
        print_warning "Please edit configs/development/.env.development with your settings"
    else
        print_success "Environment configuration already exists"
    fi
}

# Install Go dependencies
install_dependencies() {
    print_header "Installing Dependencies"

    print_step "Downloading Go modules..."
    go mod download
    print_success "Go modules downloaded"

    print_step "Installing development tools..."

    # Install Air for hot reload
    if ! command_exists air; then
        go install github.com/cosmtrek/air@latest
        print_success "Air installed (hot reload)"
    fi

    # Install golangci-lint
    if ! command_exists golangci-lint; then
        curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.59.1
        print_success "golangci-lint installed"
    fi

    # Install Swag for API docs
    if ! command_exists swag; then
        go install github.com/swaggo/swag/cmd/swag@latest
        print_success "Swag installed (API documentation)"
    fi

    # Install migrate tool
    if ! command_exists migrate; then
        go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
        print_success "Migrate installed (database migrations)"
    fi

    print_success "All dependencies installed"
}

# Setup database
setup_database() {
    print_header "Setting Up Database"

    echo -e "${CYAN}Choose database setup method:${NC}"
    echo "1) Use Docker (recommended)"
    echo "2) Use existing PostgreSQL installation"
    echo "3) Skip database setup"

    read -p "Enter choice [1-3]: " db_choice

    case $db_choice in
        1)
            print_step "Starting PostgreSQL with Docker..."
            docker run -d \
                --name n8n-postgres \
                -e POSTGRES_USER=postgres \
                -e POSTGRES_PASSWORD=postgres \
                -e POSTGRES_DB=n8n_pro \
                -p 5432:5432 \
                postgres:16-alpine 2>/dev/null || {
                print_warning "PostgreSQL container already exists"
            }

            # Wait for PostgreSQL to be ready
            print_step "Waiting for PostgreSQL to be ready..."
            sleep 5

            # Start Redis
            print_step "Starting Redis with Docker..."
            docker run -d \
                --name n8n-redis \
                -p 6379:6379 \
                redis:7-alpine 2>/dev/null || {
                print_warning "Redis container already exists"
            }

            print_success "Database services started"
            ;;
        2)
            print_info "Using existing PostgreSQL installation"
            print_warning "Make sure PostgreSQL is running and accessible"
            ;;
        3)
            print_info "Skipping database setup"
            return
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac

    # Run migrations
    print_step "Running database migrations..."
    make migrate-up 2>/dev/null || {
        print_warning "Could not run migrations. You may need to run them manually: make migrate-up"
    }
}

# Build the project
build_project() {
    print_header "Building Project"

    print_step "Building all services..."
    make build-all || {
        print_error "Build failed. Trying individual builds..."

        for service in api worker scheduler webhook admin migrate; do
            print_step "Building $service..."
            go build -o build/$service ./cmd/$service || {
                print_warning "Failed to build $service"
            }
        done
    }

    print_success "Project built successfully"
}

# Setup monitoring (optional)
setup_monitoring() {
    print_header "Monitoring Setup (Optional)"

    echo -e "${CYAN}Do you want to set up monitoring? (Prometheus, Grafana, etc.) [y/N]:${NC}"
    read -p "" setup_mon

    if [[ "$setup_mon" =~ ^[Yy]$ ]]; then
        if [ -f docker-compose.monitoring.yml ]; then
            print_step "Starting monitoring stack..."
            docker-compose -f docker-compose.monitoring.yml up -d
            print_success "Monitoring stack started"

            echo ""
            print_info "Monitoring services available at:"
            echo "  • Prometheus: http://localhost:9090"
            echo "  • Grafana: http://localhost:3000 (admin/admin123)"
            echo "  • Jaeger: http://localhost:16686"
            echo "  • Loki: http://localhost:3100"
        else
            print_warning "Monitoring configuration not found"
        fi
    else
        print_info "Skipping monitoring setup"
    fi
}

# Start services
start_services() {
    print_header "Starting Services"

    echo -e "${CYAN}How would you like to run the services?${NC}"
    echo "1) Development mode with hot reload (recommended for development)"
    echo "2) Production mode"
    echo "3) Docker Compose"
    echo "4) Manual start (I'll start them myself)"

    read -p "Enter choice [1-4]: " run_choice

    case $run_choice in
        1)
            print_step "Starting in development mode with hot reload..."
            print_info "Starting API server with Air..."
            air -c .air.toml &

            print_success "Services started in development mode"
            print_info "API server running at: http://localhost:8080"
            print_info "Press Ctrl+C to stop"
            ;;
        2)
            print_step "Starting in production mode..."
            ./build/api &
            API_PID=$!

            ./build/worker &
            WORKER_PID=$!

            ./build/scheduler &
            SCHEDULER_PID=$!

            print_success "Services started in production mode"
            print_info "API: http://localhost:8080 (PID: $API_PID)"
            print_info "Worker: PID $WORKER_PID"
            print_info "Scheduler: PID $SCHEDULER_PID"
            ;;
        3)
            print_step "Starting with Docker Compose..."
            docker-compose up -d
            print_success "Services started with Docker Compose"
            print_info "Run 'docker-compose logs -f' to view logs"
            ;;
        4)
            print_info "Manual start selected"
            echo ""
            print_info "To start services manually, run:"
            echo "  • API: ./build/api"
            echo "  • Worker: ./build/worker"
            echo "  • Scheduler: ./build/scheduler"
            echo "  • Development mode: make dev or air"
            ;;
        *)
            print_error "Invalid choice"
            exit 1
            ;;
    esac
}

# Show next steps
show_next_steps() {
    print_header "Setup Complete! 🎉"

    echo -e "${GREEN}n8n Pro is ready to use!${NC}"
    echo ""
    echo -e "${CYAN}Quick Commands:${NC}"
    echo "  • Start development server: ${WHITE}make dev${NC}"
    echo "  • Run tests: ${WHITE}make test${NC}"
    echo "  • View logs: ${WHITE}tail -f storage/logs/*.log${NC}"
    echo "  • Stop Docker services: ${WHITE}docker-compose down${NC}"
    echo ""
    echo -e "${CYAN}Important URLs:${NC}"
    echo "  • API: ${WHITE}http://localhost:8080${NC}"
    echo "  • API Health: ${WHITE}http://localhost:8080/health${NC}"
    echo "  • API Docs: ${WHITE}http://localhost:8080/swagger${NC}"
    echo "  • Metrics: ${WHITE}http://localhost:8080/metrics${NC}"
    echo ""
    echo -e "${CYAN}Documentation:${NC}"
    echo "  • Project Structure: ${WHITE}PROJECT_STRUCTURE.md${NC}"
    echo "  • Quick Reference: ${WHITE}QUICK_REFERENCE.md${NC}"
    echo "  • API Reference: ${WHITE}docs/api-reference.md${NC}"
    echo ""
    echo -e "${CYAN}Development Tools:${NC}"
    echo "  • Generate code: ${WHITE}./scripts/generate.sh${NC}"
    echo "  • Run linters: ${WHITE}make lint${NC}"
    echo "  • Format code: ${WHITE}make fmt${NC}"
    echo "  • Run benchmarks: ${WHITE}make test-bench${NC}"
    echo ""
    echo -e "${YELLOW}Don't forget to:${NC}"
    echo "  1. Review and update ${WHITE}configs/development/.env.development${NC}"
    echo "  2. Run database migrations: ${WHITE}make migrate-up${NC}"
    echo "  3. Check the documentation in ${WHITE}docs/${NC}"
    echo "  4. Join our community for support and updates"
    echo ""
    echo -e "${MAGENTA}Happy coding! 🚀${NC}"
}

# Cleanup function
cleanup() {
    print_warning "Cleaning up..."
    # Kill any background processes
    jobs -p | xargs -r kill 2>/dev/null
    exit 1
}

# Trap Ctrl+C
trap cleanup INT

# Main execution
main() {
    clear
    show_banner

    print_info "Starting n8n Pro quickstart setup..."
    print_info "This will set up everything you need to run n8n Pro"
    echo ""

    # Run setup steps
    check_prerequisites
    setup_environment
    install_dependencies
    setup_database
    build_project
    setup_monitoring
    start_services
    show_next_steps

    # Keep script running if services were started
    if [[ "$run_choice" == "1" ]] || [[ "$run_choice" == "2" ]]; then
        print_info "Press Ctrl+C to stop services and exit"
        wait
    fi
}

# Run main function
main "$@"
