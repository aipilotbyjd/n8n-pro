#!/bin/bash

# n8n-pro API Startup Script
# This script loads environment variables from .env and starts the API server

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}Starting n8n-pro API Server...${NC}"

# Check if .env file exists
if [ ! -f .env ]; then
    echo -e "${RED}Error: .env file not found!${NC}"
    echo "Please create a .env file with your configuration."
    exit 1
fi

# Load environment variables from .env file
echo -e "${YELLOW}Loading environment variables from .env...${NC}"
set -a  # Automatically export all variables
source .env
set +a  # Turn off automatic export

# Check if required services are running
echo -e "${YELLOW}Checking required services...${NC}"

# Check PostgreSQL
if ! docker exec n8n-pro-postgres-1 pg_isready -U $DB_USER -d $DB_NAME > /dev/null 2>&1; then
    echo -e "${RED}Error: PostgreSQL is not ready. Make sure Docker services are running:${NC}"
    echo "  docker-compose up -d postgres kafka"
    exit 1
fi

# Check Kafka (optional)
if ! docker exec n8n-pro-kafka-1 kafka-topics.sh --bootstrap-server localhost:9092 --list > /dev/null 2>&1; then
    echo -e "${YELLOW}Warning: Kafka may not be ready, but continuing...${NC}"
fi

echo -e "${GREEN}✓ Services are ready${NC}"

# Build and start the API server
echo -e "${YELLOW}Building and starting API server...${NC}"
echo -e "${BLUE}Configuration:${NC}"
echo "  - Database: $DB_HOST:$DB_PORT/$DB_NAME"
echo "  - API Port: $API_PORT"
echo "  - Metrics Port: $METRICS_PORT"
echo "  - Environment: $ENVIRONMENT"

# Start the server
if [ "$1" = "background" ]; then
    echo -e "${YELLOW}Starting server in background...${NC}"
    go run cmd/api/main.go > api.log 2>&1 &
    echo $! > api.pid
    sleep 2
    
    # Check if server started successfully
    if curl -s http://localhost:$API_PORT/health > /dev/null 2>&1; then
        echo -e "${GREEN}✓ API server started successfully in background${NC}"
        echo "  - API: http://localhost:$API_PORT"
        echo "  - Health: http://localhost:$API_PORT/health"
        echo "  - Metrics: http://localhost:$METRICS_PORT/metrics"
        echo "  - Logs: tail -f api.log"
        echo "  - Stop: kill \$(cat api.pid)"
    else
        echo -e "${RED}✗ Server failed to start. Check api.log for details.${NC}"
        exit 1
    fi
else
    echo -e "${YELLOW}Starting server in foreground...${NC}"
    echo -e "${BLUE}Press Ctrl+C to stop${NC}"
    go run cmd/api/main.go
fi