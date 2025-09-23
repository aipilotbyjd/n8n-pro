#!/bin/bash
echo "Building API..."
cd /Users/jaydeepdhrangiya/Code/Go/n8n-pro
docker-compose build api 2>&1 | head -50
echo "Build completed!"