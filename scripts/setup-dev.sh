#!/bin/bash
set -e
echo "Setting up development environment..."
cp configs/.env.example configs/development/.env.development
echo "Please edit configs/development/.env.development with your settings"
go mod download
make build-all
echo "Development setup complete!"
