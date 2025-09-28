#!/bin/bash
set -e
echo "Running all tests..."
go test ./...
echo "Tests complete!"
