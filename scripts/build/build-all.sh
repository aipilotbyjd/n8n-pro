#!/bin/bash
set -e
echo "Building all services..."
make build-all
echo "Build complete! Binaries are in ./build/"
