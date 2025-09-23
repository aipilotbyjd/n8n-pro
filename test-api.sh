#!/bin/bash

echo "Testing API health endpoint..."
curl -s -w "\nResponse Code: %{http_code}\n" http://localhost:8080/health

echo -e "\n\nTesting container status..."
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep n8n-pro

echo -e "\n\nTesting port 8080..."
nc -zv localhost 8080 2>&1