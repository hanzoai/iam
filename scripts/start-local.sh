#!/bin/bash
# Quick local startup script for Hanzo IAM
set -e

cd "$(dirname "$0")/.."

echo "🚀 Starting Hanzo IAM locally..."

# Start database services
echo "Starting PostgreSQL and Redis..."
docker compose -f compose.dev.local.yml up -d

# Wait for postgres
echo "Waiting for PostgreSQL..."
until docker compose -f compose.dev.local.yml exec -T postgres pg_isready -U hanzo -d hanzo_iam 2>/dev/null; do
  sleep 1
done
echo "✓ PostgreSQL ready"

# Wait for redis
echo "Waiting for Redis..."
until docker compose -f compose.dev.local.yml exec -T redis redis-cli ping 2>/dev/null | grep -q PONG; do
  sleep 1
done
echo "✓ Redis ready"

# Run Go application
echo "Starting IAM backend..."
export RUNMODE=dev
go run main.go &
GO_PID=$!

echo ""
echo "✅ Hanzo IAM running at http://localhost:8000"
echo ""
echo "Available endpoints:"
echo "  - http://localhost:8000          - Admin UI"
echo "  - http://localhost:8000/api/health - Health check"
echo "  - http://localhost:8000/swagger   - API docs"
echo ""
echo "Organizations configured:"
echo "  - Hanzo (hanzo.id)"
echo "  - Zoo (zoo.id)"
echo "  - Lux (lux.id)"
echo "  - Pars (pars.id)"
echo ""
echo "Press Ctrl+C to stop..."

# Wait for Go process
wait $GO_PID
