#!/bin/bash
# Quick start script for Django server container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "🚀 Starting Django server container on port 9000..."
echo "📁 Project root: $PROJECT_ROOT"
echo ""

cd "$PROJECT_ROOT"

# Check if .env file exists in docker directory
if [ ! -f "$SCRIPT_DIR/.env" ]; then
    echo "⚠️  No .env file found. PostgreSQL connection is required!"
    echo "   Copy docker/env.example to docker/.env and configure database credentials."
    echo "   Default values will be used (localhost, postgres/postgres)"
    echo ""
fi

# Build and start the Django server
docker-compose -f "$SCRIPT_DIR/docker-compose.yml" up --build -d django-server

echo ""
echo "✅ Django server starting..."
echo ""
echo "📊 View logs: docker-compose -f docker/docker-compose.yml logs -f django-server"
echo "🌐 Access server: http://localhost:9000/reconnaissance/"
echo "🛑 Stop server: docker-compose -f docker/docker-compose.yml stop django-server"
echo ""

# Wait a moment and show status
sleep 2
docker-compose -f "$SCRIPT_DIR/docker-compose.yml" ps django-server

