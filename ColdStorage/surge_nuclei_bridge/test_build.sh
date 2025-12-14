#!/bin/bash
# Docker Build Test for Surge Nuclei Memory Bridge
# ===============================================
#
# Tests compilation in Docker environment
#
set -e

echo "🔨 Testing Surge Nuclei Memory Bridge compilation in Docker..."
echo ""

# Get script directory
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Test with official Go Docker image
echo "📦 Testing with golang:1.21-alpine..."
docker run --rm \
    -v "$SCRIPT_DIR:/build" \
    -w /build \
    golang:1.21-alpine \
    sh -c "
        echo '✅ Go version:'
        go version
        echo ''
        echo '📥 Downloading dependencies...'
        go mod download
        echo ''
        echo '🔨 Building shared library...'
        export CGO_ENABLED=1
        go build -buildmode=c-shared -o libnuclei_bridge.so bridge.go
        echo ''
        echo '✅ Build successful!'
        ls -lh libnuclei_bridge.so
        echo ''
        echo '📋 Verifying library...'
        file libnuclei_bridge.so
    "

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Docker build test PASSED"
    echo "   Library is ready for deployment"
else
    echo ""
    echo "❌ Docker build test FAILED"
    exit 1
fi

