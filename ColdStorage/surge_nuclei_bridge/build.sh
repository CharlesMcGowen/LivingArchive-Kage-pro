#!/bin/bash
# Build script for Surge Nuclei Memory Bridge
# ============================================
#
# Builds Go shared library for Python integration
#
# Author: EGO Revolution Team
# Version: 1.0.0

set -e

echo "🔨 Building Surge Nuclei Memory Bridge..."
echo ""

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo "❌ Error: Go is not installed"
    echo "   Please install Go 1.21+ from https://go.dev"
    exit 1
fi

# Check Go version
GO_VERSION=$(go version | awk '{print $3}' | sed 's/go//')
echo "✅ Found Go version: $GO_VERSION"

# Set build environment
export CGO_ENABLED=1
export GOOS=linux
export GOARCH=amd64

echo ""
echo "📦 Initializing Go modules..."
go mod init surge_nuclei_memory_bridge 2>/dev/null || true

echo "📥 Downloading dependencies..."
go get github.com/projectdiscovery/nuclei/v3@v3.4.10

echo ""
echo "🔨 Building shared library..."

# Build as shared library
go build -buildmode=c-shared -o libnuclei_bridge.so bridge.go

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Build successful!"
    echo "   Output: libnuclei_bridge.so"
    echo ""
    ls -lh libnuclei_bridge.so
    echo ""
    echo "📋 Next steps:"
    echo "   1. Copy libnuclei_bridge.so to appropriate location"
    echo "   2. Restart Surge container"
    echo "   3. Bridge will auto-detect and enable"
else
    echo ""
    echo "❌ Build failed"
    echo "   Check Go environment and dependencies"
    exit 1
fi

echo ""
echo "🎉 Surge Nuclei Memory Bridge ready!"
