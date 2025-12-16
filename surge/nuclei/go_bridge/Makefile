# Makefile for Nuclei Go Bridge
# Builds shared library for Python ctypes integration

.PHONY: build clean test

# Go module path
MODULE := nuclei-bridge
BRIDGE_SO := libnuclei_bridge.so
BRIDGE_DIR := $(shell pwd)

build:
	@echo "🔨 Building Nuclei Go Bridge..."
	@cd $(BRIDGE_DIR) && \
	go mod tidy && \
	CGO_ENABLED=1 go build -buildmode=c-shared -o $(BRIDGE_SO) nuclei_bridge.go
	@if [ -f $(BRIDGE_SO) ]; then \
		echo "✅ Built $(BRIDGE_SO)"; \
		ls -lh $(BRIDGE_SO); \
	else \
		echo "❌ Build failed - $(BRIDGE_SO) not created"; \
		exit 1; \
	fi

clean:
	@echo "🧹 Cleaning build artifacts..."
	@rm -f $(BRIDGE_SO) $(BRIDGE_SO).h
	@echo "✅ Cleaned"

test:
	@echo "🧪 Testing Go bridge..."
	@cd $(BRIDGE_DIR) && go test -v

install-deps:
	@echo "📦 Installing Go dependencies..."
	@cd $(BRIDGE_DIR) && go mod download
	@echo "✅ Dependencies installed"

# Build with debug symbols
build-debug:
	@echo "🔨 Building Nuclei Go Bridge (debug)..."
	@cd $(BRIDGE_DIR) && \
	CGO_ENABLED=1 go build -buildmode=c-shared -gcflags="all=-N -l" -o $(BRIDGE_SO) nuclei_bridge.go
	@echo "✅ Built $(BRIDGE_SO) with debug symbols"

help:
	@echo "Available targets:"
	@echo "  build       - Build the Go bridge shared library"
	@echo "  build-debug - Build with debug symbols"
	@echo "  clean       - Remove build artifacts"
	@echo "  test        - Run Go tests"
	@echo "  install-deps - Install Go module dependencies"
