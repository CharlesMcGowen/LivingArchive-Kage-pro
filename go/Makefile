# Makefile for building Go binaries

.PHONY: all wordlist-parser clean install

# Build all binaries
all: wordlist-parser

# Build wordlist parser binary
wordlist-parser:
	@echo "Building wordlist-parser..."
	@cd cmd/wordlist-parser && go build -mod=vendor -o ../../bin/wordlist-parser .
	@chmod +x bin/wordlist-parser
	@echo "✅ Built wordlist-parser at bin/wordlist-parser"

# Install wordlist parser to system PATH (optional)
install: wordlist-parser
	@echo "Installing wordlist-parser..."
	@sudo cp bin/wordlist-parser /usr/local/bin/
	@echo "✅ Installed wordlist-parser to /usr/local/bin/"

# Clean build artifacts
clean:
	@rm -f bin/wordlist-parser
	@echo "✅ Cleaned build artifacts"

# Update Go dependencies
deps:
	@go mod tidy
	@go mod vendor
	@echo "✅ Updated dependencies"
