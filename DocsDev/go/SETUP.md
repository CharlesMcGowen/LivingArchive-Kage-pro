# Go Module Setup Guide

## Initial Setup

### 1. Create Go Directory Structure

```bash
cd /media/ego/328010BE80108A8D2/github_public/LivingArchive-Kage-pro
mkdir -p go/{cmd/kumo,cmd/suzu,internal/{kumo,suzu,api,common},pkg/htmlparser}
```

### 2. Initialize Go Module (Local Only)

```bash
cd go
go mod init recon
```

This creates `go.mod` with:
```go
module recon

go 1.21
```

**Note**: Module name is `recon` (local), not a GitHub URL.

### 3. Add Minimal Dependencies

```bash
# Only add what we absolutely need
go get golang.org/x/net/html  # For HTML parsing
```

### 4. Vendor Dependencies (Lock Versions Locally)

```bash
go mod vendor
```

This creates `vendor/` directory with local copies of all dependencies.

### 5. Verify Setup

```bash
# Check go.mod
cat go.mod

# Check vendor directory
ls -la vendor/

# Verify no external URLs in go.mod
grep -v "^module\|^go\|^require\|^replace" go.mod | grep -E "github|gitlab"
# Should return nothing
```

## Building

### Build with Vendored Dependencies Only

```bash
cd go

# Build Kumo daemon
go build -mod=vendor -o ../bin/kumo ./cmd/kumo

# Build Suzu daemon
go build -mod=vendor -o ../bin/suzu ./cmd/suzu
```

The `-mod=vendor` flag ensures:
- Only uses code from `vendor/` directory
- No external dependency pulls
- No network requests during build

### Development Build (Faster Iteration)

```bash
# Without -mod=vendor (uses go.mod, but still local)
go build ./cmd/kumo
go build ./cmd/suzu
```

## Directory Structure

```
go/
├── go.mod              # Module definition (local: "recon")
├── go.sum              # Dependency checksums (locks versions)
├── vendor/             # Vendored dependencies (local copies)
│   └── golang.org/
│       └── x/
│           └── net/
│               └── html/  # HTML parser (vendored)
├── cmd/
│   ├── kumo/
│   │   └── main.go     # Kumo daemon entry point
│   └── suzu/
│       └── main.go     # Suzu daemon entry point
├── internal/
│   ├── kumo/           # Kumo spider implementation
│   ├── suzu/           # Suzu enumerator implementation
│   ├── api/            # Django API client
│   └── common/         # Shared daemon utilities
└── pkg/
    └── htmlparser/     # HTML parsing utilities
```

## Import Paths (All Local)

All imports use local `recon/...` paths:

```go
import (
    "recon/internal/api"
    "recon/internal/common"
    "recon/internal/kumo"
    "recon/internal/suzu"
)
```

**No external URLs** like `github.com/...` or `gitlab.com/...`

## Updating Dependencies

### When You Need to Add a Dependency

1. **Add it**:
```bash
go get golang.org/x/net/html
```

2. **Vendor it** (create local copy):
```bash
go mod vendor
```

3. **Review vendor/**:
```bash
ls -la vendor/golang.org/x/net/html/
# Review the code that was added
```

4. **Build with vendor**:
```bash
go build -mod=vendor ./cmd/kumo
```

5. **Commit vendor/**:
```bash
git add vendor/ go.mod go.sum
git commit -m "Add HTML parser (vendored)"
```

### When You Need to Update a Dependency

1. **Update it**:
```bash
go get -u golang.org/x/net/html
```

2. **Re-vendor**:
```bash
go mod vendor
```

3. **Review changes**:
```bash
git diff vendor/
```

4. **Test build**:
```bash
go build -mod=vendor ./cmd/kumo
```

5. **Commit updates**:
```bash
git add vendor/ go.mod go.sum
git commit -m "Update HTML parser to vX.Y.Z"
```

## CI/CD Integration

### Build Script

```bash
#!/bin/bash
# build-go-daemons.sh

set -e

cd go

# Ensure vendor/ exists
if [ ! -d "vendor" ]; then
    echo "Error: vendor/ directory not found"
    echo "Run: go mod vendor"
    exit 1
fi

# Build with vendored deps only
echo "Building Kumo daemon..."
go build -mod=vendor -o ../bin/kumo ./cmd/kumo

echo "Building Suzu daemon..."
go build -mod=vendor -o ../bin/suzu ./cmd/suzu

echo "✅ Build complete"
```

### Dockerfile Integration

```dockerfile
# Install Go
RUN apt-get update && apt-get install -y golang-go

# Copy Go code
COPY go/ /app/go/

# Build Go daemons (with vendor)
WORKDIR /app/go
RUN go build -mod=vendor -o ../bin/kumo ./cmd/kumo
RUN go build -mod=vendor -o ../bin/suzu ./cmd/suzu

# Cleanup (optional - remove Go if not needed at runtime)
RUN apt-get remove -y golang-go && apt-get autoremove -y
```

## Verification

### Check for External Dependencies

```bash
# Should return nothing (no external URLs)
grep -r "github.com\|gitlab.com" go/ --exclude-dir=vendor

# Check go.mod (should only have module, go version, require)
cat go.mod
```

### Verify Vendor Directory

```bash
# List all vendored dependencies
find vendor/ -type d -maxdepth 3

# Check vendor integrity
go mod verify
```

## Troubleshooting

### "cannot find package" Error

**Problem**: Go can't find a package

**Solution**: 
1. Check import path uses `recon/...` (not external URL)
2. Ensure package exists in `internal/` or `pkg/`
3. Run `go mod tidy` to clean up

### "module not found" Error

**Problem**: Missing dependency

**Solution**:
1. Add dependency: `go get <package>`
2. Vendor it: `go mod vendor`
3. Build with vendor: `go build -mod=vendor`

### Build Fails Without `-mod=vendor`

**Problem**: Go tries to pull external dependencies

**Solution**: Always use `-mod=vendor` flag:
```bash
go build -mod=vendor ./cmd/kumo
```

Or set environment variable:
```bash
export GOFLAGS=-mod=vendor
go build ./cmd/kumo
```

## Best Practices

1. ✅ **Always vendor**: Run `go mod vendor` after adding deps
2. ✅ **Build with vendor**: Use `-mod=vendor` flag
3. ✅ **Commit vendor/**: Include in repository
4. ✅ **Review vendor/**: Check what code is included
5. ✅ **Minimal deps**: Only add what's necessary
6. ✅ **Local paths**: Use `recon/...` imports only
7. ✅ **Lock versions**: Commit `go.sum` for reproducibility

