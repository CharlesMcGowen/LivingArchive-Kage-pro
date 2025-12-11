# Build Instructions

## Prerequisites

1. **Install Go** (if not already installed):
   ```bash
   sudo apt install golang-go
   # or
   sudo snap install go
   ```

2. **Verify Go installation**:
   ```bash
   go version
   # Should show: go version go1.21.x or later
   ```

## Setup

1. **Navigate to go directory**:
   ```bash
   cd /media/ego/328010BE80108A8D2/github_public/LivingArchive-Kage-pro/go
   ```

2. **Add dependencies**:
   ```bash
   go get golang.org/x/net/html
   ```

3. **Vendor dependencies** (create local copies):
   ```bash
   go mod vendor
   ```

4. **Verify setup**:
   ```bash
   go mod verify
   ```

## Building

### Build Kumo Daemon

```bash
go build -mod=vendor -o ../bin/kumo ./cmd/kumo
```

### Build Suzu Daemon

```bash
go build -mod=vendor -o ../bin/suzu ./cmd/suzu
```

### Build Both

```bash
mkdir -p ../bin
go build -mod=vendor -o ../bin/kumo ./cmd/kumo
go build -mod=vendor -o ../bin/suzu ./cmd/suzu
```

## Testing

### Test API Client

```bash
# Run with test mode
go run -mod=vendor ./cmd/kumo -api-base=http://127.0.0.1:9000
```

### Test Individual Components

```bash
# Test compilation
go build -mod=vendor ./internal/api
go build -mod=vendor ./internal/kumo
go build -mod=vendor ./internal/suzu
```

## Troubleshooting

### "cannot find package" Error

**Problem**: Go can't find a package

**Solution**:
1. Ensure you're in the `go/` directory
2. Run `go mod tidy`
3. Run `go mod vendor`
4. Build with `-mod=vendor` flag

### "module not found" Error

**Problem**: Missing dependency

**Solution**:
```bash
go get golang.org/x/net/html
go mod vendor
```

### Build Fails Without `-mod=vendor`

**Problem**: Go tries to pull external dependencies

**Solution**: Always use `-mod=vendor`:
```bash
go build -mod=vendor ./cmd/kumo
```

Or set environment variable:
```bash
export GOFLAGS=-mod=vendor
go build ./cmd/kumo
```

### Import Errors

**Problem**: "package recon/internal/... is not in std"

**Solution**: 
- Ensure you're building from the `go/` directory
- Check that `go.mod` has `module recon` at the top
- Verify import paths use `recon/...` (not external URLs)

## Docker Build

Add to `docker/Dockerfile`:

```dockerfile
# Install Go
RUN apt-get update && apt-get install -y golang-go

# Build Go daemons
WORKDIR /app/go
COPY go/ .
RUN go mod vendor
RUN go build -mod=vendor -o ../bin/kumo ./cmd/kumo
RUN go build -mod=vendor -o ../bin/suzu ./cmd/suzu

# Cleanup (optional)
RUN apt-get remove -y golang-go && apt-get autoremove -y
```

## Next Steps After Build

1. **Test daemons**:
   ```bash
   ./bin/kumo -api-base=http://127.0.0.1:9000
   ./bin/suzu -api-base=http://127.0.0.1:9000
   ```

2. **Update docker-compose.yml**:
   ```yaml
   kumo-daemon:
     command: /app/bin/kumo -api-base=http://django-server:9000
   
   suzu-daemon:
     command: /app/bin/suzu -api-base=http://django-server:9000
   ```

3. **Monitor logs**:
   ```bash
   docker-compose logs -f kumo-daemon
   docker-compose logs -f suzu-daemon
   ```

