# Build Requirements for Surge Nuclei Memory Bridge

## Current Issue: Go Version Mismatch

### Problem
- **Nuclei v3.4.10** requires Go >= 1.24.1
- Current test environment: Go 1.21, 1.23 (insufficient)
- Source code has full implementation but cannot compile

### Solution Options

#### Option 1: Upgrade Go (Recommended)
```bash
# Install Go 1.24+ on host system
# Then compile:
cd /mnt/webapps-nvme/artificial_intelligence/personalities/security/surge/surge_nuclei_memory_bridge
go build -buildmode=c-shared -o libnuclei_bridge.so bridge.go
docker cp libnuclei_bridge.so ego-surge:/app/artificial_intelligence/personalities/security/surge/surge_nuclei_memory_bridge/
```

#### Option 2: Use Go 1.24+ Docker Image
```bash
# Use golang:1.24-alpine (when available) or build from source
docker run --rm -v "$(pwd):/build" -w /build golang:1.24-alpine \
  sh -c "apk add --no-cache gcc musl-dev && \
         go mod download && \
         CGO_ENABLED=1 go build -buildmode=c-shared -o libnuclei_bridge.so bridge.go"
```

#### Option 3: Downgrade Nuclei (Not Recommended)
```bash
# Modify go.mod to use older Nuclei version
go get github.com/projectdiscovery/nuclei/v3@v3.3.7
# Recompile with Go 1.23
```

### Current Library Status
- **File**: `libnuclei_bridge.so` (102MB, Nov 2, 2024)
- **Status**: OLD VERSION (pre-PinkiePie improvements)
- **Source**: `bridge.go` (Nov 5, 2024 - UPDATED)
- **Action Needed**: Recompile source with Go 1.24+

### After Compilation
1. Copy to container: `docker cp libnuclei_bridge.so ego-surge:/app/.../libnuclei_bridge.so`
2. Restart Surge or reload Python module
3. Test with: `python3 test_memory_cleanup.py`
4. Verify vulnerabilities are found

