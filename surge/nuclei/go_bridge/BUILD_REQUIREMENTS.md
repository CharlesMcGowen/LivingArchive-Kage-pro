# Go Bridge Build Requirements

## Issue: Go Version Mismatch

**Current System**: Go 1.18.1  
**Required**: Go 1.21+ (for Nuclei v3)

Nuclei v3 uses Go standard library packages introduced in Go 1.21:
- `cmp` (constraints)
- `crypto/ecdh`, `crypto/hkdf`, `crypto/mlkem`, `crypto/sha3`
- `iter`
- `log/slog`
- `maps`
- `math/rand/v2`
- `slices`

## Solutions

### Option 1: Upgrade Go (Recommended)

Install Go 1.21 or later:

```bash
# Using snap (if available)
sudo snap install go --classic

# Or download from https://go.dev/dl/
wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
export PATH=/usr/local/go/bin:$PATH

# Verify
go version  # Should show go1.21.x or later
```

Then rebuild:
```bash
cd surge/nuclei/go_bridge
make build
```

### Option 2: Use Go Version Manager (g)

```bash
# Install g (Go version manager)
curl -sSL https://git.io/g-install | sh -s

# Install and use Go 1.21
g install 1.21.0
g 1.21.0

# Verify
go version

# Build
cd surge/nuclei/go_bridge
make build
```

### Option 3: Use Docker (Temporary)

Build in a Docker container with Go 1.21:

```bash
docker run --rm -v $(pwd):/work -w /work/surge/nuclei/go_bridge golang:1.21 make build
```

### Option 4: Downgrade Nuclei (Not Recommended)

If upgrading Go is not possible, you would need to use an older Nuclei version that supports Go 1.18, but this would lose v3 features.

## Verification

After upgrading Go, verify the build:

```bash
cd surge/nuclei/go_bridge
make build
ls -lh libnuclei_bridge.so
```

The library should be created at `surge/nuclei/go_bridge/libnuclei_bridge.so`.

## Current Status

❌ **Build Blocked**: Go version too old  
✅ **Code Complete**: All migration and Phase 3 code is ready  
⏳ **Waiting**: Go upgrade required to build bridge

Once Go is upgraded, the build should complete successfully and the Python API will automatically load the bridge.



