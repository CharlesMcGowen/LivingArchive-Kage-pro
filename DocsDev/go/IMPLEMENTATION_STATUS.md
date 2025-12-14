# Implementation Status

## ✅ Completed

- [x] Go module structure created
- [x] Local module path: `recon` (no external URLs)
- [x] Directory structure: `cmd/`, `internal/`, `pkg/`
- [x] Main entry points: `cmd/kumo/main.go`, `cmd/suzu/main.go`
- [x] Type definitions: `internal/kumo/types.go`, `internal/suzu/types.go`, `internal/api/types.go`
- [x] Daemon lifecycle: `internal/common/daemon.go`
- [x] Documentation: `README.md`, `SETUP.md`, `SECURITY_NOTES.md`

## 🚧 TODO: Implementation

### Kumo Spider (`internal/kumo/`)

- [ ] `spider.go` - Core spidering logic
  - [ ] HTTP client setup with timeout/retry
  - [ ] BFS traversal with depth limit
  - [ ] Request/response handling
  - [ ] Metadata extraction
  - [ ] RequestMetaData creation via API

- [ ] `extractor.go` - HTML link extraction
  - [ ] HTML parsing (using `golang.org/x/net/html`)
  - [ ] Link extraction from anchor tags
  - [ ] Relative to absolute URL conversion
  - [ ] Same-domain filtering

- [ ] `metadata.go` - RequestMetaData creation
  - [ ] Metadata struct creation
  - [ ] API submission logic

### Suzu Enumerator (`internal/suzu/`)

- [ ] `enumerator.go` - Directory enumeration
  - [ ] Tool selection (dirsearch vs ffuf)
  - [ ] Result parsing
  - [ ] Error handling

- [ ] `tools.go` - Tool execution
  - [ ] Dirsearch subprocess execution
  - [ ] FFuf subprocess execution
  - [ ] Output parsing (JSON/text)
  - [ ] Tool availability checking

### API Client (`internal/api/`)

- [ ] `client.go` - Django API communication
  - [ ] HTTP client setup
  - [ ] GET `/api/daemon/{personality}/eggrecords/`
  - [ ] POST `/api/daemon/spider/`
  - [ ] POST `/api/daemon/enumeration/`
  - [ ] GET `/api/daemon/{personality}/health/`
  - [ ] Exponential backoff retry logic
  - [ ] JSON request/response handling

### Common Utilities (`internal/common/`)

- [x] `daemon.go` - Daemon lifecycle (basic structure done)
  - [ ] Signal handling improvements
  - [ ] Graceful shutdown with timeout
  - [ ] Task tracking improvements

- [ ] `config.go` - Configuration management
  - [ ] Environment variable parsing
  - [ ] Config struct definition
  - [ ] Default values

- [ ] `logger.go` - Logging utilities
  - [ ] Structured logging
  - [ ] Log levels
  - [ ] Log formatting

### HTML Parser (`pkg/htmlparser/`)

- [ ] `parser.go` - HTML parsing utilities
  - [ ] Link extraction
  - [ ] Form extraction
  - [ ] Script extraction
  - [ ] Image extraction

## 📋 Next Steps

1. **Install Go** (if not already installed):
   ```bash
   sudo apt install golang-go
   # or
   sudo snap install go
   ```

2. **Initialize module** (already done):
   ```bash
   cd go
   go mod init recon
   ```

3. **Add dependencies**:
   ```bash
   go get golang.org/x/net/html  # HTML parsing
   go mod vendor                 # Vendor dependencies
   ```

4. **Implement core functionality**:
   - Start with API client (needed by everything)
   - Then implement spider/extractor
   - Then implement enumerator/tools

5. **Test incrementally**:
   - Test API client against Django
   - Test spider with single URL
   - Test enumerator with single target

6. **Build and deploy**:
   ```bash
   go build -mod=vendor ./cmd/kumo
   go build -mod=vendor ./cmd/suzu
   ```

## 🔒 Security Checklist

- [x] Module uses local path `recon` (no external URLs)
- [ ] All dependencies are vendored (`go mod vendor`)
- [ ] Build uses `-mod=vendor` flag
- [ ] No external dependency pulls at runtime
- [ ] All vendored code reviewed
- [ ] `go.sum` committed (locks versions)

## 📝 Notes

- All imports use `recon/internal/...` paths (local only)
- Placeholder implementations return "not implemented yet" errors
- Type definitions are complete and match Python structures
- Main entry points have full daemon loop structure
- Ready for incremental implementation

