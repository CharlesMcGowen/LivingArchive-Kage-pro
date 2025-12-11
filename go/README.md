# Recon Go Daemons

Go implementation of Kumo and Suzu daemons with **100% local imports** for security.

## Security

- ✅ All imports use local `recon/...` paths (no external URLs)
- ✅ All dependencies are vendored in `vendor/` directory
- ✅ Builds use `-mod=vendor` flag (no external pulls)
- ✅ All code is committed to repository (auditable)

## Quick Start

```bash
# Initialize (already done)
go mod init recon

# Add minimal dependencies
go get golang.org/x/net/html

# Vendor dependencies (create local copies)
go mod vendor

# Build daemons
go build -mod=vendor ./cmd/kumo
go build -mod=vendor ./cmd/suzu
```

## Structure

```
go/
├── cmd/
│   ├── kumo/          # Kumo daemon entry point
│   └── suzu/          # Suzu daemon entry point
├── internal/
│   ├── kumo/          # Kumo spider implementation
│   ├── suzu/          # Suzu enumerator implementation
│   ├── api/           # Django API client
│   └── common/        # Shared daemon utilities
├── pkg/
│   └── htmlparser/    # HTML parsing utilities
└── vendor/            # Vendored dependencies (committed)
```

## Building

Always use `-mod=vendor` flag:

```bash
go build -mod=vendor ./cmd/kumo
go build -mod=vendor ./cmd/suzu
```

## Documentation

- `SETUP.md` - Detailed setup guide
- `SECURITY_NOTES.md` - Security rationale
- `../GOLANG_CONVERSION_PLAN.md` - Full conversion plan

