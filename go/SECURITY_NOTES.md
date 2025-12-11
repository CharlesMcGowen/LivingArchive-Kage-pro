# Security Notes: Local Go Module Setup

## Why Local Imports Only?

**Supply Chain Security**: External dependencies from GitHub/GitLab can be:
- Modified by maintainers (legitimate or compromised accounts)
- Hijacked (typosquatting, dependency confusion attacks)
- Updated with vulnerabilities or backdoors
- Removed or made unavailable

## Our Approach: 100% Local

### 1. Local Module Path
- Module name: `recon` (not `github.com/...`)
- All imports use `recon/internal/...`
- No external module URLs in code

### 2. Vendored Dependencies
- All external deps are vendored in `vendor/` directory
- Versions are locked in `go.sum`
- Code is committed to repository
- No runtime dependency pulls

### 3. Minimal Dependencies
- Use Go standard library as much as possible
- Only add external deps when absolutely necessary
- Prefer `golang.org/x/...` (official Go extensions) over third-party
- Review all vendored code before committing

### 4. Build Flags
- Always build with `-mod=vendor` flag
- Prevents Go from pulling external dependencies
- Ensures only local/vendored code is used

## Security Checklist

- [ ] All imports use local `recon/...` paths
- [ ] No `github.com`, `gitlab.com`, or external URLs in imports
- [ ] All dependencies are vendored (`go mod vendor`)
- [ ] `vendor/` directory is committed to repository
- [ ] Build scripts use `-mod=vendor` flag
- [ ] All vendored code is reviewed
- [ ] `go.sum` is committed (locks dependency versions)
- [ ] CI/CD builds use `-mod=vendor`

## Dependency Review Process

Before adding any external dependency:

1. **Evaluate necessity**: Can we use standard library?
2. **Check source**: Is it from official Go project?
3. **Review code**: Read the dependency source code
4. **Vendor it**: `go mod vendor` to create local copy
5. **Review vendor/**: Check what was actually vendored
6. **Commit vendor/**: Include in repository for audit trail

## Example: Adding HTML Parser

```bash
# 1. Add dependency
go get golang.org/x/net/html

# 2. Vendor it (creates local copy)
go mod vendor

# 3. Review what was added
ls -la vendor/golang.org/x/net/

# 4. Build with vendor flag
go build -mod=vendor ./cmd/kumo

# 5. Commit vendor/ directory
git add vendor/ go.mod go.sum
git commit -m "Add HTML parser (vendored)"
```

## Benefits

✅ **No external pulls**: All code is local  
✅ **Version locked**: Dependencies can't change  
✅ **Auditable**: All code is in your repository  
✅ **Offline builds**: Can build without internet  
✅ **Supply chain security**: No risk of external modification  
✅ **Reproducible**: Same build every time  

## Trade-offs

⚠️ **Larger repository**: Vendor directory adds size  
⚠️ **Manual updates**: Must manually update vendored deps  
⚠️ **More maintenance**: Need to review and update dependencies  

**But**: Security and control are worth it for production systems.

