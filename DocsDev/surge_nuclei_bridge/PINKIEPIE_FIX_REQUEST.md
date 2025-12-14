# PinkiePie Fix Request - Surge Nuclei Memory Bridge Segfault

## Issue Summary

**Critical Bug**: Segfault in `ExecuteWithResults()` causing scans to fail immediately

**Location**: `bridge.go` line 329

**Error**: 
```
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x20 pc=0x7f8255a89277]
github.com/projectdiscovery/nuclei/v3/pkg/core.(*Engine).ExecuteScanWithOpts(...)
	/home/ego/go/pkg/mod/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/core/execute_options.go:38 +0xd7
```

## Root Cause

**ExecuteWithResults() requires non-nil templates and input provider**

Current code (line 329):
```go
result := engine.ExecuteWithResults(ctx, nil, nil, callback)
```

**Problem**: 
- Passing `nil, nil` for templates and input provider
- Engine expects actual instances, not nil
- Engine does NOT auto-load from Options when nil is passed

## Required Fix

### 1. Load Templates from `/home/ego/nuclei-templates`

**Requirements**:
- Load templates using Nuclei v3 API
- Filter by `options.Templates`, `options.Tags`, `options.Severities`
- Create `[]*templates.Template` slice
- Handle errors gracefully

**Template Path**: `/home/ego/nuclei-templates`

**Options available**:
- `options.Templates` - goflags.StringSlice (template paths/filters)
- `options.Tags` - goflags.StringSlice
- `options.Severities` - severity.Severities

### 2. Create Input Provider from Targets

**Requirements**:
- Create input provider from `options.Targets`
- Handle single target: `target` (string)
- Create `provider.InputProvider` instance (or equivalent)
- Must be non-nil for ExecuteWithResults

**Target**: Already in `options.Targets` as `goflags.StringSlice([]string{target})`

### 3. Fix ExecuteWithResults Call

**Change from**:
```go
result := engine.ExecuteWithResults(ctx, nil, nil, callback)
```

**Change to**:
```go
result := engine.ExecuteWithResults(ctx, loadedTemplates, inputProvider, callback)
```

## Code Context

**File**: `bridge.go`
**Function**: `StartScan()` 
**Location**: Lines 314-329 (goroutine)

**Current implementation**:
```go
log.Printf("🚀 Starting engine.Execute() for %s", target)
ctx := context.Background()

// ExecuteWithResults requires: context, templates, input provider, and callback
// The engine requires actual template and input provider instances, not nil
// We'll use the engine's Execute method which handles loading internally
// Execute() loads templates from Options.Templates and uses Options.Targets

callback := func(event *output.ResultEvent) {
    _ = outputWriter.Write(event) // Ignore error for callback
}

// Use Execute() instead of ExecuteWithResults() - it handles template/provider loading
// Execute() signature: Execute(ctx context.Context) *atomic.Bool
result := engine.Execute(ctx)
```

**Problem**: This code was attempted but `Execute()` also requires templates and provider.

## Nuclei v3 API Notes

**Available packages**:
- `github.com/projectdiscovery/nuclei/v3/pkg/core` - Engine
- `github.com/projectdiscovery/nuclei/v3/pkg/templates` - Template loading
- `github.com/projectdiscovery/nuclei/v3/pkg/catalog` - Template catalog
- `github.com/projectdiscovery/nuclei/v3/pkg/input` - Input helper
- `github.com/projectdiscovery/nuclei/v3/pkg/types` - Options

**Engine.ExecuteWithResults signature**:
```go
func (e *Engine) ExecuteWithResults(
    ctx context.Context, 
    templatesList []*templates.Template, 
    inputProvider provider.InputProvider, 
    callback func(*output.ResultEvent)
) *atomic.Bool
```

**Both `templatesList` and `inputProvider` must be non-nil**.

## Expected Behavior After Fix

1. Templates load from `/home/ego/nuclei-templates`
2. Input provider created from target
3. ExecuteWithResults called with actual instances
4. Scan runs successfully
5. Vulnerabilities streamed via callback
6. No segfault

## Additional Context

- Go 1.24.9 installed
- Nuclei v3.4.10
- Templates path exists: `/home/ego/nuclei-templates`
- Bridge otherwise working (initialization, state management OK)
- Callback function working (EventStreamWriter.Write)

## Files to Modify

- `bridge.go` - Fix ExecuteWithResults call (lines 314-329)

## Testing

After fix, test with:
```bash
docker exec ego-surge python3 [test script]
```

Should see:
- Scan runs for > 1 second
- Requests being made
- Vulnerabilities found (if any)
- No segfault

---

**PinkiePie, please implement template loading and input provider creation to fix this segfault!**













