# Critical Issue: Segfault in ExecuteWithResults

## Date: November 5, 2024

### 🔴 CRITICAL: Segfault Detected

**Error**: 
```
panic: runtime error: invalid memory address or nil pointer dereference
[signal SIGSEGV: segmentation violation code=0x1 addr=0x20 pc=0x7f8255a89277]

goroutine 27 [running]:
github.com/projectdiscovery/nuclei/v3/pkg/core.(*Engine).ExecuteScanWithOpts(0xc001081c20, {0x7f8256c66e80, 0x7f82583fbc40}, {0x0, 0x0, 0x0}, {0x0, 0x0}, 0x0)
	/home/ego/go/pkg/mod/github.com/projectdiscovery/nuclei/v3@v3.4.10/pkg/core/execute_options.go:38 +0xd7
```

### Root Cause

**ExecuteWithResults() requires non-nil templates and input provider**

- Current code passes `nil, nil` for templates and input provider
- Engine expects actual instances, not nil
- Engine does NOT automatically load from Options when nil is passed
- This causes a nil pointer dereference at line 38 in execute_options.go

### Current Implementation Issue

```go
// ❌ THIS CAUSES SEGFAULT:
result := engine.ExecuteWithResults(ctx, nil, nil, callback)
```

**Problem**: 
- `ExecuteWithResults()` signature: `ExecuteWithResults(ctx, templates []*templates.Template, inputProvider provider.InputProvider, callback func(*output.ResultEvent)) *atomic.Bool`
- Both `templates` and `inputProvider` must be non-nil
- Engine does not load from `Options.Templates` or `Options.Targets` when nil is passed

### Solution Required

**We MUST implement proper template loading and input provider creation:**

1. **Load Templates**:
   - Load templates from `/home/ego/nuclei-templates`
   - Use `templates.Load()` or similar API
   - Create `[]*templates.Template` slice

2. **Create Input Provider**:
   - Create input provider from targets
   - Use `provider` package or similar
   - Create `provider.InputProvider` instance

3. **Pass to ExecuteWithResults**:
   ```go
   result := engine.ExecuteWithResults(ctx, loadedTemplates, inputProvider, callback)
   ```

### Workaround Status

**Current**: Scans complete in 0.01s with 0 vulnerabilities (no actual execution)

**Why**: Goroutine exits immediately because ExecuteWithResults segfaults

### Next Steps

1. **Implement Template Loading**:
   - Research Nuclei v3 template loading API
   - Load templates from `/home/ego/nuclei-templates`
   - Filter by Options.Templates, Tags, Severities

2. **Implement Input Provider**:
   - Research Nuclei v3 input provider API
   - Create provider from Options.Targets
   - Handle multiple targets

3. **Fix ExecuteWithResults Call**:
   - Pass actual template and provider instances
   - Handle errors properly
   - Test with real scans

### Status

**Current**: ⚠️ **BLOCKED** - Segfault prevents actual scanning  
**Priority**: 🔴 **HIGH** - Must fix before production use  
**Impact**: Bridge loads but cannot execute scans

---

**Note**: This explains why scans complete in 0.01s with 0 vulnerabilities - the goroutine crashes immediately, causing the defer to mark scan as completed.













