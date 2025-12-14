# Fix Status - ExecuteWithResults Segfault

## Date: November 5, 2024

### Status: ⚠️ IN PROGRESS

**Issue**: Segfault in ExecuteWithResults due to nil templates and inputProvider

**PinkiePie Consultation**: ✅ Completed
- PinkiePie CLI invoked
- Analysis provided
- Fix requirements identified
- Implementation in progress

### Current Implementation Attempt

**Added Imports**:
- `github.com/projectdiscovery/nuclei/v3/pkg/catalog`
- `github.com/projectdiscovery/nuclei/v3/pkg/input`
- `github.com/projectdiscovery/nuclei/v3/pkg/templates`

**Challenges**:
- API functions not matching expected signatures
- Need to find correct way to:
  1. Load templates from `/home/ego/nuclei-templates`
  2. Create `provider.InputProvider` from `options.Targets`

### Next Steps

1. Research correct Nuclei v3 API for:
   - Template loading
   - Input provider creation

2. Test compilation with correct API calls

3. Verify fix resolves segfault

### Files Modified

- `bridge.go` - Added imports and template/provider loading code (in progress)













