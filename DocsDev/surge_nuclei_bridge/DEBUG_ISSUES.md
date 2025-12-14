# Debug Issues Found

## Problem: Scan Not Running

### Symptoms:
- `StartScan()` returns success
- Scan state shows `is_running: None/False` immediately
- No requests, no vulnerabilities, no progress
- Scan completes in 0.01-0.13 seconds

### Root Cause Analysis:

1. **Engine.Execute() might be failing silently**
   - No error logs visible
   - Goroutine completes immediately
   - Scan state not updated

2. **Template Configuration Issue**
   - Templates field might not be configured correctly
   - Need to check Nuclei v3 API for template loading
   - Template paths might need different format

3. **Missing Template Directory Configuration**
   - Nuclei v3 might need `TemplateDir` or `TemplatesDirectory` option
   - Templates might not be loading from `/home/ego/nuclei-templates`

4. **Engine Options Missing Required Fields**
   - Some required options might be nil
   - TemplateLoader, WorkflowLoader might need to be set

### Next Steps:
1. Add debug logging to engine.Execute() goroutine
2. Check if engine.Execute() is actually being called
3. Verify template loading mechanism for Nuclei v3
4. Add error capture and logging
5. Check if engine needs additional initialization

