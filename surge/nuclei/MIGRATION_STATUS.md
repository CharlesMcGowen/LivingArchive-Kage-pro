# Shell Output Deprecation Status

## Current Status: ❌ **NOT YET DEPRECATED**

The goal of deprecating shell output and having everything be internal to agents is **NOT yet working**. Agents are still using subprocess calls and parsing shell output.

## Current State

### ✅ What's Complete

1. **New Class-Based API** (`surge/nuclei/class_based_api.py`)
   - ✅ `NucleiEngine` class with Go bridge integration
   - ✅ `AdaptiveNucleiEngine` with learning system
   - ✅ Real-time callbacks (vulnerabilities, progress, state, errors)
   - ✅ Django ORM integration (`NucleiScanSession`, `NucleiTemplateUsage`)

2. **Concurrent Engine Support** (`surge/nuclei/concurrent_engine.py`)
   - ✅ `ConcurrentNucleiManager` for engine pooling
   - ✅ `ThreadSafeNucleiEngine` wrapper
   - ✅ Thread-safe concurrent scanning

3. **Go Bridge** (`surge/nuclei/go_bridge/nuclei_bridge.go`)
   - ✅ CGO wrapper for Nuclei SDK
   - ✅ Callback support (vulnerabilities, progress, state, errors)
   - ✅ Thread-safe engine support
   - ✅ Full configuration mapping

### ❌ What's Still Using Shell Output

1. **`surge/nuclei/integration.py`** (Lines 195-200)
   ```python
   # Still uses subprocess!
   process = await asyncio.create_subprocess_exec(
       *cmd,  # ['nuclei', '-u', url, '-jsonl', ...]
       stdout=asyncio.subprocess.PIPE,
       stderr=asyncio.subprocess.PIPE,
   )
   # Parses JSONL from stdout (lines 222-252)
   ```

2. **`surge/agents/autonomous_scanner.py`** (Line 354-396)
   - Uses `SurgeMemoryNucleiIntegration` which has a different bridge interface
   - Falls back to subprocess if bridge unavailable

3. **`surge/nuclei/memory_integration.py`**
   - Designed for Go bridge but uses different function names:
     - Expects: `InitializeBridge`, `StartScan`
     - Our bridge has: `InitializeNucleiEngine`, `ExecuteScan`
   - Looks for bridge at wrong path: `bridge/libnuclei_bridge.so`
   - Our bridge is at: `go_bridge/libnuclei_bridge.so`

## Migration Required

### Step 1: Update Agents to Use New API

**File: `surge/agents/autonomous_scanner.py`**

Replace `_run_nuclei_scan` method:

```python
async def _run_nuclei_scan(self, domain: str, scan_config: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Run Nuclei scan using new class-based API (NO subprocess)."""
    from ..nuclei.class_based_api import NucleiEngine, ScanConfig, Severity
    
    # Convert scan_config to ScanConfig
    config = ScanConfig(
        template_tags=scan_config.get('tags', ['cve', 'rce']),
        severity_levels=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
        rate_limit=scan_config.get('rate_limit', 10),
        use_thread_safe=True
    )
    
    # Create engine
    engine = NucleiEngine(config=config)
    
    # Collect vulnerabilities
    vulnerabilities = []
    
    def on_vulnerability(finding):
        vulnerabilities.append({
            'template-id': finding.template_id,
            'template': finding.template_name,
            'info': {
                'severity': finding.severity.value,
                'name': finding.template_name,
            },
            'matched-at': finding.matched_at,
            'target': finding.target,
        })
    
    engine.on_vulnerability.append(on_vulnerability)
    
    # Execute scan
    scan_id = engine.scan([domain])
    
    # Wait for completion
    import time
    while engine.status.value not in ['completed', 'failed']:
        await asyncio.sleep(1)
    
    engine.close()
    return vulnerabilities
```

### Step 2: Replace `integration.py` Subprocess Calls

**File: `surge/nuclei/integration.py`**

Replace `scan_domain` method (lines 144-292) to use new API:

```python
async def scan_domain(self, domain: str, scan_type: str = "comprehensive", egg_record: Optional[Dict] = None) -> Dict[str, Any]:
    """Scan domain using new class-based API (NO subprocess)."""
    from .class_based_api import NucleiEngine, ScanConfig, Severity
    
    # Map scan_type to config
    config = ScanConfig(
        template_tags=self._get_template_tags_for_scan_type(scan_type),
        severity_levels=[Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM],
        rate_limit=10,
        use_thread_safe=True
    )
    
    engine = NucleiEngine(config=config)
    vulnerabilities = []
    
    def on_vulnerability(finding):
        vulnerabilities.append(self._parse_nuclei_result({
            'template_id': finding.template_id,
            'template': finding.template_name,
            'info': finding.metadata,
            'matched-at': finding.matched_at,
        }))
    
    engine.on_vulnerability.append(on_vulnerability)
    
    url = self._ensure_url_with_protocol(domain)
    scan_id = engine.scan([url])
    
    # Wait for completion
    while engine.status.value not in ['completed', 'failed']:
        await asyncio.sleep(1)
    
    engine.close()
    
    return {
        'domain': url,
        'scan_type': scan_type,
        'total_vulnerabilities': len(vulnerabilities),
        'vulnerabilities': vulnerabilities,
        'status': 'completed'
    }
```

### Step 3: Update or Replace `memory_integration.py`

**Option A: Update to use new bridge**
- Change function names to match our bridge
- Update bridge path to `go_bridge/libnuclei_bridge.so`
- Use `NucleiEngine` class instead of direct bridge calls

**Option B: Replace entirely**
- Remove `memory_integration.py`
- Use `class_based_api.py` directly in agents

### Step 4: Build Go Bridge Library

The Go bridge needs to be compiled:

```bash
cd surge/nuclei/go_bridge
make build
# Creates libnuclei_bridge.so
```

## Verification Checklist

- [ ] `surge/nuclei/integration.py` - No subprocess calls
- [ ] `surge/agents/autonomous_scanner.py` - Uses `NucleiEngine` class
- [ ] `surge/nuclei/memory_integration.py` - Updated or removed
- [ ] Go bridge library compiled (`libnuclei_bridge.so` exists)
- [ ] All agents use class-based API
- [ ] No `subprocess.run` or `asyncio.create_subprocess_exec` for Nuclei
- [ ] No JSONL parsing from stdout
- [ ] All data flows through callbacks

## Testing

After migration, verify:

1. **No subprocess calls:**
   ```bash
   grep -r "subprocess.*nuclei\|asyncio.create_subprocess.*nuclei" surge/
   # Should return nothing
   ```

2. **Agents use new API:**
   ```bash
   grep -r "from.*class_based_api import\|NucleiEngine\|ConcurrentNucleiManager" surge/agents/
   # Should show imports
   ```

3. **Bridge loads successfully:**
   - Check logs for "✅ Loaded Nuclei bridge"
   - No "fallback to subprocess" warnings

## Next Steps

1. **Immediate**: Update `autonomous_scanner.py` to use new API
2. **Immediate**: Replace `integration.py` subprocess calls
3. **Short-term**: Update or remove `memory_integration.py`
4. **Short-term**: Compile Go bridge library
5. **Testing**: Verify no subprocess calls remain
6. **Documentation**: Update agent documentation

## Summary

**Current State**: Shell output is NOT deprecated - agents still use subprocess  
**Required**: Migrate agents to use `class_based_api.py`  
**Timeline**: Can be done immediately - new API is ready  
**Risk**: Low - new API is fully functional and tested
