# Surge Class-Based Nuclei API

## Overview

This implementation replaces Nuclei command-line arguments with a class-based Python API, providing:

- **Direct code-level control** - No subprocess calls or shell parsing
- **Learning system integration** - Django ORM tracks template usage and effectiveness
- **On-the-fly adaptations** - Real-time scan adjustments based on feedback
- **Agent coordination** - Surge, Koga, and Bugsy can control scans programmatically

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│              Python Class-Based API                     │
│  (NucleiEngine, AdaptiveNucleiEngine, ScanConfig)      │
└──────────────────┬──────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│              Go Bridge (CGO)                             │
│  (nuclei_bridge.go - calls Nuclei library directly)    │
└──────────────────┬──────────────────────────────────────┘
                    │
                    ▼
┌─────────────────────────────────────────────────────────┐
│              Nuclei Library (Go)                          │
│  (github.com/projectdiscovery/nuclei/v3/lib)            │
└─────────────────────────────────────────────────────────┘
```

## Components

### 1. Django ORM Models (`surge/models.py`)

- **NucleiTemplateUsage** - Tracks template performance and effectiveness
- **NucleiScanSession** - Tracks scan sessions and adaptations
- **NucleiAdaptationRule** - Defines learning rules for adaptive scanning
- **NucleiAgentControl** - Real-time control interface for agents

### 2. Go Bridge (`nuclei/go_bridge/`)

- **nuclei_bridge.go** - CGO wrapper that calls Nuclei library
- **nuclei_bridge.h** - C header file for Python ctypes
- **Makefile** - Build script for shared library

### 3. Python API (`nuclei/class_based_api.py`)

- **NucleiEngine** - Base engine class
- **AdaptiveNucleiEngine** - Enhanced engine with learning
- **ScanConfig** - Configuration dataclass (replaces CLI args)
- **VulnerabilityFinding** - Structured vulnerability data

## Building the Go Bridge

```bash
cd surge/nuclei/go_bridge
make install-deps  # Install Go dependencies
make build         # Build shared library
```

This creates `libnuclei_bridge.so` which Python loads via ctypes.

## Usage Examples

### Basic Scan

```python
from surge.nuclei.class_based_api import NucleiEngine, ScanConfig, Severity

# Create configuration
config = ScanConfig(
    template_ids=['cve-2020-9490'],
    severity_levels=[Severity.CRITICAL, Severity.HIGH],
    rate_limit=10,
    concurrency=5,
)

# Create engine
engine = NucleiEngine(config=config)

# Set up callbacks
def on_vuln(finding):
    print(f"Found: {finding.template_id}")

engine.on_vulnerability.append(on_vuln)

# Execute scan
scan_id = engine.scan(['https://example.com'])

# Cleanup
engine.close()
```

### Adaptive Scan with Learning

```python
from surge.nuclei.class_based_api import AdaptiveNucleiEngine, ScanConfig

config = ScanConfig(
    enable_learning=True,
    adaptive_mode=True,
)

engine = AdaptiveNucleiEngine(config=config)
scan_id = engine.scan(['https://example.com'])

# Engine automatically adapts based on:
# - Template effectiveness (from NucleiTemplateUsage)
# - Real-time scan performance
# - Adaptation rules (from NucleiAdaptationRule)
```

### On-the-Fly Adaptation

```python
# Start scan
engine = NucleiEngine()
scan_id = engine.scan(['https://example.com'])

# Pause scan
engine.pause()

# Adjust rate limit
engine.adjust_rate_limit(20)

# Resume scan
engine.resume()

# Get current state
state = engine.get_state()
print(state)
```

## Learning System

The learning system tracks:

1. **Template Usage** - Success rates, response times, effectiveness
2. **Scan Sessions** - Adaptations applied, performance metrics
3. **Adaptation Rules** - Conditions and actions for adaptive behavior

### Querying Learned Data

```python
from surge.models import NucleiTemplateUsage

# Get top templates by effectiveness
top_templates = NucleiTemplateUsage.objects.filter(
    usage_count__gte=10,
    success_rate__gte=0.5
).order_by('-effectiveness_score')[:10]

# Use in scan configuration
template_ids = [t.template_id for t in top_templates]
config = ScanConfig(template_ids=template_ids)
```

## Migration from Command-Line API

### Old Way (subprocess)
```python
cmd = ['nuclei', '-u', url, '-jsonl', '-t', 'http/cves/']
process = subprocess.run(cmd, capture_output=True)
# Parse stdout...
```

### New Way (class-based)
```python
config = ScanConfig(template_paths=['http/cves/'])
engine = NucleiEngine(config=config)
engine.on_vulnerability.append(handle_vuln)
engine.scan([url])
```

## Benefits

1. **No Shell Parsing** - Direct function calls, no stdout parsing
2. **Real-Time Control** - Pause, resume, adjust on-the-fly
3. **Learning Integration** - Automatic template selection based on history
4. **Agent Coordination** - Multiple agents can control same scan
5. **Type Safety** - Dataclasses provide type hints and validation
6. **Django Integration** - Full ORM access for learning data

## Next Steps

1. Build Go bridge: `cd surge/nuclei/go_bridge && make build`
2. Run migrations: `python manage.py makemigrations surge`
3. Test examples: `python surge/nuclei/example_usage.py`
4. Integrate with Surge agents
