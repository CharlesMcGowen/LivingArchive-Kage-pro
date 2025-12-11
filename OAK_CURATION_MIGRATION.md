# Oak Target Curation Migration to Kage-pro

## Overview

Oak's target curation functionality has been migrated from the main codebase to Kage-pro to consolidate all reconnaissance and curation elements in one place.

## Migration Date

2024

## What Was Migrated

### Core Services

1. **OakTargetCurationService**
   - Location: `artificial_intelligence/personalities/reconnaissance/oak/target_curation/target_curation_service.py`
   - Functionality: Comprehensive subdomain curation with technology fingerprinting, CVE correlation, confidence scoring, and scan recommendations

2. **OakAutonomousCurationService**
   - Location: `artificial_intelligence/personalities/reconnaissance/oak/target_curation/autonomous_curation_service.py`
   - Functionality: Self-starting curation worker that runs when Oak is idle

3. **Signals Integration**
   - Location: `artificial_intelligence/personalities/reconnaissance/signals.py`
   - Functionality: Automatic curation when Ash/Jade/Kage discover subdomains

## Directory Structure

```
LivingArchive-Kage-pro/
└── artificial_intelligence/
    └── personalities/
        └── reconnaissance/
            ├── oak/
            │   └── target_curation/
            │       ├── __init__.py
            │       ├── target_curation_service.py
            │       └── autonomous_curation_service.py
            └── signals.py
```

## Import Path Changes

### Before (Main Codebase)
```python
from artificial_intelligence.personalities.coordination.oak.target_curation import (
    OakTargetCurationService,
    OakAutonomousCurationService
)
```

### After (Kage-pro)
```python
from artificial_intelligence.personalities.reconnaissance.oak.target_curation import (
    OakTargetCurationService,
    OakAutonomousCurationService
)
```

## Dependencies

### Still in Main Codebase (Not Migrated)

1. **Bugsy CVE Intelligence Service**
   - Location: `/mnt/webapps-nvme/artificial_intelligence/personalities/security/bugsy/cve_intelligence_service.py`
   - Used by: OakTargetCurationService for CVE correlation
   - Import: `from artificial_intelligence.personalities.security.bugsy.cve_intelligence_service import BugsyCVEIntelligenceService`

2. **Bugsy Base Services**
   - Location: `/mnt/webapps-nvme/artificial_intelligence/personalities/security/bugsy/base_services.py`
   - Used by: OakAutonomousCurationService
   - Import: `from artificial_intelligence.personalities.security.bugsy.base_services import BaseBugsyService`

3. **Bugsy Technology Detector**
   - Location: `/mnt/webapps-nvme/artificial_intelligence/personalities/security/bugsy/technology_detection_database.py`
   - Used by: OakTargetCurationService for HTTP fingerprinting
   - Import: `from artificial_intelligence.personalities.security.bugsy.technology_detection_database import BugsyTechnologyDetector`

## Database Models

All database models remain in the shared database:
- `enrichment_system_subdomaincurationqueue` - Curation queue
- `enrichment_system_technologyfingerprint` - Technology fingerprints
- `enrichment_system_cvefingerprintmatch` - CVE matches
- `enrichment_system_cvescanrecommendation` - Scan recommendations

No database migrations needed - models are accessed via raw SQL queries.

## Integration Points

### Django App Configuration

File: `reconnaissance/apps.py`

The autonomous curation service is automatically started when Django is ready:

```python
from artificial_intelligence.personalities.reconnaissance.oak.target_curation.autonomous_curation_service import get_instance

curation_service = get_instance()
curation_service.start_service()
```

### Signals Registration

File: `reconnaissance/signals.py`

Signals are automatically registered when the Django app loads (via `apps.py`):

```python
import artificial_intelligence.personalities.reconnaissance.signals  # noqa: F401
```

## Data Flow

```
Discovery (Ash/Jade/Kage) 
  → EggRecord created 
  → Signal triggers 
  → OakTargetCurationService.queue_subdomain_for_curation()
  → Technology fingerprinting
  → CVE correlation (via Bugsy service)
  → CVEFingerprintMatch created
  → CVEScanRecommendation created (via signals)
  → Surge reads recommendations
```

## Testing

To verify the migration:

1. **Check service startup**:
   ```bash
   # Check Django logs for:
   # "🌳 Oak autonomous curation service started"
   ```

2. **Test discovery signal**:
   - Create a new EggRecord with `discovery_metadata.discovered_by = 'ash'`
   - Verify curation is queued in logs

3. **Test autonomous curation**:
   - Wait for Oak to be idle (10 minutes)
   - Verify uncured targets are processed

## Files Modified

1. ✅ Created: `reconnaissance/oak/target_curation/__init__.py`
2. ✅ Created: `reconnaissance/oak/target_curation/target_curation_service.py`
3. ✅ Created: `reconnaissance/oak/target_curation/autonomous_curation_service.py`
4. ✅ Created: `reconnaissance/signals.py`
5. ✅ Modified: `reconnaissance/apps.py` - Added autonomous curation service startup

## Files That Need Updates (Main Codebase)

The following files in the main codebase still reference the old import path and should be updated:

1. `artificial_intelligence/personalities/security/bugsy/views.py`
2. `artificial_intelligence/personalities/security/bugsy/autonomous_curation_service.py`
3. `artificial_intelligence/personalities/security/bugsy/curation_service.py`
4. `artificial_intelligence/personalities/security/bugsy/jade_ash_discovery_signals.py`
5. `artificial_intelligence/personalities/security/bugsy/bugsy_autonomous_service.py`
6. `artificial_intelligence/personalities/security/bugsy/api.py`
7. `artificial_intelligence/personalities/security/bugsy/bugsy_api_views.py`
8. `artificial_intelligence/personalities/security/bugsy/services.py`
9. `artificial_intelligence/personalities/security/surge/surge_sabrina_intelligence.py`
10. `artificial_intelligence/personalities/coordination/oak/views.py`

**Note**: These files should be updated to import from the new Kage-pro location, or they can continue to reference the main codebase if they're not part of Kage-pro.

## Benefits

1. **Consolidation**: All reconnaissance and curation functionality in one project
2. **Simplified Deployment**: Single codebase for all reconnaissance agents
3. **Easier Maintenance**: Related code is co-located
4. **Clear Separation**: Kage-pro is now self-contained for reconnaissance operations

## Next Steps

1. Update main codebase files to use new import paths (if needed)
2. Test end-to-end curation workflow
3. Monitor autonomous curation service performance
4. Verify CVE correlation still works correctly

