# Migration Status: Ash/Misty/Jade → Kage/Kumo/Ryu

## ✅ Completed Code Migrations

### Core Models & Classes
- ✅ `JadeAssessment` → `RyuAssessment` (models.py)
- ✅ `AshWAFDetection` → `KageWAFDetection` (eggrecords_models.py)
- ✅ `AshTechniqueEffectiveness` → `KageTechniqueEffectiveness` (eggrecords_models.py)
- ✅ `AshScanResult` → `KageScanResult` (eggrecords_models.py)
- ✅ `AshNmapScanner` → `KageNmapScanner` (ash/nmap_scanner.py)
- ✅ `AshErrorReporter` → `KageErrorReporter` (ash/nmap_scanner.py)
- ✅ `JadeCybersecurityCoordinator` → `RyuCybersecurityCoordinator` (ryu/cybersecurity_coordinator.py)

### Functions & Variables
- ✅ `get_ash_scanner()` → `get_kage_scanner()`
- ✅ `get_jade_coordinator()` → `get_ryu_coordinator()`
- ✅ `start_jade_coordinator()` → `start_ryu_coordinator()`
- ✅ `stop_jade_coordinator()` → `stop_ryu_coordinator()`
- ✅ `jade_coordinator` → `ryu_coordinator`
- ✅ `_ash_scanner_instance` → `_kage_scanner_instance`

### Scan Types
- ✅ `ash_port_scan` → `kage_port_scan` (removed from queries, default updated)
- ✅ `jade_port_scan` → `ryu_port_scan` (comments updated)

### User Agents & Session IDs
- ✅ `session_id__icontains='misty'` → `session_id__icontains='kumo'`
- ✅ `Enhanced-Misty-Spider` → `Enhanced-Kumo-Spider` (User-Agent)

### Comments & Documentation
- ✅ File headers updated (ash/nmap_scanner.py, ash/scan_learning_service.py)
- ✅ Docstrings updated (models, functions, classes)
- ✅ HTML templates updated (learning_dashboard.html)
- ✅ Log messages updated (enhanced_http_spider.py)

### Database Router
- ✅ Model names updated in `db_router.py`

## ⚠️ Remaining Work

### Database Table Names (Requires Migration Scripts)
These table names still contain legacy names. Model classes are updated but `db_table` names are preserved for backward compatibility:

1. **PostgreSQL Tables:**
   - `customer_eggs_eggrecords_general_models_jadeassessment` (model: `RyuAssessment`)
   - `ash_waf_detections` (model: `KageWAFDetection`)
   - `ash_technique_effectiveness` (model: `KageTechniqueEffectiveness`)
   - `ash_scan_results` (model: `KageScanResult`)

2. **SQL Queries with Hardcoded Table Names:**
   - `ryu_app/daemon_api.py` - Line 95, 320: `customer_eggs_eggrecords_general_models_jadeassessment`
   - `daemon_api.py` - Line 95, 320: `customer_eggs_eggrecords_general_models_jadeassessment`

**Action Required**: Create database migration scripts to rename these tables, then update SQL queries.

### File/Directory Names (Low Priority)
- `artificial_intelligence/personalities/reconnaissance/ash/` directory exists
  - Content updated, but directory name unchanged
  - Consider merging with `kage/` or renaming

### Class Names in Legacy Files (Low Priority)
These files contain "Ash" in class names but may be legacy/unused:
- `kage/ash_scout_service.py` - `HeavyAshScoutService`
- `kage/ash_scout_service_working.py` - `WorkingAshScoutService`
- `kage/ash_scout_service_simple.py` - `SimpleAshScoutService`
- `kage/ash_volkner_bridge.py` - `AshVolknerBridge`
- `kage/ash_scan_dataset.py` - `AshScanSample`, `AshScanDataset`
- `kage/enhanced_reconnaissance_service.py` - `AshEnhancedReconnaissanceService`

**Note**: These may be legacy files. Verify if they're actively used before migrating.

## Verification

Run these commands to check for remaining references:

```bash
# Check for class names
grep -r "class.*Ash\|class.*Misty\|class.*Jade" --include="*.py"

# Check for function names
grep -r "def.*ash\|def.*misty\|def.*jade" --include="*.py" -i

# Check for variable names
grep -r "\bash_\|misty_\|jade_" --include="*.py" -i
```

## Legal Compliance Status

✅ **Code References**: All active code references have been migrated to Kage/Kumo/Ryu
⚠️ **Database Schema**: Table names still contain legacy names (requires migration)
⚠️ **File Names**: Some files/directories still contain legacy names (low priority)

## Next Steps

1. **Critical**: Create database migration scripts for table renames
2. **Important**: Update hardcoded SQL queries after table migration
3. **Optional**: Rename/merge `ash/` directory if needed
4. **Optional**: Update legacy file names if those files are actively used

