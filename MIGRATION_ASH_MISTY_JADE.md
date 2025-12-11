# Migration from Ash/Misty/Jade to Kage/Kumo/Ryu

## Legal Compliance Migration

This document tracks the migration from personality names Ash, Misty, and Jade to Kage, Kumo, and Ryu for legal compliance reasons.

## Mapping

- **Ash** → **Kage** (Port Scanner)
- **Misty** → **Kumo** (HTTP Spider)
- **Jade** → **Ryu** (Security Coordinator)

## Completed Migrations

### Code Changes
- ✅ Model class names updated:
  - `JadeAssessment` → `RyuAssessment`
  - `AshWAFDetection` → `KageWAFDetection`
  - `AshTechniqueEffectiveness` → `KageTechniqueEffectiveness`
  - `AshScanResult` → `KageScanResult`
  - `AshNmapScanner` → `KageNmapScanner`
  - `AshErrorReporter` → `KageErrorReporter`

- ✅ Scan types updated:
  - `ash_port_scan` → `kage_port_scan`
  - `jade_port_scan` → `ryu_port_scan`

- ✅ Function names updated:
  - `get_ash_scanner()` → `get_kage_scanner()`

- ✅ Comments and docstrings updated in:
  - `models.py` (RequestMetaData, RyuAssessment)
  - `ash/nmap_scanner.py` (file header, class names)
  - `llm_enhancer.py` (Misty → Kumo references)
  - `views.py` (scan type filters, user agent queries)

- ✅ User agent/session ID references:
  - `session_id__icontains='misty'` → `session_id__icontains='kumo'`

## Pending Migrations

### Database Table Names (Requires Migration Scripts)

**CRITICAL**: The following database table names still contain legacy names and require database migrations:

1. **PostgreSQL Tables:**
   - `customer_eggs_eggrecords_general_models_jadeassessment` → Should become `customer_eggs_eggrecords_general_models_ryuassessment`
   - `ash_waf_detections` → Should become `kage_waf_detections`
   - `ash_technique_effectiveness` → Should become `kage_technique_effectiveness`
   - `ash_scan_results` → Should become `kage_scan_results`

2. **SQL Queries:**
   - `ryu_app/daemon_api.py` - Contains hardcoded table name `customer_eggs_eggrecords_general_models_jadeassessment`
   - `daemon_api.py` - Contains hardcoded table name `customer_eggs_eggrecords_general_models_jadeassessment`

**Note**: Model classes have been updated, but `db_table` names are preserved for backward compatibility. These need database migrations.

### Directory Structure

- `artificial_intelligence/personalities/reconnaissance/ash/` directory still exists
  - Consider merging with `kage/` directory or renaming
  - Files in `ash/` have been updated but directory name remains

### File Names

Files containing "ash", "misty", or "jade" in their names:
- `ash/nmap_scanner.py` - Content updated, file location unchanged
- `ash/scan_learning_service.py` - Content updated, file location unchanged
- Files in `kage/` directory with "ash" in name:
  - `ash_scout_service.py`
  - `ash_volkner_bridge.py`
  - `ash_scan_dataset.py`
  - `create_ash_learning_tables.py` (migration file)

### Documentation Files

- `MODULE_IMPORT_SUMMARY.md` - Contains "Ash" references
- `docs/EGGRECORDS_ORM_SETUP.md` - Contains "Ash" model references
- Other MD files may contain references

## Migration Strategy

### Phase 1: Code Migration (COMPLETED)
- ✅ Update all class names, function names, and code references
- ✅ Update comments and docstrings
- ✅ Update scan types and user agents

### Phase 2: Database Migration (PENDING)
1. Create database migration scripts to rename tables
2. Update `db_table` references in models after migration
3. Update hardcoded SQL queries in `daemon_api.py` files

### Phase 3: File/Directory Cleanup (PENDING)
1. Rename or merge `ash/` directory
2. Rename files with "ash" in their names
3. Update import statements

### Phase 4: Documentation (PENDING)
1. Update all README and MD files
2. Update code comments in migration files
3. Update API documentation

## Important Notes

- **Database Compatibility**: Model `db_table` names are currently preserved to maintain database compatibility. These must be migrated separately.
- **Backward Compatibility**: Some references may need to remain for backward compatibility with existing data.
- **Legal Compliance**: All user-facing and code references must use Kage/Kumo/Ryu names only.

## Next Steps

1. Create database migration scripts for table renames
2. Test migrations on development database
3. Update file/directory structure
4. Update documentation
5. Verify no remaining references to Ash/Misty/Jade in codebase

