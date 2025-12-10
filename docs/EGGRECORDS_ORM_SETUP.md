# EggRecords Database Django ORM Setup

This document describes the Django ORM models for the `eggrecords` PostgreSQL database (learning/heuristics data).

## Overview

All raw SQL queries for the `eggrecords` database have been replaced with Django ORM models. This provides the same benefits as the `customer_eggs` database ORM setup.

## Models Created (`ryu_app/eggrecords_models.py`)

### 1. AshWAFDetection
- **Table**: `ash_waf_detections`
- **Fields**: `waf_type`, `bypass_successful`, `confidence`, `detected_at`, `target`
- **Purpose**: WAF detection records

### 2. AshTechniqueEffectiveness
- **Table**: `ash_technique_effectiveness`
- **Fields**: `target_pattern`, `waf_type`, `technique_name`, `success_count`, `failure_count`, `last_success`, `last_failure`, `last_updated`, `technique_metadata`
- **Properties**: `success_rate` (calculated property)
- **Purpose**: Technique effectiveness tracking by domain pattern

### 3. CalculatedHeuristicsRule
- **Table**: `calculated_heuristics_rules`
- **Fields**: `rule_pattern`, `nmap_arguments` (JSONField), `recommended_technique`, `confidence_score`, `success_rate`, `sample_count`, `last_updated`
- **Properties**: `nmap_arguments_list` (parses JSON to list)
- **Purpose**: Stored heuristics rules with Nmap arguments

### 4. WAFDetectionDetail
- **Table**: `waf_detection_details`
- **Fields**: `waf_type`, `waf_version`, `waf_product`, `confidence`, `detected_at`, `target`
- **Purpose**: Enhanced WAF detection with version/product details

### 5. IPTechniqueEffectiveness
- **Table**: `ip_technique_effectiveness`
- **Fields**: `asn`, `cidr_block`, `ipv6_prefix`, `waf_type`, `technique_name`, `success_count`, `failure_count`, `avg_scan_duration`, `last_updated`
- **Properties**: `success_rate` (calculated property)
- **Purpose**: Technique effectiveness by IP/ASN/CIDR

### 6. TechnologyFingerprint
- **Table**: `technology_fingerprints`
- **Fields**: `technology_type`, `product`, `version`, `target`, `detected_at`
- **Purpose**: Technology fingerprinting data (Oak's curated data)

### 7. AshScanResult
- **Table**: `ash_scan_results`
- **Fields**: `target`, `technique_used`, `waf_detected`, `waf_type`, `open_ports_found`, `bypass_successful`, `scan_duration`, `scanned_at`
- **Purpose**: Scan result decisions and outcomes

## Database Router Updated

The `PostgresRouter` in `ryu_app/db_router.py` now routes:
- `customer_eggs` models → `customer_eggs` database
- `eggrecords` models → `eggrecords` database

## Refactored Views

All views that previously used raw SQL for `eggrecords` database now use Django ORM:

1. **`learning_dashboard`** - Uses all eggrecords models with aggregations
2. **`learning_heuristics_api`** - Uses `CalculatedHeuristicsRule.objects`
3. **`learning_techniques_api`** - Uses `AshTechniqueEffectiveness.objects`
4. **`learning_ip_effectiveness_api`** - Uses `IPTechniqueEffectiveness.objects`
5. **Dashboard views** - Use `AshWAFDetection` and `AshTechniqueEffectiveness` for stats

## Usage Examples

### Querying Technique Effectiveness

```python
from ryu_app.eggrecords_models import AshTechniqueEffectiveness
from django.db.models import F

# Get techniques with success rate calculation
techniques = AshTechniqueEffectiveness.objects.using('eggrecords').annotate(
    total_attempts=F('success_count') + F('failure_count')
).order_by('-total_attempts')[:50]

for tech in techniques:
    print(f"{tech.technique_name}: {tech.success_rate}% success")
```

### Querying WAF Patterns with Aggregations

```python
from ryu_app.eggrecords_models import WAFDetectionDetail
from django.db.models import Count, Avg, Max

# Group by WAF type/version/product
waf_patterns = WAFDetectionDetail.objects.using('eggrecords').filter(
    waf_type__isnull=False
).values('waf_type', 'waf_version', 'waf_product').annotate(
    detection_count=Count('id'),
    avg_confidence=Avg('confidence'),
    last_detected=Max('detected_at'),
    unique_targets=Count('target', distinct=True)
).order_by('-detection_count')[:50]
```

### Querying Heuristics Rules

```python
from ryu_app.eggrecords_models import CalculatedHeuristicsRule

# Get rules with parsed JSON arguments
rules = CalculatedHeuristicsRule.objects.using('eggrecords').order_by(
    '-confidence_score', '-sample_count'
)[:50]

for rule in rules:
    print(f"Pattern: {rule.rule_pattern}")
    print(f"Arguments: {rule.nmap_arguments_list}")  # Auto-parsed JSON
```

## Benefits

✅ **No raw SQL** - All queries use Django ORM  
✅ **Type safety** - IDE autocomplete and type checking  
✅ **Calculated properties** - `success_rate` automatically calculated  
✅ **JSON handling** - `nmap_arguments` automatically parsed  
✅ **Aggregations** - Use Django's `annotate()` for complex queries  
✅ **Consistency** - Same patterns as `customer_eggs` models  

## Migration Notes

- All models have `managed = False` - Django won't create migrations
- Tables already exist in PostgreSQL
- Models map directly to existing table structures
- No schema changes needed

## Complete ORM Coverage

**Before**: 68+ raw SQL queries  
**After**: 0 raw SQL queries - 100% Django ORM! 🎉

All database operations now use Django ORM for both:
- `customer_eggs` database (main scan data)
- `eggrecords` database (learning/heuristics data)

