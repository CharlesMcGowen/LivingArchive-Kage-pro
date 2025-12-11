# Oak Template Registry Integration

## Overview

Oak now has a **Template Registry Service** that scans and indexes Nuclei templates from the template directory (`/home/ego/nuclei-templates`). This connects Oak's template selection logic to actual template files, enabling Nuclei agents (Surge/Koga/Bugsy) to use ready-to-use templates without needing selection logic.

## Architecture

```
Template Upload (Surge API)
  → /home/ego/nuclei-templates/
  → Oak Template Registry Service scans directory
  → Indexes templates in eggrecords database
  → Oak queries registry for template selection
  → Templates correlated to EggRecords
  → Surge/Koga/Bugsy query API for ready templates
```

## Components

### 1. Template Registry Database Table

**Table**: `enrichment_system_nucleitemplate`

**Schema**:
```sql
CREATE TABLE enrichment_system_nucleitemplate (
    id UUID PRIMARY KEY,
    template_id VARCHAR(500) UNIQUE NOT NULL,  -- Nuclei template ID
    template_path VARCHAR(1000) NOT NULL,      -- Relative path from templates dir
    template_name VARCHAR(500),                -- Human-readable name
    cve_id VARCHAR(50),                        -- CVE ID if applicable
    technology VARCHAR(200),                   -- Technology (apache, wordpress, etc.)
    tags JSONB,                                -- Template tags array
    severity VARCHAR(20),                     -- critical, high, medium, low, info
    author VARCHAR(200),
    description TEXT,
    reference TEXT,
    classification JSONB,
    raw_content TEXT,                         -- Full YAML content
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    indexed_at TIMESTAMP
)
```

**Indexes**:
- `idx_nuclei_template_cve` - Fast CVE lookups
- `idx_nuclei_template_technology` - Fast technology lookups
- `idx_nuclei_template_severity` - Severity filtering
- `idx_nuclei_template_tags_gin` - GIN index for JSONB tag searches

### 2. OakTemplateRegistryService

**Location**: `artificial_intelligence/personalities/reconnaissance/oak/template_registry_service.py`

**Key Methods**:
- `scan_and_index_templates()` - Scan template directory and index all templates
- `find_templates_by_technology()` - Find templates matching a technology
- `find_templates_by_cve()` - Find templates matching a CVE ID
- `find_templates_by_tags()` - Find templates matching tags
- `get_template_by_id()` - Get full template metadata by ID

**Features**:
- Automatically extracts CVE IDs from template metadata
- Identifies technologies from template tags
- Parses severity, author, description, references
- Stores full template content for later use

### 3. Updated Oak Template Selection

**Location**: `artificial_intelligence/personalities/reconnaissance/oak/nmap_coordination_service.py`

Oak's template selection now:
1. **Priority 1**: Uses CVE matches from `CVEFingerprintMatch` (if they have template IDs)
2. **Priority 1b**: Queries template registry for CVE matches
3. **Priority 3**: Queries template registry for technology fingerprints
4. **Fallback**: Uses hardcoded patterns if registry unavailable

**Benefits**:
- Returns actual template IDs that exist in the filesystem
- Includes `template_path` for direct use by Surge
- Prioritizes by severity (critical/high first)
- Correlates templates with EggRecords via technology/CVE

### 4. API Endpoints

#### GET `/api/oak/nuclei-templates/<egg_record_id>/`

Returns recommended templates for an EggRecord with full metadata including `template_path`.

**Query Parameters**:
- `status`: Filter by status ('pending', 'scanned', 'failed') - default: 'pending'
- `limit`: Maximum templates to return - default: 20

**Response**:
```json
{
    "success": true,
    "egg_record_id": "uuid",
    "status_filter": "pending",
    "templates": [
        {
            "id": "uuid",
            "template_id": "cve-2023-12345",
            "template_path": "http/cves/CVE-2023-12345.yaml",
            "template_name": "Apache 2.4.41 RCE",
            "source": "cve_match",
            "source_id": "CVE-2023-12345",
            "priority": "high",
            "severity": "critical",
            "cve_id": "CVE-2023-12345",
            "technology": "apache",
            "reasoning": "CVE CVE-2023-12345 (CRITICAL) - Apache",
            "status": "pending",
            "created_at": "2024-01-01T00:00:00Z"
        }
    ],
    "template_count": 5
}
```

#### POST `/api/oak/refresh-templates/`

Refresh/scan the template registry. Call this after uploading new templates.

**Body** (optional):
```json
{
    "force_rescan": false
}
```

**Response**:
```json
{
    "success": true,
    "scanned": 1500,
    "indexed": 50,
    "updated": 10,
    "errors": 0,
    "total_templates": 1500,
    "message": "Scanned 1500 templates, indexed 50 new, updated 10 existing"
}
```

## Usage

### Initial Setup

1. **Index existing templates**:
```bash
# Via Django shell
python manage.py shell
>>> from artificial_intelligence.personalities.reconnaissance.oak.seed_templates import seed_templates
>>> seed_templates()

# Or via API
curl -X POST http://localhost:8000/api/oak/refresh-templates/
```

2. **After uploading new templates**:
```bash
# After uploading via Surge API, refresh registry
curl -X POST http://localhost:8000/api/oak/refresh-templates/
```

### For Nuclei Agents (Surge/Koga/Bugsy)

1. **Query recommended templates**:
```python
import requests

# Get templates for an EggRecord
response = requests.get(
    'http://localhost:8000/api/oak/nuclei-templates/<egg_record_id>/',
    params={'status': 'pending', 'limit': 20}
)

templates = response.json()['templates']
for template in templates:
    template_id = template['template_id']
    template_path = template.get('template_path')
    
    # Use template_path if available, otherwise use template_id
    if template_path:
        # Use relative path: http/cves/CVE-2023-12345.yaml
        nuclei_cmd = f"nuclei -t {template_path} -u {target}"
    else:
        # Fallback to template ID
        nuclei_cmd = f"nuclei -t {template_id} -u {target}"
```

### For Oak Curation

Templates are automatically selected during curation:

```python
from artificial_intelligence.personalities.reconnaissance.oak.target_curation import (
    OakTargetCurationService
)

curation_service = OakTargetCurationService()
result = curation_service.curate_subdomain(egg_record)

# Templates are automatically selected and stored
templates_selected = result.get('nuclei_templates', {}).get('template_count', 0)
```

## Workflow

1. **Template Upload**: Surge uploads templates via `POST /surge/upload-templates/`
2. **Template Storage**: Templates saved to `/home/ego/nuclei-templates/`
3. **Registry Scan**: Oak scans directory (manual trigger or scheduled)
4. **Template Indexing**: Templates indexed in `enrichment_system_nucleitemplate` table
5. **EggRecord Curation**: Oak curates EggRecord, creates fingerprints
6. **Template Selection**: Oak queries registry for matching templates
7. **Template Recommendations**: Stored in `enrichment_system_nucleitemplaterecommendation`
8. **Agent Query**: Surge/Koga/Bugsy query API for ready templates
9. **Nuclei Scanning**: Agents use `template_path` directly

## Database Relationships

```
EggRecord (1) ──→ (N) TechnologyFingerprint
                    └──→ (N) CVEFingerprintMatch
                            └──→ (N) NucleiTemplateRecommendation
                                    └──→ (1) NucleiTemplate (via template_id)
```

## Benefits

1. **Ready-to-Use Templates**: Agents get actual template paths, no selection logic needed
2. **CVE Correlation**: Templates automatically linked to CVEs
3. **Technology Matching**: Templates matched to detected technologies
4. **Severity Prioritization**: Critical/high templates scanned first
5. **Complete Metadata**: Template name, description, references available
6. **Automatic Updates**: Refresh registry after template uploads

## Files Created/Modified

1. ✅ Created: `oak/template_registry_service.py` - Template registry service
2. ✅ Created: `oak/seed_templates.py` - Seed script for indexing templates
3. ✅ Modified: `oak/nmap_coordination_service.py` - Uses registry for template selection
4. ✅ Modified: `ryu_app/views.py` - Added refresh API endpoint, enriched templates API
5. ✅ Modified: `ryu_app/urls.py` - Added refresh template route

## Next Steps

1. **Schedule Automatic Scans**: Add periodic task to scan templates directory
2. **Template Effectiveness Tracking**: Track which templates find vulnerabilities
3. **Template Versioning**: Handle template updates and version changes
4. **Webhook Integration**: Auto-refresh registry when templates uploaded via Surge API
5. **Template Validation**: Validate template YAML before indexing

## Status

✅ **Complete** - Template registry integrated with Oak

- Database table created automatically
- Template scanning and indexing implemented
- Oak template selection uses registry
- API endpoints for querying and refreshing
- Seed script for initial indexing

