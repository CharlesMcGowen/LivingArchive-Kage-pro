# Oak Nmap Coordination & Nuclei Template Selection

## Overview

Oak now coordinates Nmap scanning for Nuclei agents and intelligently selects Nuclei templates based on technology fingerprints, CVE matches, and open ports. This creates a complete workflow from discovery to vulnerability scanning.

## Architecture

```
Discovery (Ash/Jade/Kage)
  → EggRecord created
  → Oak Curation triggered
  → Oak ensures Nmap scan exists (triggers if needed)
  → Technology fingerprinting from Nmap data
  → CVE correlation
  → Nuclei template selection
  → Template relationships created in database
  → Surge queries templates via API
  → Nuclei scanning with selected templates
```

## Components Created

### 1. OakNmapCoordinationService

**Location**: `artificial_intelligence/personalities/reconnaissance/oak/nmap_coordination_service.py`

**Key Methods**:

- `ensure_nmap_scan_for_egg_record()` - Ensures Nmap scan exists, triggers if needed
- `select_nuclei_templates_for_egg_record()` - Selects templates based on intelligence
- `get_recommended_templates_for_egg_record()` - Retrieves recommended templates for Surge

**Features**:
- Checks for recent Nmap scans (within 24 hours)
- Marks EggRecords for daemon pickup if scan needed
- Selects templates with priority:
  1. Templates from CVE matches (highest priority)
  2. Templates from scan recommendations
  3. Templates based on technology fingerprints
  4. Templates based on open ports/services

### 2. Database Table

**Table**: `enrichment_system_nucleitemplaterecommendation`

**Schema**:
```sql
CREATE TABLE enrichment_system_nucleitemplaterecommendation (
    id UUID PRIMARY KEY,
    egg_record_id UUID NOT NULL,
    template_id VARCHAR(500) NOT NULL,
    template_source VARCHAR(100) NOT NULL,  -- 'cve_match', 'fingerprint', 'port_scan'
    source_id VARCHAR(500),                 -- CVE ID, fingerprint ID, or port number
    priority VARCHAR(20) NOT NULL,          -- 'high', 'medium', 'low'
    reasoning TEXT,
    status VARCHAR(20) DEFAULT 'pending',   -- 'pending', 'scanned', 'failed'
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    scanned_at TIMESTAMP,
    scan_result JSONB,
    UNIQUE(egg_record_id, template_id)
)
```

### 3. Integration with Oak Curation

**Modified**: `target_curation_service.py`

Oak's curation workflow now:
1. Ensures Nmap scan exists (triggers if needed)
2. Selects Nuclei templates after fingerprinting and CVE correlation
3. Creates template relationships in database

### 4. API Endpoint

**Endpoint**: `GET /api/oak/nuclei-templates/<egg_record_id>/`

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
            "source": "cve_match",
            "source_id": "CVE-2023-12345",
            "priority": "high",
            "reasoning": "CVE CVE-2023-12345 (CRITICAL) - Apache",
            "status": "pending",
            "created_at": "2024-01-01T00:00:00Z"
        }
    ],
    "template_count": 5,
    "message": "Found 5 recommended templates"
}
```

## Template Selection Logic

### Priority 1: CVE Matches
- Templates directly linked to CVEs via `nuclei_template_ids` field
- Highest priority (CRITICAL/HIGH severity CVEs)
- Includes CVSS score and severity in reasoning

### Priority 2: Scan Recommendations
- Templates from existing `CVEScanRecommendation` records
- High-priority recommendations preferred

### Priority 3: Technology Fingerprints
- Templates mapped from detected technologies
- Examples:
  - Apache → `apache`, `httpd`, `cve-apache`
  - MySQL → `mysql`, `cve-mysql`, `mariadb`
  - WordPress → `wordpress`, `wp`, `cve-wordpress`

### Priority 4: Open Ports/Services
- Templates based on open ports and services
- Examples:
  - Port 80/443 → `http`, `https`, `web`
  - Port 22 → `ssh`, `openssh`, `cve-ssh`
  - Port 3306 → `mysql`, `cve-mysql`

## Usage

### For Surge (Nuclei Agents)

```python
import requests

# Query recommended templates for an EggRecord
response = requests.get(
    'http://localhost:8000/api/oak/nuclei-templates/<egg_record_id>/',
    params={'status': 'pending', 'limit': 20}
)

templates = response.json()['templates']
for template in templates:
    template_id = template['template_id']
    priority = template['priority']
    reasoning = template['reasoning']
    
    # Use template for Nuclei scan
    # nuclei -t {template_id} -u {target}
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
templates_selected = result.get('templates_selected', 0)
nuclei_templates = result.get('nuclei_templates', {})
```

## Workflow Example

1. **Discovery**: Kage discovers `subdomain.example.com`
2. **EggRecord Created**: New EggRecord with `subDomain='subdomain.example.com'`
3. **Oak Curation Triggered**: Signal fires, Oak queues curation
4. **Nmap Scan Check**: Oak checks for recent scan, finds none
5. **Nmap Scan Triggered**: Oak marks EggRecord for Kage daemon pickup
6. **Nmap Scan Completes**: Kage daemon runs scan, stores results
7. **Fingerprinting**: Oak creates fingerprints from Nmap data (Apache 2.4.41, MySQL 8.0)
8. **CVE Correlation**: Bugsy service correlates CVEs (CVE-2023-12345 for Apache)
9. **Template Selection**: Oak selects templates:
   - `cve-2023-12345` (from CVE match - HIGH priority)
   - `apache` (from fingerprint - MEDIUM priority)
   - `mysql` (from fingerprint - MEDIUM priority)
   - `http` (from port 80 - MEDIUM priority)
10. **Template Relationships**: Oak creates database entries linking templates to EggRecord
11. **Surge Queries**: Surge queries API for templates
12. **Nuclei Scanning**: Surge runs Nuclei with selected templates

## Database Relationships

```
EggRecord (1) ──→ (N) NucleiTemplateRecommendation
                    ├── template_id: "cve-2023-12345"
                    ├── source: "cve_match"
                    ├── source_id: "CVE-2023-12345"
                    └── priority: "high"

TechnologyFingerprint (1) ──→ (N) CVEFingerprintMatch
                                └── (N) NucleiTemplateRecommendation
```

## Benefits

1. **Intelligent Template Selection**: Templates selected based on actual technology stack and CVEs
2. **Reduced False Positives**: Only relevant templates are used
3. **Prioritized Scanning**: High-priority templates (CVE matches) scanned first
4. **Complete Workflow**: From discovery to scanning, all coordinated by Oak
5. **API Integration**: Surge can easily query recommended templates

## Future Enhancements

1. **Template Effectiveness Tracking**: Track which templates find vulnerabilities
2. **Dynamic Template Updates**: Update recommendations as new CVEs are discovered
3. **Template Exclusion**: Exclude templates that consistently fail
4. **Custom Template Mapping**: Allow custom technology-to-template mappings
5. **Template Versioning**: Track template versions and update recommendations

## Files Modified

1. ✅ Created: `oak/nmap_coordination_service.py`
2. ✅ Modified: `oak/target_curation/target_curation_service.py`
3. ✅ Modified: `ryu_app/views.py` - Added API endpoint
4. ✅ Modified: `ryu_app/urls.py` - Added URL route

## Testing

To test the integration:

1. **Create an EggRecord**:
   ```python
   # Via Django shell or API
   egg_record = EggRecord.objects.create(
       subDomain='test.example.com',
       alive=True
   )
   ```

2. **Trigger Oak Curation**:
   ```python
   from artificial_intelligence.personalities.reconnaissance.oak.target_curation import (
       OakTargetCurationService
   )
   
   service = OakTargetCurationService()
   result = service.curate_subdomain(egg_record)
   ```

3. **Query Templates**:
   ```bash
   curl "http://localhost:8000/api/oak/nuclei-templates/<egg_record_id>/?status=pending"
   ```

4. **Verify Database**:
   ```sql
   SELECT * FROM enrichment_system_nucleitemplaterecommendation
   WHERE egg_record_id = '<egg_record_id>';
   ```

## Status

✅ **Complete** - All components implemented and integrated

- Oak coordinates Nmap scanning
- Template selection based on fingerprints/CVEs
- Database relationships created
- API endpoint for Surge
- Integrated into curation workflow

