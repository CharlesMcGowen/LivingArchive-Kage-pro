# Suzu Directory Enumeration Enhancement - Implementation Summary

## Overview
Enhanced Suzu's directory enumeration capabilities with metadata correlation, CMS detection, priority scoring, and integration with Nmap scans and technology fingerprints.

## Components Created

### 1. DirectoryEnumerationResult Django ORM Model
**Location**: `artificial_intelligence/customer_eggs_eggrecords_general_models/models.py`

**Features**:
- Stores discovered paths with full metadata
- Correlates with Nmap scan data (port, service, version, product, CPE)
- Links to technology fingerprints
- CMS detection results (name, version, confidence, method, signatures)
- Priority scoring (0.0-1.0) with factor breakdown
- Request metadata correlation from Kumo
- Enumeration tool tracking (dirsearch, gobuster, ffuf)

**Database Table**: `customer_eggs_eggrecords_general_models_directoryenumerationresult`

### 2. CMS Detection Service
**Location**: `suzu/cms_detector.py`

**Features**:
- Detects CMS from HTTP headers (X-Powered-By, Link, etc.)
- Detects CMS from HTML content (wp-content, wp-includes, etc.)
- Detects CMS from meta tags (generator tags)
- Detects CMS from path patterns (/wp-admin/, /administrator/, etc.)
- Extracts CMS versions (WordPress, Drupal, Joomla, Magento, Shopify)
- Correlates with Nmap scan data for service detection

**Supported CMS**:
- WordPress
- Drupal
- Joomla
- Magento
- Shopify

### 3. Priority Scoring System
**Location**: `suzu/priority_scorer.py`

**Features**:
- Calculates priority scores (0.0-1.0) based on multiple factors:
  - High-priority path patterns (/admin, /api, /config, etc.)
  - CMS detection confidence
  - Nmap service correlation
  - Technology fingerprint correlation
  - HTTP status codes (200, 403, 401, etc.)
  - Content length
  - File extensions
- Generates priority wordlists based on detected technologies
- Provides factor breakdown for transparency

### 4. Enhanced Dirsearch Wrapper
**Location**: `suzu/enhanced_dirsearch.py`

**Features**:
- Wraps dirsearch with metadata correlation
- Supports priority wordlists (check high-value paths first)
- Future: Golang acceleration support
- Fallback enumeration using requests library
- JSON and text output parsing

### 5. Updated Directory Enumerator
**Location**: `suzu/directory_enumerator.py`

**Enhancements**:
- Integrated CMS detector
- Integrated priority scorer
- Integrated enhanced dirsearch
- Metadata correlation during enumeration
- Stores results in DirectoryEnumerationResult model with full correlation

## Integration Flow

1. **Enumeration Start**:
   - Learn patterns from Kumo's spidering data
   - Detect CMS from RequestMetaData
   - Get technology fingerprints
   - Generate priority wordlist

2. **Enumeration Execution**:
   - Use enhanced dirsearch (or fallback tools)
   - Check priority paths first
   - Correlate with Nmap scan data
   - Detect CMS from paths

3. **Result Storage**:
   - Calculate priority scores
   - Store in DirectoryEnumerationResult with:
     - Nmap correlation (port, service, version, product, CPE)
     - CMS detection (name, version, confidence, method, signatures)
     - Technology fingerprint links
     - Priority score and factors
     - Request metadata correlation

## Database Migration

**Note**: The model has `managed = True`, so a migration needs to be created. Since `customer_eggs_eggrecords_general_models` is not a registered Django app, you may need to:

1. Register it as an app in `settings.py`, OR
2. Create a manual migration SQL script, OR
3. Use Django's `makemigrations` with the app registered temporarily

**Migration SQL** (for reference):
```sql
CREATE TABLE customer_eggs_eggrecords_general_models_directoryenumerationresult (
    id UUID PRIMARY KEY,
    egg_record_id UUID NOT NULL,
    discovered_path VARCHAR(2048) NOT NULL,
    path_status_code INTEGER,
    path_content_length INTEGER,
    path_content_type VARCHAR(255),
    path_response_time_ms FLOAT,
    nmap_scan_id UUID,
    correlated_port INTEGER,
    correlated_service_name VARCHAR(100),
    correlated_service_version VARCHAR(255),
    correlated_product VARCHAR(255),
    correlated_os_details JSONB,
    correlated_cpe JSONB,
    technology_fingerprint_id UUID,
    detected_cms VARCHAR(100),
    detected_cms_version VARCHAR(50),
    detected_framework VARCHAR(100),
    detected_framework_version VARCHAR(50),
    cms_detection_method VARCHAR(50),
    cms_detection_confidence FLOAT DEFAULT 0.0,
    cms_detection_signatures JSONB,
    priority_score FLOAT NOT NULL DEFAULT 0.0,
    priority_factors JSONB,
    request_metadata_id UUID,
    correlated_headers JSONB,
    correlated_html_entities JSONB,
    enumeration_tool VARCHAR(50),
    wordlist_used VARCHAR(255),
    enumeration_depth INTEGER DEFAULT 1,
    discovered_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

CREATE INDEX idx_dir_enum_egg_record ON customer_eggs_eggrecords_general_models_directoryenumerationresult(egg_record_id);
CREATE INDEX idx_dir_enum_path ON customer_eggs_eggrecords_general_models_directoryenumerationresult(discovered_path);
CREATE INDEX idx_dir_enum_status ON customer_eggs_eggrecords_general_models_directoryenumerationresult(path_status_code);
CREATE INDEX idx_dir_enum_priority ON customer_eggs_eggrecords_general_models_directoryenumerationresult(priority_score);
CREATE INDEX idx_dir_enum_cms ON customer_eggs_eggrecords_general_models_directoryenumerationresult(detected_cms);
CREATE INDEX idx_dir_enum_port ON customer_eggs_eggrecords_general_models_directoryenumerationresult(correlated_port);
CREATE INDEX idx_dir_enum_egg_priority ON customer_eggs_eggrecords_general_models_directoryenumerationresult(egg_record_id, priority_score);
CREATE INDEX idx_dir_enum_egg_cms ON customer_eggs_eggrecords_general_models_directoryenumerationresult(egg_record_id, detected_cms);
```

## Future Enhancements

1. **Golang Dirsearch**: Implement high-performance Go version for faster enumeration
2. **Oak Integration**: Use directory enumeration data for CVE/Nuclei template prediction
3. **Machine Learning**: Learn from successful enumeration patterns
4. **Real-time Updates**: WebSocket updates during enumeration
5. **Batch Processing**: Enumerate multiple targets in parallel
6. **Custom Wordlist Generation**: Generate wordlists from discovered paths
7. **Path Pattern Learning**: Learn common path patterns per technology stack

## Usage Example

```python
from suzu.directory_enumerator import SuzuDirectoryEnumerator

enumerator = SuzuDirectoryEnumerator()

# Enumerate an EggRecord
result = enumerator.enumerate_egg_record(
    egg_record_id="123e4567-e89b-12d3-a456-426614174000",
    write_to_db=True
)

# Results are stored in DirectoryEnumerationResult model
# with full metadata correlation:
# - Nmap scan data
# - CMS detection
# - Technology fingerprints
# - Priority scores
```

## Files Created/Modified

1. ✅ `artificial_intelligence/customer_eggs_eggrecords_general_models/models.py` - Added DirectoryEnumerationResult model
2. ✅ `suzu/cms_detector.py` - New CMS detection service
3. ✅ `suzu/priority_scorer.py` - New priority scoring system
4. ✅ `suzu/enhanced_dirsearch.py` - New enhanced dirsearch wrapper
5. ✅ `suzu/directory_enumerator.py` - Updated with new integrations

## Next Steps

1. Create database migration for DirectoryEnumerationResult table
2. Test enumeration with real targets
3. Integrate with Oak for CVE/Nuclei template prediction
4. Add Golang dirsearch implementation
5. Extend CMS detection patterns
6. Add more technology fingerprint correlations

