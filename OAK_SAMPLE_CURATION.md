# Oak Sample Curation

## Overview

Tools to force-curate a sample of random EggRecords with Oak for testing and examination.

## Usage

### Option 1: Django Management Command (CLI)

```bash
# Curate 10 random EggRecords
python manage.py oak_curate_sample

# Curate 20 random EggRecords
python manage.py oak_curate_sample --count 20

# Only curate alive EggRecords
python manage.py oak_curate_sample --count 10 --alive-only

# Verbose output showing all steps
python manage.py oak_curate_sample --count 10 --verbose
```

**Output**:
- Real-time progress for each EggRecord
- Summary statistics
- Detailed results saved to JSON file: `oak_curation_sample_YYYYMMDD_HHMMSS.json`

### Option 2: API Endpoint (Web/HTTP)

```bash
# Curate 10 random EggRecords
curl -X POST http://localhost:8000/api/oak/curate-sample/ \
  -H "Content-Type: application/json" \
  -d '{"count": 10}'

# Only curate alive EggRecords
curl -X POST http://localhost:8000/api/oak/curate-sample/ \
  -H "Content-Type: application/json" \
  -d '{"count": 10, "alive_only": true}'
```

**Response**:
```json
{
    "success": true,
    "count": 10,
    "summary": {
        "successful": 8,
        "failed": 2,
        "total_fingerprints": 25,
        "total_cve_matches": 12,
        "total_templates_selected": 45,
        "average_confidence_score": 67.5
    },
    "results": [
        {
            "egg_record_id": "uuid",
            "subdomain": "example.com",
            "alive": true,
            "success": true,
            "fingerprints_created": 3,
            "cve_matches": 2,
            "recommendations": 1,
            "confidence_score": 75.5,
            "templates_selected": 5,
            "steps_completed": [
                "http_metadata_collected",
                "fingerprinting",
                "confidence_calculation",
                "nuclei_template_selection",
                "vulnerability_profile"
            ],
            "nuclei_templates": {
                "success": true,
                "template_count": 5,
                "fingerprints_used": 2,
                "cve_matches_used": 2,
                "open_ports_used": 1
            },
            "nmap_scan_status": {
                "success": true,
                "scan_exists": true,
                "scan_id": "uuid"
            }
        }
    ]
}
```

## What Gets Curated

For each EggRecord, Oak performs:

1. **HTTP Metadata Check** - Checks for existing HTTP request metadata
2. **Technology Fingerprinting** - Creates fingerprints from Nmap scans
3. **CVE Correlation** - Matches fingerprints to CVEs
4. **Confidence Calculation** - Calculates curation confidence score
5. **Nmap Scan Coordination** - Ensures Nmap scan exists (triggers if needed)
6. **Nuclei Template Selection** - Selects templates based on fingerprints/CVEs
7. **Vulnerability Profile** - Creates vulnerability profile

## Results Examination

### Management Command Output

The command saves detailed results to a JSON file:
- Location: `oak_curation_sample_YYYYMMDD_HHMMSS.json`
- Contains full curation results for each EggRecord
- Includes all metadata, fingerprints, CVE matches, templates, etc.

### API Response

The API returns:
- Summary statistics across all curated EggRecords
- Individual results for each EggRecord
- Success/failure status
- Step-by-step completion status
- Template selection details

## Example Output

```
🌳 Oak Sample Curation - Selecting 10 random EggRecords...
✅ Found 10 EggRecords to curate

[1/10] Curating: example.com (ID: uuid)
  ✅ Success
     Fingerprints: 3
     CVE Matches: 2
     Recommendations: 1
     Confidence: 75.5%
     Templates Selected: 5

[2/10] Curating: test.example.com (ID: uuid)
  ✅ Success
     Fingerprints: 2
     CVE Matches: 1
     Recommendations: 0
     Confidence: 45.2%
     Templates Selected: 3

...

============================================================
📊 Curation Summary
============================================================
Total Curated: 10
Successful: 8 (80.0%)
Total Fingerprints Created: 25
Total CVE Matches: 12
Total Templates Selected: 45
Average Confidence Score: 67.5%

💾 Detailed results saved to: oak_curation_sample_20240101_120000.json
✅ Sample curation complete!
```

## Use Cases

1. **Testing Template Selection** - Verify templates are being selected correctly
2. **Examining Fingerprinting** - See what technologies are being detected
3. **CVE Correlation Testing** - Check if CVEs are being matched properly
4. **Performance Testing** - Measure curation speed and success rate
5. **Debugging** - Identify issues with specific EggRecords

## Files Created

1. ✅ `ryu_app/management/commands/oak_curate_sample.py` - Django management command
2. ✅ `ryu_app/views.py` - Added `oak_curate_sample_api()` function
3. ✅ `ryu_app/urls.py` - Added `/api/oak/curate-sample/` route

## Status

✅ **Complete** - Sample curation tools ready to use

