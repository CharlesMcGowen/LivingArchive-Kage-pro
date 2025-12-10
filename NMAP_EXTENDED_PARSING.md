# Extended Nmap XML Parsing Implementation

## Overview

This document describes the comprehensive Nmap XML parsing implementation that extracts ALL relevant data from Nmap scans for use in WAF detection, CVE correlation, heuristics learning, and technology fingerprinting.

## What's Been Implemented

### 1. Comprehensive Nmap XML Parser (`_parse_nmap_xml_comprehensive`)

Extracts the following data from Nmap XML output:

#### Host-Level Metadata
- **`nmaprun.args`**: Exact Nmap command used (for heuristics learning)
- **`scaninfo.type`**: Type of scan (Syn Scan, UDP Scan, etc.) - for technique effectiveness
- **`host.status.reason`**: Why host is up/down (for target selection)
- **`osmatch`**: OS detection with accuracy and CPE strings

#### Port-Level Data
- **`state.reason`**: Packet reason for port state (e.g., `syn-ack`, `no-response`) - for WAF/filtering detection
- **`service.extrainfo`**: Additional service details (e.g., HTTP server modules)
- **`service.devicetype`**: Device type (e.g., "load balancer", "proxy")
- **`service.cpe`**: **CRITICAL** - CPE strings for CVE correlation and TechnologyFingerprint creation
- **`service.product`**: Product name (e.g., "nginx", "Apache")
- **`service.version`**: Version string
- **`service.banner`**: Service banner

#### NSE Script Output
- **`script.output`**: Full text output from NSE scripts
- **`script.tables`**: Structured data from NSE scripts
- Scripts like `http-waf-detect`, `http-headers`, `http-title` provide actionable intelligence

### 2. TechnologyFingerprint Creation from CPE (`_create_technology_fingerprint_from_cpe`)

Automatically creates `TechnologyFingerprint` records from CPE strings:

- **Parses CPE format**: `cpe:/a:apache:http_server:2.4.41`
- **Extracts**: vendor, product, version
- **Creates records with**:
  - `technology_name`: "apache http_server"
  - `technology_version`: "2.4.41"
  - `technology_category`: "application" (from CPE part)
  - `confidence_score`: 0.95 (high confidence from CPE)
  - `detection_method`: "nmap_cpe"
  - `raw_detection_data`: Full CPE and parsed components

### 3. Nmap Arguments Storage for Heuristics Learning

Stores Nmap arguments in `calculated_heuristics_rules` table:

- **Parses Nmap command**: Extracts flags and values into structured format
- **Creates/updates rules**: Based on target pattern and scan type
- **Tracks sample count**: Increments for each similar scan
- **Enables learning**: System can learn which Nmap arguments work best for different targets

### 4. Extended Database Storage

The `open_ports` JSONB field now includes:

```json
{
  "port": 443,
  "protocol": "tcp",
  "state": "open",
  "state_reason": "syn-ack",
  "service": "ssl/http-proxy",
  "version": "F5 BIG-IP load balancer http proxy",
  "product": "F5 BIG-IP",
  "extrainfo": "load balancer",
  "devicetype": "load balancer",
  "cpe": ["cpe:/a:f5:big-ip:..."],
  "banner": "...",
  "scripts": [
    {
      "id": "http-waf-detect",
      "output": "...",
      "tables": []
    }
  ]
}
```

## Usage Example

### Before (Basic Parsing)
```python
# Only captured: port, service_name, service_version, banner
port_data = {
    'port': 443,
    'service': 'https',
    'version': 'nginx/1.18.0',
    'banner': '...'
}
```

### After (Comprehensive Parsing)
```python
# Captures: CPE, extrainfo, devicetype, scripts, state_reason, product
port_data = {
    'port': 443,
    'service': 'ssl/http-proxy',
    'version': 'F5 BIG-IP load balancer http proxy',
    'product': 'F5 BIG-IP',
    'extrainfo': 'load balancer',
    'devicetype': 'load balancer',
    'cpe': ['cpe:/a:f5:big-ip:...'],
    'state_reason': 'syn-ack',
    'scripts': [
        {
            'id': 'http-waf-detect',
            'output': 'WAF detected: F5 BIG-IP'
        }
    ]
}

# Automatically creates TechnologyFingerprint from CPE
# Automatically stores Nmap arguments for heuristics learning
```

## Benefits

### 1. CVE Correlation
- **CPE strings** provide standardized identifiers for direct CVE database matching
- **TechnologyFingerprint** records enable automated CVE lookup
- **More accurate** than fuzzy string matching on version strings

### 2. WAF Detection
- **Service devicetype** ("load balancer", "proxy") indicates WAF/proxy presence
- **Service extrainfo** contains additional WAF clues
- **NSE scripts** (`http-waf-detect`) provide direct WAF detection
- **State reasons** help detect filtering/WAF behavior

### 3. Heuristics Learning
- **Nmap arguments** stored for each successful scan
- **Scan type** tracked for technique effectiveness
- **Sample count** enables statistical learning
- **System learns** which arguments work best for different targets

### 4. Technology Fingerprinting
- **Automatic creation** of TechnologyFingerprint from CPE
- **High confidence** (0.95) from standardized CPE format
- **Structured data** enables better CVE matching and vulnerability assessment

## Integration Points

### 1. Nmap Execution
- `_execute_nmap_with_techniques()`: Executes Nmap with `-sV -sC` for version detection and scripts
- Stores results in `self._last_nmap_results` for database storage

### 2. Database Storage
- `_scan_egg_record_impl()`: Uses comprehensive parser results when storing Nmap entries
- Creates TechnologyFingerprint records automatically from CPE strings
- Stores Nmap arguments in heuristics rules

### 3. WAF Detection
- Service fields (devicetype, extrainfo, product) feed into WAF detection logic
- NSE script output provides additional WAF indicators

## Files Modified

- `kage/nmap_scanner.py`:
  - Added `_parse_nmap_xml_comprehensive()` method
  - Added `_parse_script_table()` helper method
  - Added `_create_technology_fingerprint_from_cpe()` method
  - Added `_parse_nmap_args_to_list()` method
  - Added `_execute_nmap_with_techniques()` method
  - Updated database storage to include extended fields
  - Added automatic TechnologyFingerprint creation
  - Added heuristics rule storage

## Next Steps

1. **WAF Detection Integration**: Use service devicetype/extrainfo in WAF detection logic
2. **CVE Matching Service**: Use TechnologyFingerprint CPE for automated CVE lookup
3. **Heuristics Learning**: Use stored Nmap arguments to improve scan strategy selection
4. **NSE Script Analysis**: Parse and utilize NSE script output for actionable intelligence

## Testing

To test the comprehensive parsing:

```bash
# Run a scan that will trigger Nmap execution
# Check database for:
# 1. open_ports JSONB field contains CPE, extrainfo, devicetype, scripts
# 2. TechnologyFingerprint records created from CPE
# 3. calculated_heuristics_rules contains Nmap arguments
```

## Summary

✅ **Comprehensive Nmap XML parsing** - Extracts all relevant data  
✅ **CPE extraction** - Critical for CVE correlation  
✅ **TechnologyFingerprint creation** - Automatic from CPE strings  
✅ **Nmap arguments storage** - For heuristics learning  
✅ **Extended database storage** - All fields preserved in JSONB  
✅ **NSE script support** - Actionable intelligence from scripts  

The system now harvests every relevant piece of data Nmap provides, maximizing the effectiveness of Kage, Kaze, Ryu, Suzu, Kumo, and Oak intelligence systems.

