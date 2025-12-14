# Daemon Parallel Execution Logic

## Overview

The reconnaissance system uses multiple daemons that can run in parallel, each with different responsibilities and data dependencies.

## Daemon Architecture

### 1. **Kage Daemon** - Standard Port Scanner
- **Scan Type**: `kage_port_scan`
- **Purpose**: Standard Nmap port scanning
- **Interval**: 30 seconds
- **Max Scans/Cycle**: 5
- **Database Query**: Finds eggrecords that need `kage_port_scan` OR haven't been scanned in 24 hours
- **Status**: ✅ Running (but has SessionLocal() bug)

### 2. **Kaze Daemon** - High-Speed Port Scanner  
- **Scan Type**: `kaze_port_scan`
- **Purpose**: Maximum throughput port scanning (optimized for speed)
- **Interval**: 15 seconds (faster than Kage)
- **Max Scans/Cycle**: 10 (more than Kage)
- **Database Query**: Finds eggrecords that need `kaze_port_scan` OR haven't been scanned in 24 hours
- **Status**: ⚠️ Running but scanner initialization failed (syntax error in nmap_scanner.py)

### 3. **Kumo Daemon** - HTTP Spider
- **Purpose**: HTTP spidering and web content discovery
- **Interval**: 45 seconds
- **Max Spiders/Cycle**: 3
- **Database Query**: Finds eggrecords that need HTTP spidering OR haven't been spidered in 6 months
- **Status**: ✅ Running

### 4. **Ryu Daemon** - Threat Assessment
- **Scan Type**: `ryu_port_scan` (for additional scanning)
- **Purpose**: Threat assessment and vulnerability analysis
- **Intervals**: 
  - Scan: 30 seconds
  - Assessment: 60 seconds
- **Max/Cycle**: 5 scans, 2 assessments
- **Database Query**: Finds eggrecords that:
  - Have scan data (from Kage/Kaze) OR HTTP data (from Kumo)
  - Don't have recent assessments (< 7 days)
  - Prioritizes records with BOTH scan AND HTTP data
- **Status**: ✅ Running

### 5. **Suzu Daemon** - Directory Enumeration
- **Purpose**: Directory and file enumeration
- **Interval**: 60 seconds
- **Max Enums/Cycle**: 2
- **Status**: ✅ Defined but needs verification

## Parallel Execution Logic

### Why Kage and Kaze CAN Run in Parallel

1. **Different Scan Types**: 
   - Kage uses `kage_port_scan`
   - Kaze uses `kaze_port_scan`
   - They query the database with different `scan_type` filters

2. **Separate Database Queries**:
   ```sql
   -- Kage query
   WHERE n.scan_type = 'kage_port_scan'
   
   -- Kaze query  
   WHERE n.scan_type = 'kaze_port_scan'
   ```

3. **No Data Conflicts**:
   - Each writes to the same `nmap` table but with different `scan_type` values
   - They can scan the same target simultaneously without conflicts
   - Database handles concurrent writes safely

4. **Independent Containers**:
   - Each runs in its own Docker container
   - Separate processes, separate resources
   - No shared state or locks

### Why Ryu Depends on Kage/Kaze/Kumo

1. **Assessment Requires Data**:
   - Ryu needs scan data (from Kage/Kaze) OR HTTP data (from Kumo)
   - Query: `EXISTS (SELECT 1 FROM nmap ...) OR EXISTS (SELECT 1 FROM requestmetadata ...)`

2. **Prioritization**:
   - Records with BOTH scan AND HTTP data get priority
   - This ensures comprehensive assessments

3. **No Direct Dependency**:
   - Ryu doesn't wait for specific scans to complete
   - It just checks if data exists
   - Can run in parallel but will only process records with existing data

## Current Issues

### 1. Kaze Scanner Initialization Error
```
ERROR: ❌ Failed to initialize scanner: expected an indented block after 'try' statement on line 68 (nmap_scanner.py, line 69)
```
**Impact**: Kaze daemon is running but cannot perform scans
**Fix Needed**: Check `nmap_scanner.py` line 68-69 for syntax error

### 2. Kage SessionLocal() Error
```
TypeError: 'NoneType' object is not callable
File: scan_learning_service.py, line 251
```
**Impact**: Kage scans fail when trying to use learning database
**Fix Needed**: Initialize SessionLocal properly in scan_learning_service.py

### 3. Ryu Connection Errors
- Temporary connection refused errors when Django restarts
- This is expected and handled with retry logic
- Not a critical issue

## Docker Container Status

```bash
# Check all daemon containers
docker compose ps

# Expected containers:
- recon-django (Django server)
- recon-kage (Kage daemon)
- recon-kaze (Kaze daemon) - NEWLY ADDED
- recon-kumo (Kumo daemon)
- recon-ryu (Ryu daemon)
- recon-suzu (Suzu daemon)
```

## Recommendations

1. **Fix Kaze Scanner Error**: Check `nmap_scanner.py` syntax
2. **Fix Kage Learning Service**: Initialize SessionLocal properly
3. **Monitor Parallel Execution**: All daemons should run simultaneously
4. **Database Performance**: Monitor for contention with multiple scanners writing simultaneously

## Testing Parallel Execution

To verify parallel execution:
1. Check container logs: `docker logs recon-kage`, `docker logs recon-kaze`
2. Check database for both scan types: `SELECT scan_type, COUNT(*) FROM nmap GROUP BY scan_type`
3. Monitor dashboard - all should show "Running" status
4. Check that scans are happening simultaneously (different targets or same target with different scan types)

