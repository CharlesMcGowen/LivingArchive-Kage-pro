# Dashboard Population Issues - Analysis

## Root Causes Identified

### 1. **KAZE Dashboard - Not Populating**

**Problem**: Kaze daemon cannot initialize scanner
- **Error**: `IndentationError: expected an indented block after 'try' statement on line 68 (nmap_scanner.py, line 69)`
- **Location**: Container has malformed syntax in `/app/kage/nmap_scanner.py`
- **Impact**: `self.scanner = None`, so no scans can be performed
- **Result**: No `kaze_port_scan` records in database → Empty dashboard

**Fix Required**: Rebuild Kaze container to get correct source code:
```bash
docker compose build --no-cache kaze-daemon
docker compose up -d kaze-daemon
```

### 2. **RYU Dashboard - Not Populating**

**Problem**: Ryu needs scan data before it can assess
- **Logic**: Ryu queries for eggrecords that have scan OR HTTP data
- **Query**: `EXISTS (SELECT 1 FROM nmap ...) OR EXISTS (SELECT 1 FROM requestmetadata ...)`
- **Issue**: If Kage/Kaze aren't producing scans, Ryu has nothing to assess
- **Result**: No `ryu_port_scan` or assessment records → Empty dashboard

**Fix**: Once Kage/Kaze are working, Ryu should start producing data

### 3. **KUMO Dashboard - May Not Be Populating**

**Problem**: Dashboard queries for specific user_agent patterns
- **Query**: `Q(user_agent__icontains='Kumo') | Q(session_id__icontains='kumo')`
- **Issue**: Kumo daemon might not be setting these fields correctly
- **Check**: Verify Kumo is setting user_agent and session_id in request metadata

### 4. **SUZU Dashboard - May Not Be Populating**

**Problem**: Similar to Kumo - queries for specific patterns
- **Query**: `Q(user_agent__icontains='Suzu') | Q(session_id__startswith='suzu-')`
- **Issue**: Suzu daemon might not be setting these fields correctly
- **Check**: Verify Suzu is setting user_agent and session_id

## API Endpoint Verification

### Kaze API
- **Endpoint**: `/reconnaissance/api/daemon/kaze/eggrecords/`
- **Query**: Finds eggrecords needing `kaze_port_scan`
- **Status**: API should work, but daemon can't process due to scanner error

### Ryu API  
- **Endpoint**: `/reconnaissance/api/daemon/ryu/eggrecords/`
- **Query**: Finds eggrecords with scan OR HTTP data
- **Status**: API should work, but may return empty if no scan data exists

### Kumo API
- **Endpoint**: `/reconnaissance/api/daemon/kumo/eggrecords/`
- **Query**: Finds eggrecords needing HTTP spidering
- **Status**: Should work if daemon is running

### Suzu API
- **Endpoint**: `/reconnaissance/api/daemon/suzu/eggrecords/`
- **Query**: (Need to check if this endpoint exists)
- **Status**: Unknown

## Diagnostic Steps

1. **Check Database for Data**:
   ```python
   # Run check_dashboard_data.py
   python3 check_dashboard_data.py
   ```

2. **Check Daemon Logs**:
   ```bash
   docker logs recon-kaze --tail 50
   docker logs recon-ryu --tail 50
   docker logs recon-kumo --tail 50
   docker logs recon-suzu --tail 50
   ```

3. **Test API Endpoints**:
   ```bash
   curl http://127.0.0.1:9000/reconnaissance/api/daemon/kaze/eggrecords/?limit=5
   curl http://127.0.0.1:9000/reconnaissance/api/daemon/ryu/eggrecords/?limit=5
   curl http://127.0.0.1:9000/reconnaissance/api/daemon/kumo/eggrecords/?limit=5
   ```

4. **Check Scanner Initialization**:
   ```bash
   docker exec recon-kaze python3 -c "from kage.nmap_scanner import get_kage_scanner; print(get_kage_scanner())"
   ```

## Recommended Fixes

1. **Fix Kaze Scanner** (CRITICAL):
   - Rebuild container with correct source
   - Verify scanner initializes
   - Check logs for successful scans

2. **Verify Kumo/Suzu Data Format**:
   - Check if user_agent and session_id are being set
   - Update daemon code if needed
   - Update dashboard queries if field names are different

3. **Check Ryu Dependencies**:
   - Ensure Kage/Kaze are producing scan data
   - Verify Ryu can find eggrecords with scan data
   - Check if assessment logic is working

4. **Add Debugging**:
   - Add logging to dashboard views
   - Log query results
   - Log exceptions

