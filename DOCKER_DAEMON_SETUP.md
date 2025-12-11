# Docker Daemon Setup - Kage, Kumo, Ryu, Suzu

## Overview

All daemons are **Python-based** (not Go) and run as Docker containers that communicate with Django via HTTP API.

## Current Status

### ✅ Configured Daemons
- **Kage** - Port Scanner (Python)
- **Kumo** - HTTP Spider (Python)  
- **Ryu** - Threat Assessment (Python)
- **Suzu** - Directory Enumeration (Python) - **NEWLY ADDED**

### Language Implementation
- **All daemons are Python** - No Go implementations found
- Dockerfile installs `golang-go` for tools (ffuf, gobuster) used by Suzu, but daemons themselves are Python
- Kage, Kaze, Ryu daemons are Python scripts, not Go binaries

## Docker Compose Setup

All daemons are configured in `docker/docker-compose.yml`:

```yaml
services:
  django-server:    # Django API server
  kage-daemon:      # Port scanner
  kumo-daemon:      # HTTP spider
  ryu-daemon:       # Threat assessment
  suzu-daemon:      # Directory enumeration (NEW)
```

## Starting Daemons

### Using Docker Compose

```bash
cd /media/ego/328010BE80108A8D2/github_public/LivingArchive-Kage-pro/docker

# Start all daemons
docker-compose up -d

# Start specific daemon
docker-compose up -d kumo-daemon
docker-compose up -d suzu-daemon

# Check status
docker-compose ps

# View logs
docker-compose logs -f kumo-daemon
docker-compose logs -f suzu-daemon

# Stop daemons
docker-compose stop kumo-daemon
docker-compose down  # Stop all
```

### Using Management Script (Local)

```bash
cd /media/ego/328010BE80108A8D2/github_public/LivingArchive-Kage-pro

# Check status
python3 daemons/manage_daemons.py status all

# Start daemons
python3 daemons/manage_daemons.py start kumo
python3 daemons/manage_daemons.py start suzu
python3 daemons/manage_daemons.py start all

# Stop daemons
python3 daemons/manage_daemons.py stop kumo
python3 daemons/manage_daemons.py stop all
```

## Suzu Daemon Details

### Tools Used
- **dirsearch** (Python) - Primary enumeration tool
- **ffuf** (Go binary) - Fallback enumeration tool
- **gobuster** (Go binary) - Available but not used by default

### Configuration
- `SUZU_ENUM_INTERVAL=60` - Seconds between enumeration cycles
- `SUZU_MAX_ENUMS=2` - Max enumerations per cycle
- Enumeration timeout: 5 minutes per target

### API Endpoints
- `GET /reconnaissance/api/daemon/suzu/eggrecords/` - Get targets to enumerate
- `POST /reconnaissance/api/daemon/enumeration/` - Submit enumeration results
- `GET /reconnaissance/api/daemon/suzu/health/` - Health check

## Kumo Daemon Details

### Implementation
- **Python-based** (not Go)
- Uses `kumo.http_spider.KumoHttpSpider` class
- Communicates with Django via HTTP API

### Configuration
- `KUMO_SPIDER_INTERVAL=45` - Seconds between spider cycles
- `KUMO_MAX_SPIDERS=3` - Max spiders per cycle

## Pipeline Verification

### Test Docker Compose Build

```bash
cd /media/ego/328010BE80108A8D2/github_public/LivingArchive-Kage-pro/docker

# Build all containers
docker-compose build

# Verify containers can start (dry run)
docker-compose config

# Start in foreground to see logs
docker-compose up
```

### Test Individual Daemons

```bash
# Test Kumo daemon
docker-compose up kumo-daemon

# Test Suzu daemon  
docker-compose up suzu-daemon
```

### Health Checks

Each daemon has a health check endpoint:
- `http://django-server:9000/reconnaissance/api/daemon/kumo/health/`
- `http://django-server:9000/reconnaissance/api/daemon/suzu/health/`

Test manually:
```bash
curl http://localhost:9000/reconnaissance/api/daemon/kumo/health/
curl http://localhost:9000/reconnaissance/api/daemon/suzu/health/
```

## Environment Variables

All daemons use these environment variables:

```bash
# Django API connection
DJANGO_API_BASE=http://django-server:9000

# Kumo configuration
KUMO_SPIDER_INTERVAL=45
KUMO_MAX_SPIDERS=3

# Suzu configuration
SUZU_ENUM_INTERVAL=60
SUZU_MAX_ENUMS=2

# Kage configuration
KAGE_SCAN_INTERVAL=30
KAGE_MAX_SCANS=5

# Ryu configuration
RYU_SCAN_INTERVAL=30
RYU_ASSESSMENT_INTERVAL=60
RYU_MAX_SCANS=5
RYU_MAX_ASSESSMENTS=2
```

## Troubleshooting

### Daemon Not Starting
1. Check Django server is running: `curl http://localhost:9000/reconnaissance/`
2. Check logs: `docker-compose logs daemon-name`
3. Verify database connection in Django
4. Check PID files: `ls -la /tmp/*daemon*.pid`

### API Connection Issues
- Verify `DJANGO_API_BASE` environment variable
- Check network connectivity: `docker network ls`
- Verify containers are on same network: `docker network inspect recon-network`

### Suzu Enumeration Issues
- Verify tools are installed: `docker exec recon-suzu which dirsearch`
- Check wordlist exists: `docker exec recon-suzu ls /opt/dirsearch/db/`
- Test tool manually: `docker exec recon-suzu dirsearch -u http://example.com`

## Next Steps

1. **Build and test Docker containers**:
   ```bash
   cd docker
   docker-compose build
   docker-compose up -d
   ```

2. **Verify all daemons start**:
   ```bash
   docker-compose ps
   docker-compose logs -f
   ```

3. **Test API endpoints**:
   ```bash
   curl http://localhost:9000/reconnaissance/api/daemon/kumo/health/
   curl http://localhost:9000/reconnaissance/api/daemon/suzu/health/
   ```

4. **Monitor daemon activity**:
   ```bash
   docker-compose logs -f kumo-daemon
   docker-compose logs -f suzu-daemon
   ```

