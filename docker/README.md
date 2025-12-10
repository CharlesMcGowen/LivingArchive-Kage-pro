# Reconnaissance Daemons

Kage, Kumo, and Ryu now run as **standalone daemon processes** that communicate with Django via API, rather than as threads within Django.

## Architecture

- **Kage Daemon**: Standalone port scanner service
- **Kumo Daemon**: Standalone HTTP spider service  
- **Ryu Daemon**: Standalone threat assessment service (performs both scanning and assessments)

Each daemon:
- Runs as an independent process with its own PID
- Communicates with Django via HTTP API
- Has its own PID file for process management
- Can be started/stopped independently
- Uses named process titles (if `setproctitle` is available)

## API Endpoints

The daemons use these Django API endpoints:

- `GET /reconnaissance/api/daemon/<personality>/eggrecords/` - Get eggrecords to process
- `POST /reconnaissance/api/daemon/<personality>/scan/` - Submit scan results (Kage/Ryu)
- `POST /reconnaissance/api/daemon/spider/` - Submit spider results (Kumo)
- `POST /reconnaissance/api/daemon/assessment/` - Submit threat assessments (Ryu)

## Usage

### Management Script

Use the management script to control all daemons:

```bash
# Check status of all daemons
python3 manage_daemons.py status

# Check status of specific daemon
python3 manage_daemons.py status kage

# Start a daemon
python3 manage_daemons.py start kage
python3 manage_daemons.py start kumo
python3 manage_daemons.py start ryu

# Start all daemons
python3 manage_daemons.py start all

# Stop a daemon
python3 manage_daemons.py stop kage

# Stop all daemons
python3 manage_daemons.py stop all

# Restart a daemon
python3 manage_daemons.py restart kage
python3 manage_daemons.py restart all
```

### Direct Execution

You can also run daemons directly:

```bash
# Run Kage daemon
python3 kage_daemon.py

# Run Kumo daemon
python3 kumo_daemon.py

# Run Ryu daemon
python3 ryu_daemon.py
```

### Environment Variables

Configure daemon behavior with environment variables:

```bash
# Django API base URL (default: http://127.0.0.1:9000)
export DJANGO_API_BASE="http://127.0.0.1:9000"

# Kage configuration
export KAGE_SCAN_INTERVAL=30      # Seconds between scan cycles
export KAGE_MAX_SCANS=5            # Max scans per cycle

# Kumo configuration
export KUMO_SPIDER_INTERVAL=45     # Seconds between spider cycles
export KUMO_MAX_SPIDERS=3          # Max spiders per cycle

# Ryu configuration
export RYU_SCAN_INTERVAL=30        # Seconds between scan cycles
export RYU_ASSESSMENT_INTERVAL=60  # Seconds between assessment cycles
export RYU_MAX_SCANS=5              # Max scans per cycle
export RYU_MAX_ASSESSMENTS=2       # Max assessments per cycle
```

## PID Files

Each daemon creates a PID file in `/tmp/`:
- `/tmp/kage_daemon.pid`
- `/tmp/kumo_daemon.pid`
- `/tmp/ryu_daemon.pid`

These files contain the process ID and are used by the management script to track running daemons.

## Process Names

If `setproctitle` is installed, processes are named:
- `kage-recon-daemon [PID:xxxxx]`
- `kumo-recon-daemon [PID:xxxxx]`
- `ryu-recon-daemon [PID:xxxxx]`

You can find them with:
```bash
ps aux | grep -E "(kage|kumo|ryu)-recon-daemon"
```

## Logging

Each daemon logs to stdout/stderr with prefixes:
- `[KAGE]` - Kage daemon logs
- `[KUMO]` - Kumo daemon logs
- `[RYU]` - Ryu daemon logs

## Docker Deployment

### Quick Start

```bash
# Build and start all daemons
cd /mnt/webapps-nvme/artificial_intelligence/personalities/reconnaissance/daemons
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f kage-daemon
docker-compose logs -f kumo-daemon
docker-compose logs -f ryu-daemon

# Stop all daemons
docker-compose down
```

### Docker Commands

```bash
# Start specific daemon
docker-compose up -d kage-daemon

# Stop specific daemon
docker-compose stop kage-daemon

# Restart specific daemon
docker-compose restart kage-daemon

# Pause daemon (SIGUSR1)
docker kill --signal=SIGUSR1 recon-kage

# Resume daemon (SIGUSR2)
docker kill --signal=SIGUSR2 recon-kage

# View logs
docker logs -f recon-kage

# Execute commands in container
docker exec -it recon-kage bash
```

### Docker Health Checks

Each daemon container includes health checks that verify:
- Container is running
- Can connect to Django API
- Health endpoint responds correctly

Health check status:
```bash
docker inspect --format='{{.State.Health.Status}}' recon-kage
```

### Signal Handling in Docker

- **SIGTERM**: Graceful shutdown (Docker `stop` command)
- **SIGKILL**: Force kill (Docker `kill` command)
- **SIGUSR1**: Pause daemon
- **SIGUSR2**: Resume daemon

Docker automatically sends SIGTERM on `docker stop`, then SIGKILL after 10 seconds if process doesn't stop.

### Container Recovery

With `restart: unless-stopped` policy:
- Containers automatically restart on crash
- Containers restart after Docker daemon restart
- Containers do NOT restart if manually stopped

## Enhanced Features

### Pause/Resume

Daemons can be paused and resumed without stopping:

```bash
# Pause (finishes current task first)
python3 manage_daemons.py pause kage
# Or via Docker:
docker kill --signal=SIGUSR1 recon-kage

# Resume
python3 manage_daemons.py resume kage
# Or via Docker:
docker kill --signal=SIGUSR2 recon-kage
```

### Exponential Backoff Retry

Daemons automatically retry failed API calls with exponential backoff:
- Initial retry: 2 seconds
- Max retry: 60 seconds
- Max attempts: 5
- Resets on successful connection

### Graceful Shutdown

On SIGTERM/SIGINT:
- Daemon finishes current task (max 30 seconds)
- Cleans up resources
- Removes PID file
- Exits cleanly

### Health Check Endpoints

Each daemon has a health check endpoint:
- `GET /reconnaissance/api/daemon/kage/health/`
- `GET /reconnaissance/api/daemon/kumo/health/`
- `GET /reconnaissance/api/daemon/ryu/health/`

Returns:
```json
{
  "success": true,
  "status": "healthy",
  "personality": "kage",
  "database": "connected",
  "functional": true,
  "timestamp": "2025-12-03T20:00:00Z",
  "pid": 12345
}
```

## Benefits of Daemon Architecture

1. **Independence**: Daemons run independently of Django server
2. **Scalability**: Can run on separate machines or containers
3. **Resilience**: Django server restart doesn't affect daemons
4. **Resource Isolation**: Each daemon has its own process space
5. **Easy Monitoring**: Separate PIDs make monitoring easier
6. **API-Based**: Clean separation via HTTP API
7. **Docker-Ready**: Full containerization support with health checks
8. **Graceful Shutdown**: Proper signal handling for clean stops
9. **Auto-Recovery**: Exponential backoff and retry logic
10. **Pause/Resume**: Control daemons without full restart

## Migration from Thread-Based Services

The old thread-based services in `background_services.py` are still available for backward compatibility, but the daemon architecture is recommended for production use.

To migrate:
1. Stop any running thread-based services via Django API
2. Start daemon processes using the management script or Docker
3. Daemons will automatically begin processing eggrecords via API

