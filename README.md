# KageKumoRyu - Autonomous Reconnaissance Agents

Standalone daemon agents for network reconnaissance, port scanning, web spidering, and threat assessment.

## Overview

**KageKumoRyu** consists of three autonomous daemon agents:

- **Kage (Shadow)** - Port Scanner: Fast Nmap-based port scanning and service detection
- **Kumo (Spider)** - Web Spider: HTTP/HTTPS crawling and endpoint discovery  
- **Ryu (Dragon)** - Threat Assessment: Security analysis and vulnerability assessment

Each agent runs as an independent daemon process that communicates with a Django API server via HTTP.

## Features

- 🚀 **Standalone Daemons**: Independent processes with their own PIDs
- 🐳 **Docker Ready**: Full containerization support with health checks
- ⏸️ **Pause/Resume**: Control daemons without full restart
- 🔄 **Auto-Recovery**: Exponential backoff retry logic
- 🛑 **Graceful Shutdown**: Proper signal handling for clean stops
- 📊 **Health Checks**: Built-in health monitoring endpoints
- 🔌 **API-Based**: Clean separation via HTTP API

## Quick Start

### Prerequisites

- Python 3.13+
- Nmap installed (`apt-get install nmap` or `brew install nmap`)
- Django server running (for API communication)

### Installation

```bash
# Clone the repository
git clone <your-repo-url>
cd KageKumoRyu

# Install dependencies
pip install -r requirements.txt

# Configure environment
export DJANGO_API_BASE="http://127.0.0.1:9000"
```

### Running Daemons

```bash
# Start all daemons
python3 daemons/manage_daemons.py start all

# Start specific daemon
python3 daemons/manage_daemons.py start kage

# Check status
python3 daemons/manage_daemons.py status

# Pause/Resume
python3 daemons/manage_daemons.py pause kage
python3 daemons/manage_daemons.py resume kage

# Stop
python3 daemons/manage_daemons.py stop all
```

### Docker Deployment

```bash
cd docker

# Build and start all daemons
docker-compose up -d

# View logs
docker-compose logs -f kage-daemon

# Stop
docker-compose down
```

## Architecture

```
KageKumoRyu/
├── daemons/           # Daemon scripts
│   ├── kage_daemon.py
│   ├── kumo_daemon.py
│   ├── ryu_daemon.py
│   └── manage_daemons.py
├── kage/              # Kage (Port Scanner) source
│   ├── nmap_scanner.py
│   └── ...
├── kumo/              # Kumo (Web Spider) source
│   ├── http_spider.py
│   └── ...
├── ryu/               # Ryu (Threat Assessment) source
│   └── ...
├── docker/            # Docker configuration
│   ├── Dockerfile
│   ├── docker-compose.yml
│   └── README.md
├── daemon_api.py      # Django API endpoints (for reference)
├── llm_enhancer.py    # LLM integration (optional)
├── fallback_storage.py # Fallback storage system
└── requirements.txt
```

## API Endpoints

The daemons communicate with Django via these endpoints:

- `GET /reconnaissance/api/daemon/<personality>/eggrecords/` - Get targets to process
- `POST /reconnaissance/api/daemon/<personality>/scan/` - Submit scan results
- `POST /reconnaissance/api/daemon/spider/` - Submit spider results
- `POST /reconnaissance/api/daemon/assessment/` - Submit threat assessments
- `GET /reconnaissance/api/daemon/<personality>/health/` - Health check

## Configuration

Environment variables:

```bash
# Django API base URL
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

## Signal Handling

- **SIGTERM/SIGINT**: Graceful shutdown (finishes current work)
- **SIGUSR1**: Pause daemon
- **SIGUSR2**: Resume daemon

## Docker Commands

```bash
# Start all
docker-compose up -d

# Pause daemon
docker kill --signal=SIGUSR1 recon-kage

# Resume daemon
docker kill --signal=SIGUSR2 recon-kage

# Stop gracefully
docker stop recon-kage

# View logs
docker logs -f recon-kage
```

## Development

This is an isolated version extracted from the main EgoWebs1 project. The agents are designed to work independently via API communication.

## License

[Add your license here]

## Author

EGO Revolution

