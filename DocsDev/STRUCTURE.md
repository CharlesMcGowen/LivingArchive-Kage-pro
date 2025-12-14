# KageKumoRyu Repository Structure

## Overview

This is an isolated version of the Kage, Kumo, and Ryu reconnaissance agents extracted from the main EgoWebs1 project for independent GitHub repository.

## Directory Structure

```
KageKumoRyu/
├── daemons/              # Daemon execution scripts
│   ├── kage_daemon.py    # Kage (Port Scanner) daemon
│   ├── kumo_daemon.py    # Kumo (Web Spider) daemon
│   ├── ryu_daemon.py     # Ryu (Threat Assessment) daemon
│   └── manage_daemons.py # Management script (start/stop/pause/resume)
│
├── kage/                 # Kage agent source code
│   ├── nmap_scanner.py   # Main Nmap scanning logic
│   ├── waf_fingerprinting.py
│   ├── scan_learning_service.py
│   └── ... (other Kage modules)
│
├── kumo/                 # Kumo agent source code
│   ├── http_spider.py    # Main HTTP spidering logic
│   └── enhanced_http_spider.py
│
├── ryu/                  # Ryu agent source code
│   ├── threat_assessment_service.py
│   ├── cybersecurity_coordinator.py
│   └── ... (other Ryu modules)
│
├── docker/               # Docker configuration
│   ├── Dockerfile        # Container image definition
│   ├── docker-compose.yml # Multi-container orchestration
│   ├── .dockerignore    # Docker build exclusions
│   └── README.md        # Docker-specific documentation
│
├── daemon_api.py        # Django API endpoints (reference)
├── llm_enhancer.py      # LLM integration (optional)
├── fallback_storage.py  # Fallback storage system
├── requirements.txt     # Python dependencies
├── README.md           # Main documentation
├── STRUCTURE.md        # This file
└── .gitignore          # Git exclusions
```

## Key Files

### Daemon Scripts
- **kage_daemon.py**: Standalone port scanner daemon
- **kumo_daemon.py**: Standalone HTTP spider daemon
- **ryu_daemon.py**: Standalone threat assessment daemon
- **manage_daemons.py**: CLI tool for managing all daemons

### Core Agent Modules
- **kage/nmap_scanner.py**: Nmap scanning, service detection, port discovery
- **kumo/http_spider.py**: HTTP/HTTPS crawling, endpoint discovery
- **ryu/threat_assessment_service.py**: Security analysis, vulnerability assessment

### Supporting Files
- **daemon_api.py**: Django API endpoints that daemons communicate with
- **llm_enhancer.py**: Optional LLM integration for intelligent analysis
- **fallback_storage.py**: JSON-based fallback when database unavailable

## Features Implemented

✅ Standalone daemon processes
✅ Docker containerization
✅ Pause/Resume functionality (SIGUSR1/SIGUSR2)
✅ Graceful shutdown (SIGTERM)
✅ Exponential backoff retry logic
✅ Health check endpoints
✅ Process management scripts
✅ PID file tracking

## Note on Imports

Some source files still contain imports referencing the original project structure (`artificial_intelligence.personalities.reconnaissance`). These would need to be updated for a fully standalone version, but the daemon scripts themselves have been updated to use relative imports.

For inspection purposes, the structure is complete. For production use, you may want to:
1. Update remaining absolute imports to relative imports
2. Create adapter modules for any missing dependencies
3. Test in isolation environment

## Docker Usage

```bash
cd docker
docker-compose up -d
```

## Management Script Usage

```bash
python3 daemons/manage_daemons.py start all
python3 daemons/manage_daemons.py status
python3 daemons/manage_daemons.py pause kage
python3 daemons/manage_daemons.py resume kage
python3 daemons/manage_daemons.py stop all
```

