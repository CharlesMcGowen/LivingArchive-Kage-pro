<div align="center">
  <img src="images/Kage-banner.png" alt="Kage Reconnaissance Team Banner">
</div>

# LivingArchive-Kage-Pro - Autonomous Reconnaissance Platform

**Enterprise-grade autonomous reconnaissance system with multiple AI-driven agents for comprehensive network security assessment.**

[![Python 3.13+](https://img.shields.io/badge/python-3.13+-blue.svg)](https://www.python.org/downloads/)
[![Django](https://img.shields.io/badge/django-5.0+-green.svg)](https://www.djangoproject.com/)
[![Docker](https://img.shields.io/badge/docker-ready-blue.svg)](https://www.docker.com/)

## 🎯 Overview

**LivingArchive-Kage-Pro** is a production-ready, multi-agent reconnaissance platform that autonomously performs network scanning, web crawling, directory enumeration, and threat assessment. The system consists of specialized daemon agents that work together to provide comprehensive security reconnaissance capabilities.

### Key Highlights

- 🤖 **5 Autonomous Agents**: Kage, Kaze, Kumo, Ryu, and Suzu work independently and in coordination
- 🐳 **Docker-Ready**: Full containerization with Docker Compose for easy deployment
- 📊 **Comprehensive Dashboards**: Real-time monitoring and visualization of all agent activities
- 🔄 **API-Based Architecture**: Clean separation between agents and Django backend
- 🎯 **Intelligent Coordination**: Oak AI coordinator for target curation and task management
- 📈 **Learning System**: Adaptive techniques that improve over time
- 🛡️ **Production Features**: Health checks, graceful shutdown, retry logic, monitoring

## 🚀 Quick Start

### Prerequisites

- Python 3.13+
- PostgreSQL (for Django backend)
- Nmap installed (`apt-get install nmap` or `brew install nmap`)
- Docker & Docker Compose (recommended)

### Docker Deployment (Recommended)

```bash
# Clone the repository
git clone git@github.com:CharlesMcGowen/LivingArchive-Kage-pro.git
cd LivingArchive-Kage-pro

# Start all services (Django + all daemons)
cd docker
docker-compose up -d

# View logs
docker-compose logs -f

# Access web interface
open http://localhost:9000/reconnaissance/
```

### Manual Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Set up database (PostgreSQL)
# Configure settings in ryu_project/settings.py

# Run migrations
python manage.py migrate

# Start Django server
python manage.py runserver

# In separate terminals, start daemons
python daemons/manage_daemons.py start all
```

See [DEMO_GUIDE.md](DEMO_GUIDE.md) for detailed setup and demonstration instructions.

## 🏗️ Architecture

### Agent Ecosystem

The platform consists of five specialized reconnaissance agents:

| Agent | Purpose | Capabilities |
|-------|---------|--------------|
| **Kage** (Shadow) | Port Scanner | Fast Nmap-based port scanning, service detection, WAF fingerprinting |
| **Kaze** (Wind) | High-Speed Scanner | Parallel scanning, optimized for high-volume targets |
| **Kumo** (Spider) | Web Crawler | HTTP/HTTPS spidering, endpoint discovery, content analysis |
| **Ryu** (Dragon) | Threat Assessment | Comprehensive port scanning (1-65535), security analysis, vulnerability assessment |
| **Suzu** (Bell) | Directory Enumerator | CMS detection, intelligent path discovery, vector-based learning |

### System Components

```
┌─────────────────────────────────────────────────────────────┐
│                    Django Backend (Port 9000)                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │   API Layer  │  │  Dashboards  │  │   Database   │      │
│  │  (REST API)  │  │  (Django)    │  │ (PostgreSQL) │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└─────────────────────────────────────────────────────────────┘
                            ↕ HTTP API
┌─────────────────────────────────────────────────────────────┐
│                    Autonomous Agents (Daemons)               │
│  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐  ┌──────┐         │
│  │ Kage │  │ Kaze │  │ Kumo │  │ Ryu  │  │ Suzu │         │
│  │ Port │  │ Fast │  │ Web  │  │ Full │  │ Dir  │         │
│  │Scan  │  │Scan  │  │Crawl │  │Scan  │  │Enum  │         │
│  └──────┘  └──────┘  └──────┘  └──────┘  └──────┘         │
└─────────────────────────────────────────────────────────────┘
                            ↕
┌─────────────────────────────────────────────────────────────┐
│                   Oak AI Coordinator                         │
│          (Target Curation & Task Management)                 │
└─────────────────────────────────────────────────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed architecture documentation.

## ✨ Features

### Core Capabilities

- **Multi-Agent Reconnaissance**: Five specialized agents work independently and in coordination
- **Intelligent Target Management**: Oak AI coordinator curates targets and manages agent workloads
- **Comprehensive Scanning**: Port scanning (selective and full 1-65535), service detection, WAF fingerprinting
- **Web Crawling**: Automated HTTP/HTTPS spidering with content analysis
- **Directory Enumeration**: CMS-aware path discovery with vector-based learning
- **Threat Assessment**: Security analysis and vulnerability identification
- **Network Visualization**: Interactive graph visualization of discovered infrastructure
- **Learning System**: Adaptive techniques that improve effectiveness over time

### Production Features

- **Docker Containerization**: All services containerized with health checks
- **API-Based Architecture**: Clean separation via REST APIs
- **Graceful Shutdown**: Proper signal handling for clean stops
- **Auto-Recovery**: Exponential backoff retry logic for resilience
- **Health Monitoring**: Built-in health checks for all services
- **Pause/Resume**: Control daemons without full restart
- **Comprehensive Logging**: Structured logging with agent identification

See [FEATURES.md](FEATURES.md) for complete feature documentation.

## 📊 Dashboards

Access comprehensive dashboards at `http://localhost:9000/reconnaissance/`:

- **General Dashboard**: Overview of all agent activities
- **Kage Dashboard**: Port scan results and statistics
- **Kaze Dashboard**: High-speed scan results
- **Kumo Dashboard**: Web crawl results and discovered endpoints
- **Ryu Dashboard**: Threat assessments and vulnerability data
- **Suzu Dashboard**: Directory enumeration results
- **Oak Dashboard**: Target curation and coordination metrics
- **Learning Dashboard**: Technique effectiveness and adaptive learning metrics
- **Network Visualizer**: Interactive graph of discovered infrastructure

## 🛠️ Configuration

### Environment Variables

```bash
# Django API Configuration
export DJANGO_API_BASE="http://127.0.0.1:9000"

# Agent Configuration
export KAGE_SCAN_INTERVAL=30
export KAGE_MAX_SCANS=5

export KAZE_SCAN_INTERVAL=30
export KAZE_MAX_SCANS=5

export KUMO_SPIDER_INTERVAL=45
export KUMO_MAX_SPIDERS=3

export RYU_SCAN_INTERVAL=30
export RYU_ASSESSMENT_INTERVAL=60
export RYU_MAX_SCANS=5
export RYU_MAX_ASSESSMENTS=2

export SUZU_ENUM_INTERVAL=60
export SUZU_MAX_ENUMS=3
```

### Agent Configuration Files

Agent-specific configurations can be set in `config/agents/` directory. See `config/agents/README.md` for details.

## 📚 Documentation

- **[DEMO_GUIDE.md](DEMO_GUIDE.md)** - Step-by-step demonstration guide
- **[ARCHITECTURE.md](ARCHITECTURE.md)** - System architecture and design
- **[FEATURES.md](FEATURES.md)** - Complete feature documentation
- **[docker/README.md](docker/README.md)** - Docker deployment guide
- **[docs/DJANGO_ORM_POSTGRES_SETUP.md](docs/DJANGO_ORM_POSTGRES_SETUP.md)** - Database setup

## 🔧 Development

### Project Structure

```
LivingArchive-Kage-pro/
├── daemons/              # Agent daemon scripts
│   ├── kage_daemon.py
│   ├── kaze_daemon.py
│   ├── kumo_daemon.py
│   ├── ryu_daemon.py
│   └── suzu_daemon.py
├── ryu_app/              # Django application
│   ├── views.py          # Dashboard views
│   ├── daemon_api.py     # API endpoints
│   └── templates/        # HTML templates
├── kage/                 # Kage scanner implementation
├── kaze/                 # Kaze scanner implementation
├── kumo/                 # Kumo spider implementation
├── ryu/                  # Ryu threat assessment
├── suzu/                 # Suzu directory enumerator
├── artificial_intelligence/
│   └── personalities/
│       └── reconnaissance/
│           └── oak/      # Oak AI coordinator
└── docker/               # Docker configuration
```

### Running Tests

```bash
# Run Django tests
python manage.py test

# Test individual agents
python -m pytest tests/
```

## 🎓 Use Cases

- **Penetration Testing**: Automated reconnaissance phase
- **Bug Bounty Programs**: Continuous target discovery and scanning
- **Security Audits**: Comprehensive network assessment
- **Threat Intelligence**: Infrastructure mapping and analysis
- **Research & Development**: Reconnaissance technique development

## 🤝 Contributing

This is a professional/portfolio project. For questions or discussions, please open an issue.

## 📄 License

See [LICENSE](LICENSE) file for details.

## 👤 Author

**EGO Revolution**

---

**Built with:** Python, Django, PostgreSQL, Docker, Nmap, and lots of ☕
