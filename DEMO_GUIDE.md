# Demo Guide - LivingArchive-Kage-Pro

This guide will walk you through setting up and demonstrating the LivingArchive-Kage-Pro reconnaissance platform.

## 🎯 Demo Overview

The demo showcases:
1. Multi-agent autonomous reconnaissance system
2. Real-time dashboards and monitoring
3. Docker-based deployment
4. Agent coordination and task management
5. Network visualization

## 📋 Prerequisites

### Required Software

```bash
# Check Python version (3.13+ required)
python3 --version

# Check Docker installation
docker --version
docker-compose --version

# Check PostgreSQL (if not using Docker)
psql --version
```

### Required Tools

- Nmap (installed in Docker containers automatically)
- Modern web browser (Chrome, Firefox, Safari, Edge)

## 🚀 Quick Demo Setup (Docker)

### Step 1: Clone and Navigate

```bash
git clone git@github.com:CharlesMcGowen/LivingArchive-Kage-pro.git
cd LivingArchive-Kage-pro
```

### Step 2: Configure Environment

```bash
# Copy example environment file
cp docker/env.example docker/.env

# Edit .env file if needed (defaults work for local demo)
# Key settings:
# - DATABASE settings
# - SECRET_KEY
# - ALLOWED_HOSTS
```

### Step 3: Start All Services

```bash
cd docker

# Build and start all containers
docker-compose up -d --build

# Wait for services to start (30-60 seconds)
# Check status
docker-compose ps

# View logs to verify everything is running
docker-compose logs -f
```

You should see:
- Django server starting on port 9000
- All 5 daemon containers starting (kage, kaze, kumo, ryu, suzu)
- Health checks passing

### Step 4: Access Web Interface

```bash
# Open in browser
open http://localhost:9000/reconnaissance/

# Or navigate manually to:
# http://localhost:9000/reconnaissance/
```

## 📊 Demo Walkthrough

### 1. General Dashboard

**URL:** `http://localhost:9000/reconnaissance/`

**What to Show:**
- Overview of all agent activities
- Recent scan results from all agents
- System statistics

**Key Points:**
- "Here's our general dashboard showing activity from all 5 agents"
- "Real-time updates as agents perform reconnaissance"
- "Each agent has specialized capabilities"

### 2. Agent-Specific Dashboards

Navigate through each agent dashboard:

#### Kage Dashboard
**URL:** `http://localhost:9000/reconnaissance/kage/`

**What to Show:**
- Port scan results
- Service detection data
- WAF fingerprinting results
- Filtering and search capabilities

**Talking Points:**
- "Kage performs intelligent port scanning using Nmap"
- "Automatically detects services and fingerprinting WAFs"
- "Adaptive scanning strategies based on target characteristics"

#### Kaze Dashboard
**URL:** `http://localhost:9000/reconnaissance/kaze/`

**What to Show:**
- High-speed scan results
- Parallel scanning capabilities
- Performance metrics

**Talking Points:**
- "Kaze is optimized for high-volume scanning"
- "Uses parallel processing for efficiency"
- "Complements Kage with faster scanning for large target sets"

#### Kumo Dashboard
**URL:** `http://localhost:9000/reconnaissance/kumo/`

**What to Show:**
- Web crawl results
- Discovered endpoints
- Content analysis

**Talking Points:**
- "Kumo spiders web applications"
- "Discovers endpoints, forms, and content"
- "Integrates with port scan data for comprehensive coverage"

#### Ryu Dashboard
**URL:** `http://localhost:9000/reconnaissance/ryu/`

**What to Show:**
- Comprehensive port scans (1-65535)
- Threat assessments
- Vulnerability data

**Talking Points:**
- "Ryu performs deep scanning - all 65,535 ports"
- "Provides threat assessments and vulnerability analysis"
- "Most thorough scanning agent"

#### Suzu Dashboard
**URL:** `http://localhost:9000/reconnaissance/suzu/`

**What to Show:**
- Directory enumeration results
- CMS detection
- Path discovery

**Talking Points:**
- "Suzu discovers directories and files"
- "CMS-aware enumeration"
- "Uses vector-based learning to improve over time"

### 3. Oak Dashboard (AI Coordinator)

**URL:** `http://localhost:9000/reconnaissance/oak/`

**What to Show:**
- Target curation metrics
- Agent coordination statistics
- Template management

**Talking Points:**
- "Oak is our AI coordinator"
- "Curates targets and manages agent workloads"
- "Intelligent task distribution and prioritization"

### 4. Network Visualizer

**URL:** `http://localhost:9000/reconnaissance/network/`

**What to Show:**
- Interactive graph visualization
- Network relationships
- IP/CIDR/ASN mapping

**Talking Points:**
- "Interactive visualization of discovered infrastructure"
- "Shows relationships between IPs, CIDRs, and ASNs"
- "Built with Cytoscape.js for performance"

### 5. Learning Dashboard

**URL:** `http://localhost:9000/reconnaissance/learning/`

**What to Show:**
- Technique effectiveness metrics
- Adaptive learning statistics
- Heuristics and patterns

**Talking Points:**
- "System learns from results"
- "Techniques improve over time"
- "Adaptive reconnaissance strategies"

### 6. EggRecords Management

**URL:** `http://localhost:9000/reconnaissance/eggrecords/`

**What to Show:**
- Target management interface
- Create/edit targets
- Filtering and search

**Talking Points:**
- "Centralized target management"
- "Agents fetch targets from here via API"
- "Comprehensive filtering and organization"

## 🔍 Live Demo Scenarios

### Scenario 1: Add a Target and Watch Agents Work

1. Go to EggRecords page
2. Create a new target (use a test domain you own or have permission to scan)
3. Navigate to General Dashboard
4. Watch as agents automatically pick up and scan the target
5. Show real-time updates appearing in dashboards

**Talking Points:**
- "Agents work autonomously"
- "No manual intervention needed"
- "Real-time updates across all dashboards"

### Scenario 2: Agent Coordination

1. Show Oak Dashboard
2. Explain how Oak coordinates multiple agents
3. Show how agents avoid duplicate work
4. Demonstrate load balancing across agents

**Talking Points:**
- "Intelligent coordination prevents duplicate work"
- "Agents focus on their specialties"
- "Efficient resource utilization"

### Scenario 3: Docker Management

```bash
# Show running containers
docker-compose ps

# Show logs from specific agent
docker-compose logs -f recon-kage

# Demonstrate pause/resume
docker kill --signal=SIGUSR1 recon-kage
docker kill --signal=SIGUSR2 recon-kage

# Show health checks
docker inspect --format='{{.State.Health.Status}}' recon-kage
```

**Talking Points:**
- "All agents run in isolated containers"
- "Easy to scale and manage"
- "Health checks ensure reliability"

## 🎤 Talking Points for Interviews

### Architecture

- "API-based microservices architecture"
- "Clean separation between agents and backend"
- "Docker containerization for easy deployment"
- "PostgreSQL for production-grade data persistence"

### Technical Highlights

- "Multi-threaded parallel scanning"
- "Vector-based learning for path discovery"
- "RESTful API design"
- "Real-time dashboard updates"
- "Graceful shutdown and error recovery"

### Production Features

- "Health checks and monitoring"
- "Exponential backoff retry logic"
- "Comprehensive logging"
- "Docker orchestration"
- "Database migrations and schema management"

### Problem-Solving

- "Solved coordination challenges between multiple agents"
- "Implemented duplicate prevention logic"
- "Optimized for high-volume scanning"
- "Balanced thoroughness with performance"

## 🛑 Stopping the Demo

```bash
cd docker

# Stop all services
docker-compose down

# Remove volumes (cleans database)
docker-compose down -v

# View logs from stopped containers
docker-compose logs
```

## 📝 Demo Checklist

Before your demo:

- [ ] All containers running (`docker-compose ps`)
- [ ] Web interface accessible
- [ ] At least a few targets in database
- [ ] Agents have performed some scans (check dashboards)
- [ ] Test all dashboard pages load correctly
- [ ] Have talking points ready for each component

## 🐛 Troubleshooting

### Containers won't start

```bash
# Check logs
docker-compose logs

# Rebuild containers
docker-compose up -d --build --force-recreate

# Check port conflicts
netstat -an | grep 9000
```

### Agents not scanning

1. Check agent logs: `docker-compose logs recon-kage`
2. Verify Django API is accessible: `curl http://localhost:9000/reconnaissance/api/daemon/kage/health/`
3. Check for targets: Go to EggRecords page
4. Verify database connection

### Database issues

```bash
# Access Django shell
docker-compose exec recon-django python manage.py shell

# Check database connection
docker-compose exec recon-django python manage.py dbshell

# Run migrations
docker-compose exec recon-django python manage.py migrate
```

## 📸 Screenshot Opportunities

Great screenshots for portfolio:

1. General Dashboard showing all agent activity
2. Network Visualizer with graph
3. Multiple agent dashboards side-by-side
4. Docker containers running
5. Oak Dashboard showing coordination

## 🎯 Key Metrics to Highlight

- Number of targets scanned
- Ports discovered
- Services detected
- Endpoints found
- Directories enumerated
- Agent uptime and reliability

---

**Ready to demo!** This platform showcases production-ready multi-agent systems, API design, Docker orchestration, and comprehensive monitoring - all valuable skills for software engineering roles.
