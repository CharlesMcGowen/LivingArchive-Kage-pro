# Feature Documentation - LivingArchive-Kage-Pro

Complete documentation of all features and capabilities in the LivingArchive-Kage-Pro platform.

## 🤖 Autonomous Agents

### Kage (Shadow) - Port Scanner

**Purpose:** Intelligent port scanning with service detection and analysis

**Key Features:**
- Fast Nmap-based port scanning
- Service detection and version identification
- WAF (Web Application Firewall) fingerprinting
- SSL/TLS certificate analysis
- Intelligent scan strategy generation
- Parallel scanning with configurable workers
- Adaptive port selection based on target characteristics

**Capabilities:**
- Common port scanning (top ports)
- Full port range scanning (1-65535) on demand
- Service banner grabbing
- OS detection (when enabled)
- Script scanning for additional information
- CPE (Common Platform Enumeration) extraction

**Configuration:**
```bash
export KAGE_SCAN_INTERVAL=30      # Seconds between scan cycles
export KAGE_MAX_SCANS=5            # Max scans per cycle
```

**Dashboard:** `/reconnaissance/kage/`

### Kaze (Wind) - High-Speed Scanner

**Purpose:** Optimized high-volume port scanning

**Key Features:**
- Parallel scanning architecture
- Optimized for large target sets
- Fast scan completion
- Efficient resource utilization
- Duplicate prevention across agents

**Differences from Kage:**
- Focused on speed over depth
- Fewer script scans for performance
- Optimized worker pool management

**Configuration:**
```bash
export KAZE_SCAN_INTERVAL=30      # Seconds between scan cycles
export KAZE_MAX_SCANS=5            # Max scans per cycle
```

**Dashboard:** `/reconnaissance/kaze/`

### Kumo (Spider) - Web Crawler

**Purpose:** Automated web application crawling and endpoint discovery

**Key Features:**
- HTTP/HTTPS spidering
- Automatic endpoint discovery
- Form detection and analysis
- JavaScript rendering support
- Cookie and session handling
- Content type detection
- Link following and depth control

**Capabilities:**
- Discover hidden endpoints
- Identify API endpoints
- Extract forms and input fields
- Analyze response headers
- Content analysis for security indicators
- Integration with port scan data

**Configuration:**
```bash
export KUMO_SPIDER_INTERVAL=45     # Seconds between spider cycles
export KUMO_MAX_SPIDERS=3          # Max spiders per cycle
```

**Dashboard:** `/reconnaissance/kumo/`

### Ryu (Dragon) - Threat Assessment

**Purpose:** Comprehensive security analysis and vulnerability assessment

**Key Features:**
- Full port range scanning (1-65535)
- Deep security analysis
- Threat assessment scoring
- Vulnerability identification
- Security posture evaluation
- Integration with learning system

**Capabilities:**
- Comprehensive port scanning
- Service vulnerability assessment
- SSL/TLS security analysis
- Security configuration review
- Risk scoring and prioritization
- Detailed reporting

**Configuration:**
```bash
export RYU_SCAN_INTERVAL=30        # Seconds between scan cycles
export RYU_ASSESSMENT_INTERVAL=60  # Seconds between assessment cycles
export RYU_MAX_SCANS=5             # Max scans per cycle
export RYU_MAX_ASSESSMENTS=2       # Max assessments per cycle
```

**Dashboard:** `/reconnaissance/ryu/`

### Suzu (Bell) - Directory Enumerator

**Purpose:** Intelligent directory and file discovery

**Key Features:**
- CMS-aware enumeration
- Vector-based path learning
- Intelligent wordlist management
- Priority-based path scoring
- Pattern recognition
- Duplicate detection

**Capabilities:**
- Directory and file discovery
- CMS detection and enumeration
- Custom wordlist support
- Learning from successful discoveries
- Vector similarity search for paths
- Smart path prioritization

**Configuration:**
```bash
export SUZU_ENUM_INTERVAL=60       # Seconds between enum cycles
export SUZU_MAX_ENUMS=3            # Max enumerations per cycle
```

**Dashboard:** `/reconnaissance/suzu/`

## 🎯 Target Management

### EggRecords System

**Purpose:** Centralized target management and tracking

**Features:**
- Create/edit/delete targets
- Bulk target operations
- Filtering and search
- Target grouping (Egg Names, Project Eggs)
- Alive/dead status tracking
- Associated data aggregation (scans, crawls, etc.)

**Key Fields:**
- Domain name
- Subdomain
- IP address
- CIDR ranges
- Alive status
- Timestamps (created, updated)
- Associated scan/enumeration counts

**Interface:** `/reconnaissance/eggrecords/`

## 🧠 Oak AI Coordinator

**Purpose:** Intelligent coordination and curation of reconnaissance tasks

**Key Features:**
- Target curation and prioritization
- Template management
- Agent workload balancing
- Duplicate work prevention
- Intelligent task distribution

**Components:**
- Autonomous Curation Service
- Template Registry Service
- Nmap Coordination Service

**Dashboard:** `/reconnaissance/oak/`

## 📊 Dashboards and Visualization

### General Dashboard

**Purpose:** Overview of all agent activities

**Features:**
- Combined activity feed
- Statistics across all agents
- Recent results from all sources
- System-wide metrics

**URL:** `/reconnaissance/`

### Network Visualizer

**Purpose:** Interactive visualization of discovered infrastructure

**Features:**
- Graph-based visualization
- IP → CIDR → ASN relationships
- Interactive node exploration
- Filtering and level selection
- Edge relationship visualization
- Real-time updates

**Technology:** Cytoscape.js

**URL:** `/reconnaissance/network/`

### Learning Dashboard

**Purpose:** Adaptive learning and technique effectiveness metrics

**Features:**
- Technique effectiveness tracking
- Heuristics rules display
- Pattern recognition results
- Learning progress metrics
- Adaptive strategy insights

**URL:** `/reconnaissance/learning/`

### Agent-Specific Dashboards

Each agent has a dedicated dashboard showing:
- Scan/crawl/enumeration results
- Filtering and search
- Detailed result views
- Statistics and metrics
- Export capabilities

## 🔄 Agent Coordination

### Duplicate Prevention

**Mechanism:**
- SQL-based duplicate detection
- Time-based coordination windows
- Agent-specific scan type tracking
- Yearly scan limits (1 scan per year per target)

**Implementation:**
- Pre-scan duplicate checks
- Post-scan validation
- Race condition prevention (5-minute window)

### Load Balancing

**Features:**
- Round-robin target distribution
- Priority-based selection
- Agent workload monitoring
- Automatic load distribution

## 🐳 Docker Deployment

### Container Architecture

**Services:**
- `recon-django` - Django backend
- `recon-kage` - Kage daemon
- `recon-kaze` - Kaze daemon
- `recon-kumo` - Kumo daemon
- `recon-ryu` - Ryu daemon
- `recon-suzu` - Suzu daemon

**Features:**
- Health checks for all containers
- Automatic restart on failure
- Network isolation
- Volume mounts for persistence
- Environment variable configuration

### Docker Compose

**Benefits:**
- Single command deployment
- Service orchestration
- Network management
- Volume management
- Easy scaling

## 🔌 API Architecture

### RESTful API Design

**Endpoints:**
- `GET /reconnaissance/api/daemon/{agent}/eggrecords/` - Fetch targets
- `POST /reconnaissance/api/daemon/{agent}/scan/` - Submit scan results
- `POST /reconnaissance/api/daemon/spider/` - Submit spider results
- `POST /reconnaissance/api/daemon/assessment/` - Submit assessments
- `GET /reconnaissance/api/daemon/{agent}/health/` - Health checks

**Features:**
- JSON request/response format
- Error handling and validation
- Rate limiting considerations
- Authentication support

## 📈 Learning and Adaptation

### Adaptive Techniques

**Features:**
- Technique effectiveness tracking
- Pattern recognition
- Heuristic rule generation
- Strategy optimization
- Result-based learning

### Vector-Based Learning (Suzu)

**Features:**
- Path similarity matching
- Successful path pattern extraction
- Priority scoring based on history
- CMS-specific path learning

## 🛡️ Production Features

### Reliability

- Graceful shutdown handling
- Exponential backoff retry logic
- Health check monitoring
- Automatic container restart
- Error logging and tracking

### Monitoring

- Structured logging
- Health check endpoints
- Docker health status
- Agent status tracking
- Performance metrics

### Scalability

- Horizontal scaling support
- Independent agent processes
- Database connection pooling
- Efficient query optimization
- Resource isolation

## 🔐 Security Features

### Input Validation

- Django ORM (SQL injection prevention)
- Input sanitization
- Type validation
- Length limits

### Container Security

- Isolated execution contexts
- No direct database access from agents
- Network isolation
- Resource limits

### API Security

- CSRF protection
- Input validation
- Error message sanitization
- Rate limiting support

## 📝 Data Models

### Core Models

**EggRecord:**
- Target information
- Status tracking
- Relationships to scans/crawls

**Nmap:**
- Port scan results
- Service detection
- Scan metadata

**RequestMetadata:**
- HTTP request/response data
- Headers and content
- Relationship to targets

**DirectoryEnumerationResult:**
- Discovered paths
- CMS information
- Enumeration metadata

### Database Architecture

- PostgreSQL for production data
- Multiple database support
- Efficient indexing
- Relationship management

## 🚀 Performance Features

### Optimization

- Parallel processing
- Efficient scanning strategies
- Database query optimization
- Result caching
- Minimal API overhead

### Resource Management

- Configurable worker pools
- Memory-efficient processing
- CPU usage optimization
- Network bandwidth management

## 🎓 Use Cases

### Penetration Testing
- Automated reconnaissance phase
- Comprehensive target discovery
- Vulnerability identification

### Bug Bounty Programs
- Continuous target scanning
- New endpoint discovery
- Security issue detection

### Security Audits
- Network infrastructure mapping
- Service inventory
- Security posture assessment

### Threat Intelligence
- Infrastructure discovery
- Attack surface mapping
- Vulnerability tracking

---

This comprehensive feature set makes LivingArchive-Kage-Pro a powerful platform for autonomous reconnaissance and security assessment.
