# Architecture Documentation - LivingArchive-Kage-Pro

## System Overview

LivingArchive-Kage-Pro is built on a microservices-inspired architecture with autonomous agents communicating via REST APIs. The system is designed for scalability, reliability, and maintainability.

## High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Layer                             │
│                   (Web Browser / API Clients)                    │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP/HTTPS
┌────────────────────────────▼────────────────────────────────────┐
│                      Django Backend                              │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    Web Layer (Port 9000)                  │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐         │   │
│  │  │  Views     │  │   URLs     │  │  Templates │         │   │
│  │  │  (Django)  │  │  Routing   │  │   (HTML)   │         │   │
│  │  └────────────┘  └────────────┘  └────────────┘         │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   API Layer                               │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐         │   │
│  │  │ Daemon API │  │ Health API │  │  REST API  │         │   │
│  │  │ Endpoints  │  │ Endpoints  │  │  Endpoints │         │   │
│  │  └────────────┘  └────────────┘  └────────────┘         │   │
│  └──────────────────────────────────────────────────────────┘   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                 Data Layer                                │   │
│  │  ┌────────────┐  ┌────────────┐  ┌────────────┐         │   │
│  │  │  Models    │  │  ORM       │  │  Database  │         │   │
│  │  │  (Django)  │  │  (Django)  │  │(PostgreSQL)│         │   │
│  │  └────────────┘  └────────────┘  └────────────┘         │   │
│  └──────────────────────────────────────────────────────────┘   │
└────────────────────────────┬────────────────────────────────────┘
                             │ HTTP REST API
┌────────────────────────────▼────────────────────────────────────┐
│                   Autonomous Agent Layer                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐       │
│  │   Kage   │  │   Kaze   │  │   Kumo   │  │   Ryu    │       │
│  │  Daemon  │  │  Daemon  │  │  Daemon  │  │  Daemon  │       │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘       │
│  ┌──────────┐                                                 │
│  │   Suzu   │                                                 │
│  │  Daemon  │                                                 │
│  └──────────┘                                                 │
└─────────────────────────────────────────────────────────────────┘
                             │
┌────────────────────────────▼────────────────────────────────────┐
│                  Coordination Layer                              │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │              Oak AI Coordinator                          │   │
│  │  • Target Curation                                       │   │
│  │  • Task Distribution                                     │   │
│  │  • Agent Coordination                                    │   │
│  │  • Template Management                                   │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

## Component Details

### 1. Django Backend

**Purpose:** Central orchestration, data persistence, and web interface

**Responsibilities:**
- Serve web dashboards
- Provide REST API for agents
- Manage database (PostgreSQL)
- Handle authentication and authorization
- Coordinate agent activities

**Key Files:**
- `ryu_app/views.py` - Dashboard views
- `ryu_app/daemon_api.py` - Agent API endpoints
- `ryu_app/models.py` - Data models
- `ryu_project/settings.py` - Configuration

**Database:**
- PostgreSQL for production data
- Multiple databases supported (customer_eggs, eggrecords)
- Database routing via `db_router.py`

### 2. Agent Daemons

Each agent is an independent Python process that:

- Runs continuously in background
- Fetches tasks from Django API
- Performs reconnaissance operations
- Submits results back via API
- Maintains its own state and configuration

#### Agent Architecture Pattern

```python
class AgentDaemon:
    def __init__(self):
        self.running = False
        self.paused = False
        self.scanner = None  # Agent-specific scanner/tool
        
    def coordination_loop(self):
        """Main execution loop"""
        while self.running:
            if not self.paused:
                tasks = self.fetch_tasks()
                for task in tasks:
                    result = self.process_task(task)
                    self.submit_result(result)
            time.sleep(interval)
```

#### Agent-Specific Implementations

**Kage (Port Scanner)**
- Uses `kage/nmap_scanner.py`
- Fast port scanning with service detection
- WAF fingerprinting
- SSL certificate analysis

**Kaze (High-Speed Scanner)**
- Uses `kaze/nmap_scanner.py`
- Optimized for parallel scanning
- High-volume target processing

**Kumo (Web Spider)**
- Uses `kumo/http_spider.py`
- HTTP/HTTPS crawling
- Endpoint discovery
- Content analysis

**Ryu (Threat Assessment)**
- Uses `ryu/threat_assessment_service.py`
- Comprehensive port scanning (1-65535)
- Vulnerability analysis
- Security assessment

**Suzu (Directory Enumerator)**
- Uses `suzu/directory_enumerator.py`
- CMS detection
- Path discovery
- Vector-based learning

### 3. API Communication

**Protocol:** HTTP REST API

**Agent → Django:**
```
GET  /reconnaissance/api/daemon/{agent}/eggrecords/
POST /reconnaissance/api/daemon/{agent}/scan/
POST /reconnaissance/api/daemon/spider/
POST /reconnaissance/api/daemon/assessment/
GET  /reconnaissance/api/daemon/{agent}/health/
```

**Request Flow:**
1. Agent requests tasks via GET endpoint
2. Django queries database for available targets
3. Returns JSON with target list
4. Agent processes targets
5. Agent submits results via POST endpoint
6. Django validates and stores results

### 4. Oak AI Coordinator

**Purpose:** Intelligent task curation and agent coordination

**Location:** `artificial_intelligence/personalities/reconnaissance/oak/`

**Features:**
- Target curation and prioritization
- Template management
- Agent workload balancing
- Duplicate prevention

**Key Components:**
- `target_curation/autonomous_curation_service.py`
- `nmap_coordination_service.py`
- `template_registry_service.py`

### 5. Data Models

**EggRecord:** Central target model
- Domain/subdomain information
- IP addresses
- Alive status
- Timestamps

**Nmap:** Port scan results
- Port numbers
- Service detection
- Scan metadata
- Relationships to EggRecords

**RequestMetadata:** Web crawl results
- HTTP requests/responses
- Headers and content
- Relationships to EggRecords

**DirectoryEnumerationResult:** Directory enumeration results
- Discovered paths
- CMS information
- Relationships to EggRecords

### 6. Database Architecture

**Primary Database (customer_eggs):**
- Main application data
- EggRecords
- Nmap results
- RequestMetadata

**Secondary Database (eggrecords):**
- Learning system data
- Heuristics rules
- Technique effectiveness

**Database Routing:**
- Automatic routing via `db_router.py`
- Models specify database via `using` parameter
- Supports multiple PostgreSQL instances

## Deployment Architecture

### Docker-Based Deployment

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Network                        │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ recon-django │  │ recon-kage   │  │ recon-kaze   │  │
│  │  (Django)    │  │  (Kage)      │  │  (Kaze)      │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ recon-kumo   │  │ recon-ryu    │  │ recon-suzu   │  │
│  │  (Kumo)      │  │  (Ryu)       │  │  (Suzu)      │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
                          │
                    ┌─────▼─────┐
                    │ PostgreSQL │
                    │  (Host)    │
                    └────────────┘
```

**Container Configuration:**
- All agents share Docker network
- Django container exposes port 9000
- Agents connect to Django via network name
- PostgreSQL runs on host or separate container
- Volume mounts for persistent data

### Scalability Considerations

**Horizontal Scaling:**
- Agents can run on separate machines
- Django API supports multiple agent instances
- Database can be replicated

**Vertical Scaling:**
- Individual agents can be tuned for performance
- Database connection pooling
- Async processing where applicable

## Communication Patterns

### Agent Coordination

**Duplicate Prevention:**
- Agents check for recent scans before processing
- SQL-based duplicate detection
- Time-based coordination (24-hour windows, 1-year limits)

**Load Balancing:**
- Round-robin target distribution
- Priority-based target selection
- Agent-specific target filtering

### Error Handling

**Retry Logic:**
- Exponential backoff for API failures
- Configurable retry limits
- Graceful degradation

**Health Checks:**
- Periodic health check endpoints
- Docker health check integration
- Automatic container restart on failure

## Security Considerations

**API Security:**
- Django CSRF protection
- Input validation
- SQL injection prevention (ORM)
- Rate limiting considerations

**Agent Security:**
- Isolated execution contexts
- No direct database access
- API-based communication only
- Container isolation

## Performance Optimizations

**Database:**
- Indexed queries
- Connection pooling
- Query optimization
- Bulk operations where possible

**Agents:**
- Parallel processing (multithreading)
- Efficient scanning strategies
- Result caching
- Minimal API calls

**Web Interface:**
- Template caching
- Static file serving
- Efficient queries
- Pagination for large datasets

## Monitoring and Observability

**Logging:**
- Structured logging per agent
- Log aggregation via Docker logs
- Error tracking and alerting

**Health Monitoring:**
- Health check endpoints
- Docker health status
- Agent status tracking

**Metrics:**
- Scan counts
- Agent uptime
- API response times
- Database query performance

## Future Enhancements

**Potential Improvements:**
- Message queue for agent communication (RabbitMQ, Redis)
- Event-driven architecture
- GraphQL API option
- Real-time updates via WebSockets
- Kubernetes deployment manifests
- Prometheus metrics integration

---

This architecture provides a solid foundation for a production reconnaissance platform while maintaining flexibility for future enhancements.
