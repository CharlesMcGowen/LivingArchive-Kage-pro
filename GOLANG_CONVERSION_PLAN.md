# Golang Conversion Plan: Kumo & Suzu Daemons
## Using Local Imports Only (No External Dependencies)

**Security Note**: All code uses local imports. External dependencies are vendored locally to prevent supply chain attacks.

## Package Structure

```
go/
├── go.mod                    # Local module: "recon" (no GitHub URLs)
├── go.sum
├── vendor/                   # Vendored dependencies (locked versions)
├── cmd/
│   ├── kumo/
│   │   └── main.go          # Kumo daemon entry point
│   └── suzu/
│       └── main.go          # Suzu daemon entry point
├── internal/
│   ├── kumo/
│   │   ├── spider.go        # Core spidering logic
│   │   ├── extractor.go    # HTML link extraction
│   │   ├── metadata.go     # RequestMetaData creation
│   │   └── types.go        # Type definitions
│   ├── suzu/
│   │   ├── enumerator.go   # Directory enumeration
│   │   ├── tools.go        # Tool execution (dirsearch, ffuf)
│   │   └── types.go        # Type definitions
│   ├── api/
│   │   ├── client.go       # Django API client
│   │   └── types.go       # API request/response types
│   └── common/
│       ├── config.go      # Configuration management
│       ├── logger.go      # Logging utilities
│       └── daemon.go      # Daemon lifecycle management
└── pkg/
    └── htmlparser/        # HTML parsing utilities
        └── parser.go
```

## go.mod Setup (Local Module)

```go
module recon

go 1.21

// All dependencies are vendored locally - no external pulls
// Use: go mod vendor to create vendor/ directory
// Use: go build -mod=vendor to use vendored deps only

require (
    // Minimal external deps - all vendored
    golang.org/x/net v0.17.0 // HTML parsing
)

// Replace any external deps with local paths if needed
replace golang.org/x/net => ./vendor/golang.org/x/net
```

## Type Definitions

### Kumo Types (`internal/kumo/types.go`)

```go
package kumo

import (
    "time"
    "net/http"
)

// SpiderConfig holds spider configuration
type SpiderConfig struct {
    ParallelEnabled   bool
    RequestTimeout    time.Duration
    MaxWorkers        int
    MaxPagesPerDomain int
    SpiderDepth       int
    UserAgent         string
    TorEnabled        bool
    TorProxyURL       string
    LLMEnabled        bool
    LLMAPIURL         string
}

// EggRecord represents an eggrecord from Django
type EggRecord struct {
    ID          string    `json:"id"`
    SubDomain   string    `json:"subDomain"`
    DomainName  string    `json:"domainname"`
    Alive       bool      `json:"alive"`
    UpdatedAt   time.Time `json:"updated_at"`
}

// SpiderResult represents spidering results
type SpiderResult struct {
    Success                bool      `json:"success"`
    Target                 string    `json:"target"`
    PagesSpidered          int       `json:"pages_spidered"`
    MetadataEntriesCreated int       `json:"metadata_entries_created"`
    SpiderDuration         float64   `json:"spider_duration"`
    Pages                   []PageData `json:"pages"`
    Error                  string    `json:"error,omitempty"`
}

// PageData represents a single spidered page
type PageData struct {
    URL           string            `json:"url"`
    StatusCode    int               `json:"status_code"`
    Headers       map[string]string `json:"headers"`
    Cookies       []Cookie          `json:"cookies"`
    ContentLength int               `json:"content_length"`
    Depth         int               `json:"depth"`
    MetadataID    string            `json:"metadata_id"`
}

// Cookie represents an HTTP cookie
type Cookie struct {
    Name   string `json:"name"`
    Value  string `json:"value"`
    Domain string `json:"domain"`
}

// RequestMetaData represents metadata to be stored
type RequestMetaData struct {
    ID              string            `json:"id"`
    RequestID       string            `json:"request_id"`
    SessionID       string            `json:"session_id"`
    TargetURL       string            `json:"target_url"`
    RequestMethod   string            `json:"request_method"`
    ResponseStatus  int               `json:"response_status"`
    RequestHeaders  map[string]string  `json:"request_headers"`
    ResponseHeaders map[string]string `json:"response_headers"`
    ResponseBody    string            `json:"response_body"`
    ResponseTimeMS  int               `json:"response_time_ms"`
    UserAgent       string            `json:"user_agent"`
    Timestamp       time.Time         `json:"timestamp"`
    RecordID        string            `json:"record_id_id"`
}
```

### Suzu Types (`internal/suzu/types.go`)

```go
package suzu

import "time"

// EnumerationResult represents directory enumeration results
type EnumerationResult struct {
    Success    bool     `json:"success"`
    Tool       string   `json:"tool"`
    PathsFound int      `json:"paths_found"`
    Paths      []string `json:"paths"`
    RawOutput  string   `json:"raw_output"`
    Error      string   `json:"error,omitempty"`
}

// ToolConfig holds tool configuration
type ToolConfig struct {
    DirsearchPath string
    FFufPath      string
    WordlistPath  string
    Timeout       time.Duration
    MaxTime       time.Duration
    Threads       int
}
```

### API Types (`internal/api/types.go`)

```go
package api

import "time"

// EggRecordResponse represents API response for eggrecords
type EggRecordResponse struct {
    Success    bool        `json:"success"`
    Count      int         `json:"count"`
    EggRecords []EggRecord `json:"eggrecords"`
    Error      string      `json:"error,omitempty"`
}

// EggRecord represents an eggrecord
type EggRecord struct {
    ID         string    `json:"id"`
    SubDomain  string    `json:"subDomain"`
    DomainName string    `json:"domainname"`
    Alive      bool      `json:"alive"`
    UpdatedAt  time.Time `json:"updated_at"`
}

// SubmitSpiderRequest represents spider result submission
type SubmitSpiderRequest struct {
    EggRecordID string       `json:"eggrecord_id"`
    Target      string       `json:"target"`
    Result      interface{}  `json:"result"` // Will be SpiderResult from kumo package
}

// SubmitEnumRequest represents enumeration result submission
type SubmitEnumRequest struct {
    EggRecordID string            `json:"eggrecord_id"`
    Target      string            `json:"target"`
    Result      EnumerationResult `json:"result"`
}

// APIResponse represents generic API response
type APIResponse struct {
    Success bool   `json:"success"`
    Message string `json:"message,omitempty"`
    Error   string `json:"error,omitempty"`
}
```

## Method Signatures

### Kumo Spider (`internal/kumo/spider.go`)

```go
package kumo

import (
    "context"
    "net/http"
    "time"
    "sync"
)

// Spider is the main spider struct
type Spider struct {
    config     SpiderConfig
    httpClient *http.Client
    visited    map[string]bool
    mu         sync.RWMutex
}

// NewSpider creates a new spider instance
func NewSpider(config SpiderConfig) (*Spider, error)

// SpiderEggRecord spiders an eggrecord and creates RequestMetaData entries
func (s *Spider) SpiderEggRecord(
    ctx context.Context,
    eggRecordID string,
    eggRecordData *EggRecord,
    depth int,
) (*SpiderResult, error)

// SpiderURL spiders a URL and creates RequestMetaData entries
func (s *Spider) SpiderURL(
    ctx context.Context,
    url string,
    eggRecordID string,
    depth int,
) (*SpiderResult, error)

// BatchSpider spiders multiple eggrecords
func (s *Spider) BatchSpider(
    ctx context.Context,
    eggRecordIDs []string,
    depth int,
) ([]*SpiderResult, error)

// makeRequest makes an HTTP request with retry logic
func (s *Spider) makeRequest(
    ctx context.Context,
    url string,
) (*http.Response, error)

// extractMetadata extracts metadata from HTTP response
func (s *Spider) extractMetadata(
    resp *http.Response,
    url string,
    eggRecordID string,
) (*RequestMetaData, error)

// createRequestMetaData creates RequestMetaData entry via API
func (s *Spider) createRequestMetaData(
    ctx context.Context,
    metadata *RequestMetaData,
) error
```

### Kumo Extractor (`internal/kumo/extractor.go`)

```go
package kumo

import (
    "context"
    "net/url"
)

// Extractor handles HTML parsing and link extraction
type Extractor struct{}

// NewExtractor creates a new extractor
func NewExtractor() *Extractor

// ExtractLinks extracts links from HTML content
func (e *Extractor) ExtractLinks(
    ctx context.Context,
    htmlContent string,
    baseURL *url.URL,
) ([]string, error)

// ExtractLinksEnhanced extracts links with enhanced analysis
func (e *Extractor) ExtractLinksEnhanced(
    ctx context.Context,
    htmlContent string,
    baseURL *url.URL,
) ([]LinkData, error)

// LinkData represents extracted link information
type LinkData struct {
    Href        string
    AbsoluteURL string
    Text        string
    Title       string
    Rel         []string
}
```

### Suzu Enumerator (`internal/suzu/enumerator.go`)

```go
package suzu

import (
    "context"
    "time"
)

// Enumerator handles directory enumeration
type Enumerator struct {
    config ToolConfig
}

// NewEnumerator creates a new enumerator
func NewEnumerator(config ToolConfig) *Enumerator

// EnumerateTarget performs directory enumeration on target
func (e *Enumerator) EnumerateTarget(
    ctx context.Context,
    targetURL string,
) (*EnumerationResult, error)

// RunDirsearch runs dirsearch tool
func (e *Enumerator) RunDirsearch(
    ctx context.Context,
    targetURL string,
) (*EnumerationResult, error)

// RunFFuf runs ffuf tool
func (e *Enumerator) RunFFuf(
    ctx context.Context,
    targetURL string,
) (*EnumerationResult, error)

// ParseDirsearchOutput parses dirsearch JSON/text output
func (e *Enumerator) ParseDirsearchOutput(output []byte) (*EnumerationResult, error)

// ParseFFufOutput parses ffuf JSON output
func (e *Enumerator) ParseFFufOutput(output []byte) (*EnumerationResult, error)
```

### Suzu Tools (`internal/suzu/tools.go`)

```go
package suzu

import (
    "context"
    "os/exec"
    "time"
)

// ToolExecutor executes external enumeration tools
type ToolExecutor struct {
    config ToolConfig
}

// NewToolExecutor creates a new tool executor
func NewToolExecutor(config ToolConfig) *ToolExecutor

// ExecuteDirsearch executes dirsearch command
func (te *ToolExecutor) ExecuteDirsearch(
    ctx context.Context,
    targetURL string,
) ([]byte, error)

// ExecuteFFuf executes ffuf command
func (te *ToolExecutor) ExecuteFFuf(
    ctx context.Context,
    targetURL string,
) ([]byte, error)

// CheckToolAvailability checks if a tool is available
func (te *ToolExecutor) CheckToolAvailability(toolName string) bool
```

### API Client (`internal/api/client.go`)

```go
package api

import (
    "context"
    "net/http"
    "time"
)

// Client handles Django API communication
type Client struct {
    baseURL    string
    httpClient *http.Client
    timeout    time.Duration
}

// NewClient creates a new API client
func NewClient(baseURL string, timeout time.Duration) *Client

// GetEggRecords fetches eggrecords for a personality
func (c *Client) GetEggRecords(
    ctx context.Context,
    personality string,
    limit int,
) (*EggRecordResponse, error)

// SubmitSpiderResult submits spider results
func (c *Client) SubmitSpiderResult(
    ctx context.Context,
    req *SubmitSpiderRequest,
) (*APIResponse, error)

// SubmitEnumerationResult submits enumeration results
func (c *Client) SubmitEnumerationResult(
    ctx context.Context,
    req *SubmitEnumRequest,
) (*APIResponse, error)

// HealthCheck performs health check
func (c *Client) HealthCheck(
    ctx context.Context,
    personality string,
) (*APIResponse, error)

// getWithRetry performs GET request with exponential backoff
func (c *Client) getWithRetry(
    ctx context.Context,
    endpoint string,
    maxRetries int,
) (*http.Response, error)

// postWithRetry performs POST request with exponential backoff
func (c *Client) postWithRetry(
    ctx context.Context,
    endpoint string,
    body interface{},
    maxRetries int,
) (*http.Response, error)
```

### Daemon (`internal/common/daemon.go`)

```go
package common

import (
    "context"
    "os"
    "os/signal"
    "sync"
    "syscall"
)

// Daemon manages daemon lifecycle
type Daemon struct {
    name       string
    pidFile    string
    running    bool
    paused     bool
    currentTask string
    mu         sync.RWMutex
    ctx        context.Context
    cancel     context.CancelFunc
}

// NewDaemon creates a new daemon instance
func NewDaemon(name, pidFile string) *Daemon

// Start starts the daemon
func (d *Daemon) Start() error

// Stop stops the daemon
func (d *Daemon) Stop() error

// Pause pauses the daemon
func (d *Daemon) Pause()

// Resume resumes the daemon
func (d *Daemon) Resume()

// IsRunning returns if daemon is running
func (d *Daemon) IsRunning() bool

// IsPaused returns if daemon is paused
func (d *Daemon) IsPaused() bool

// SetCurrentTask sets the current task ID
func (d *Daemon) SetCurrentTask(taskID string)

// ClearCurrentTask clears the current task ID
func (d *Daemon) ClearCurrentTask()

// GetCurrentTask returns the current task ID
func (d *Daemon) GetCurrentTask() string

// writePIDFile writes PID to file
func (d *Daemon) writePIDFile() error

// removePIDFile removes PID file
func (d *Daemon) removePIDFile() error

// setupSignalHandlers sets up signal handlers
func (d *Daemon) setupSignalHandlers()
```

## Main Entry Points

### Kumo Daemon (`cmd/kumo/main.go`)

```go
package main

import (
    "context"
    "flag"
    "log"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    "recon/internal/api"
    "recon/internal/common"
    "recon/internal/kumo"
)

func main() {
    // Parse flags
    apiBase := flag.String("api-base", "http://127.0.0.1:9000", "Django API base URL")
    interval := flag.Duration("interval", 45*time.Second, "Spider interval")
    maxSpiders := flag.Int("max-spiders", 3, "Max spiders per cycle")
    flag.Parse()

    // Create daemon
    daemon := common.NewDaemon("kumo", "/tmp/kumo_daemon.pid")
    
    // Create API client
    apiClient := api.NewClient(*apiBase, 30*time.Second)
    
    // Create spider
    spiderConfig := kumo.SpiderConfig{
        ParallelEnabled:   true,
        RequestTimeout:    10 * time.Second,
        MaxWorkers:        32,
        MaxPagesPerDomain: 50,
        SpiderDepth:       2,
        UserAgent:         "Kumo-Spider/2.0 (EGO Security Scanner)",
    }
    spider, err := kumo.NewSpider(spiderConfig)
    if err != nil {
        log.Fatalf("Failed to create spider: %v", err)
    }

    // Start daemon
    if err := daemon.Start(); err != nil {
        log.Fatalf("Failed to start daemon: %v", err)
    }
    defer daemon.Stop()

    // Setup signal handlers
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)

    // Main loop
    cycleCount := 0
    for daemon.IsRunning() {
        // Handle signals
        select {
        case sig := <-sigChan:
            switch sig {
            case syscall.SIGINT, syscall.SIGTERM:
                daemon.Stop()
                return
            case syscall.SIGUSR1:
                daemon.Pause()
            case syscall.SIGUSR2:
                daemon.Resume()
            }
        default:
        }

        // Check pause state
        for daemon.IsPaused() && daemon.IsRunning() {
            time.Sleep(1 * time.Second)
        }

        if !daemon.IsRunning() {
            break
        }

        cycleCount++
        log.Printf("🔄 Kumo spider cycle #%d", cycleCount)

        // Get eggrecords
        ctx := context.Background()
        eggRecords, err := apiClient.GetEggRecords(ctx, "kumo", *maxSpiders)
        if err != nil {
            log.Printf("Error getting eggrecords: %v", err)
            time.Sleep(*interval)
            continue
        }

        if len(eggRecords.EggRecords) == 0 {
            log.Println("No eggrecords to spider, waiting...")
            time.Sleep(*interval)
            continue
        }

        log.Printf("📋 Found %d eggrecords to spider", len(eggRecords.EggRecords))

        // Spider each eggrecord
        spidered := 0
        for _, eggRecord := range eggRecords.EggRecords {
            if !daemon.IsRunning() || daemon.IsPaused() {
                break
            }

            daemon.SetCurrentTask(eggRecord.ID)
            targetURL := buildTargetURL(eggRecord)
            
            log.Printf("🕷️  Spidering %s (%s)", targetURL, eggRecord.ID)

            // Perform spidering
            result, err := spider.SpiderEggRecord(ctx, eggRecord.ID, &eggRecord, 2)
            if err != nil {
                log.Printf("❌ Spider failed: %v", err)
                daemon.ClearCurrentTask()
                continue
            }

            if result.Success {
                // Submit result
                req := &api.SubmitSpiderRequest{
                    EggRecordID: eggRecord.ID,
                    Target:      targetURL,
                    Result:      result,
                }
                if _, err := apiClient.SubmitSpiderResult(ctx, req); err != nil {
                    log.Printf("Error submitting result: %v", err)
                } else {
                    spidered++
                }
            }

            daemon.ClearCurrentTask()
            time.Sleep(100 * time.Millisecond)
        }

        if spidered > 0 {
            log.Printf("✅ Completed %d spiders this cycle", spidered)
        }

        time.Sleep(*interval)
    }
}

func buildTargetURL(eggRecord api.EggRecord) string {
    target := eggRecord.SubDomain
    if target == "" {
        target = eggRecord.DomainName
    }
    if !strings.HasPrefix(target, "http") {
        return "http://" + target
    }
    return target
}
```

### Suzu Daemon (`cmd/suzu/main.go`)

```go
package main

import (
    "context"
    "flag"
    "log"
    "os"
    "os/signal"
    "strings"
    "syscall"
    "time"

    "recon/internal/api"
    "recon/internal/common"
    "recon/internal/suzu"
)

func main() {
    // Parse flags
    apiBase := flag.String("api-base", "http://127.0.0.1:9000", "Django API base URL")
    interval := flag.Duration("interval", 60*time.Second, "Enumeration interval")
    maxEnums := flag.Int("max-enums", 2, "Max enumerations per cycle")
    flag.Parse()

    // Create daemon
    daemon := common.NewDaemon("suzu", "/tmp/suzu_daemon.pid")
    
    // Create API client
    apiClient := api.NewClient(*apiBase, 30*time.Second)
    
    // Create enumerator
    toolConfig := suzu.ToolConfig{
        DirsearchPath: "/opt/dirsearch/dirsearch.py",
        FFufPath:      "/usr/local/bin/ffuf",
        WordlistPath:  "/opt/dirsearch/db/dicc.txt",
        Timeout:       10 * time.Second,
        MaxTime:       5 * time.Minute,
        Threads:       20,
    }
    enumerator := suzu.NewEnumerator(toolConfig)

    // Start daemon
    if err := daemon.Start(); err != nil {
        log.Fatalf("Failed to start daemon: %v", err)
    }
    defer daemon.Stop()

    // Setup signal handlers
    sigChan := make(chan os.Signal, 1)
    signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)

    // Main loop
    cycleCount := 0
    for daemon.IsRunning() {
        // Handle signals
        select {
        case sig := <-sigChan:
            switch sig {
            case syscall.SIGINT, syscall.SIGTERM:
                daemon.Stop()
                return
            case syscall.SIGUSR1:
                daemon.Pause()
            case syscall.SIGUSR2:
                daemon.Resume()
            }
        default:
        }

        // Check pause state
        for daemon.IsPaused() && daemon.IsRunning() {
            time.Sleep(1 * time.Second)
        }

        if !daemon.IsRunning() {
            break
        }

        cycleCount++
        log.Printf("🔄 Suzu enumeration cycle #%d", cycleCount)

        // Get eggrecords
        ctx := context.Background()
        eggRecords, err := apiClient.GetEggRecords(ctx, "suzu", *maxEnums)
        if err != nil {
            log.Printf("Error getting eggrecords: %v", err)
            time.Sleep(*interval)
            continue
        }

        if len(eggRecords.EggRecords) == 0 {
            log.Println("No eggrecords to enumerate, waiting...")
            time.Sleep(*interval)
            continue
        }

        log.Printf("📋 Found %d eggrecords to enumerate", len(eggRecords.EggRecords))

        // Enumerate each eggrecord
        enumerated := 0
        for _, eggRecord := range eggRecords.EggRecords {
            if !daemon.IsRunning() || daemon.IsPaused() {
                break
            }

            daemon.SetCurrentTask(eggRecord.ID)
            targetURL := buildTargetURL(eggRecord)
            
            log.Printf("🔔 Enumerating directories for %s (%s)", targetURL, eggRecord.ID)

            // Perform enumeration
            result, err := enumerator.EnumerateTarget(ctx, targetURL)
            if err != nil {
                log.Printf("❌ Enumeration failed: %v", err)
                daemon.ClearCurrentTask()
                continue
            }

            if result.Success {
                // Submit result
                req := &api.SubmitEnumRequest{
                    EggRecordID: eggRecord.ID,
                    Target:      targetURL,
                    Result:      *result,
                }
                if _, err := apiClient.SubmitEnumerationResult(ctx, req); err != nil {
                    log.Printf("Error submitting result: %v", err)
                } else {
                    enumerated++
                }
            }

            daemon.ClearCurrentTask()
            time.Sleep(1 * time.Second)
        }

        if enumerated > 0 {
            log.Printf("✅ Completed %d enumerations this cycle", enumerated)
        }

        time.Sleep(*interval)
    }
}

func buildTargetURL(eggRecord api.EggRecord) string {
    target := eggRecord.SubDomain
    if target == "" {
        target = eggRecord.DomainName
    }
    if !strings.HasPrefix(target, "http") {
        return "http://" + target
    }
    return target
}
```

## Security: Vendoring Dependencies

### Setup Steps

1. **Initialize Go module (local only)**:
```bash
cd /media/ego/328010BE80108A8D2/github_public/LivingArchive-Kage-pro/go
go mod init recon
```

2. **Add minimal dependencies**:
```bash
go get golang.org/x/net/html  # HTML parsing only
```

3. **Vendor all dependencies** (locks versions locally):
```bash
go mod vendor
```

4. **Build with vendored deps only** (no external pulls):
```bash
go build -mod=vendor ./cmd/kumo
go build -mod=vendor ./cmd/suzu
```

### Benefits

- **No external pulls**: All code is local
- **Version locked**: Dependencies are frozen in `vendor/`
- **Supply chain security**: No risk of external code being modified
- **Offline builds**: Can build without internet
- **Auditable**: All code is in your repository

### Dependency Management

- **Minimal deps**: Only use standard library + golang.org/x/net for HTML parsing
- **Vendor everything**: `go mod vendor` creates local copies
- **No replace needed**: Since we're using local module path "recon"
- **Check vendor/**: Review all vendored code before committing

## Integration with Existing Python Code

The Go daemons communicate with Django via HTTP API (same as Python daemons):

- **No changes needed** to Django API endpoints
- **Same API contracts** as Python daemons
- **Drop-in replacement** - can run Go or Python daemons
- **Gradual migration** - convert one daemon at a time

## Build & Deployment

### Local Development

```bash
cd go
go build -mod=vendor ./cmd/kumo
go build -mod=vendor ./cmd/suzu
```

### Docker Integration

Update `docker/Dockerfile` to include Go build:

```dockerfile
# Install Go
RUN apt-get update && apt-get install -y golang-go

# Build Go daemons
WORKDIR /app/go
COPY go/ .
RUN go mod vendor
RUN go build -mod=vendor -o ../bin/kumo ./cmd/kumo
RUN go build -mod=vendor -o ../bin/suzu ./cmd/suzu
```

### Docker Compose

Update `docker/docker-compose.yml`:

```yaml
kumo-daemon:
  command: /app/bin/kumo -api-base=http://django-server:9000

suzu-daemon:
  command: /app/bin/suzu -api-base=http://django-server:9000
```

