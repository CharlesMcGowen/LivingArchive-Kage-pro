package kumo

import "time"

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
	ID         string    `json:"id"`
	SubDomain  string    `json:"subDomain"`
	DomainName string    `json:"domainname"`
	Alive      bool      `json:"alive"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// SpiderResult represents spidering results
type SpiderResult struct {
	Success                bool       `json:"success"`
	Target                 string     `json:"target"`
	PagesSpidered          int        `json:"pages_spidered"`
	MetadataEntriesCreated int        `json:"metadata_entries_created"`
	SpiderDuration         float64    `json:"spider_duration"`
	Pages                  []PageData `json:"pages"`
	Error                  string     `json:"error,omitempty"`
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
	RequestHeaders  map[string]string `json:"request_headers"`
	ResponseHeaders map[string]string `json:"response_headers"`
	ResponseBody    string            `json:"response_body"`
	ResponseTimeMS  int               `json:"response_time_ms"`
	UserAgent       string            `json:"user_agent"`
	Timestamp       time.Time         `json:"timestamp"`
	RecordID        string            `json:"record_id_id"`
}

