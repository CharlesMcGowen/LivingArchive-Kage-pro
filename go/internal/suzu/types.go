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

