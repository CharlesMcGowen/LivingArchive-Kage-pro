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
	EggRecordID string                 `json:"eggrecord_id"`
	Target      string                 `json:"target"`
	Result      map[string]interface{} `json:"result"` // SpiderResult as map for JSON
}

// EnumerationResult represents directory enumeration results (from suzu package)
type EnumerationResult struct {
	Success    bool     `json:"success"`
	Tool       string   `json:"tool"`
	PathsFound int      `json:"paths_found"`
	Paths      []string `json:"paths"`
	RawOutput  string   `json:"raw_output"`
	Error      string   `json:"error,omitempty"`
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

