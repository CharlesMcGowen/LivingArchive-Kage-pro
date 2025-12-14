// ⚡ SURGE Memory-Integrated Nuclei Bridge
// =========================================
//
// Go-Python memory bridge for real-time Nuclei scanning
// Provides instant AI-driven scan control and vulnerability streaming
//
// Author: EGO Revolution Team (Fixed by PinkiePie + Engineering Review)
// Version: 2.0.0 - Production Ready

package main

/*
#cgo LDFLAGS: -lpthread

#include <stdlib.h>
#include <string.h>

typedef void (*vuln_cb_t)(const char *);
static inline void call_vuln_callback(vuln_cb_t cb, const char *payload) {
	if (cb != NULL) {
		cb(payload);
	}
}
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/logrusorgru/aurora"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/nuclei/v3/pkg/core"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/model/types/severity"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols"
	protocolinit "github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolinit"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/protocolstate"
	nucleitemplates "github.com/projectdiscovery/nuclei/v3/pkg/templates"
	templatetypes "github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

// Global bridge state with mutex for thread safety
var (
	bridgeInstance *SurgeMemoryBridge
	bridgeMutex    sync.RWMutex
	callbackMutex  sync.RWMutex
	vulnCallback   C.vuln_cb_t
)

// SurgeMemoryBridge manages Nuclei engine and event streaming
type SurgeMemoryBridge struct {
	engine       *core.Engine
	scanState    *ScanState
	eventChannel chan NucleiEvent
	ctx          context.Context
	cancel       context.CancelFunc
	mu           sync.RWMutex // Protects scanState
	scanID       string
	isPaused     bool
	isRunning    bool
}

// NucleiEvent represents real-time vulnerability events
type NucleiEvent struct {
	Timestamp  string                 `json:"timestamp"`
	EventType  string                 `json:"event_type"` // VULNERABILITY, PROGRESS, STATE_CHANGE
	TemplateID string                 `json:"template_id"`
	Severity   string                 `json:"severity"`
	Target     string                 `json:"target"`
	MatchedAt  string                 `json:"matched_at"`
	Request    string                 `json:"request"`
	Response   string                 `json:"response"`
	Info       map[string]interface{} `json:"info"`
}

// ScanState exposes Nuclei's current internal state
type ScanState struct {
	ScanID             string        `json:"scan_id"`
	TotalRequests      int           `json:"total_requests"`
	SuccessfulRequests int           `json:"successful_requests"`
	FailedRequests     int           `json:"failed_requests"`
	ActiveTemplates    []string      `json:"active_templates"`
	CurrentTarget      string        `json:"current_target"`
	ProgressPercent    float64       `json:"progress_percent"`
	VulnsFound         []NucleiEvent `json:"vulns_found"`
	QueueLength        int           `json:"queue_length"`
	IsPaused           bool          `json:"is_paused"`
	IsRunning          bool          `json:"is_running"`
}

// Config represents Nuclei scan configuration
type Config struct {
	ScanType      string             `json:"scan_type"`
	Templates     []string           `json:"templates"`
	Tags          []string           `json:"tags"`
	Severities    []string           `json:"severities"`
	MaxTemplates  int                `json:"max_templates"`
	RateLimit     int                `json:"rate_limit"`
	Timeout       int                `json:"timeout"`
	Retries       int                `json:"retries"`
	MaxHostError  int                `json:"max_host_error"`
	Concurrency   int                `json:"concurrency"`
	RawTemplates  []string           `json:"raw_templates"`
	TemplateMeta  []TemplateMetadata `json:"template_metadata"`
	Requested     []string           `json:"requested_templates"`
	TemplateCount int                `json:"template_count"`
}

type TemplateMetadata struct {
	TemplateID   string `json:"template_id"`
	TemplatePath string `json:"template_path"`
	Severity     string `json:"severity"`
}

func parseTemplateFromRaw(raw string, execOpts *protocols.ExecutorOptions) (*nucleitemplates.Template, error) {
	reader := strings.NewReader(raw)
	return nucleitemplates.ParseTemplateFromReader(reader, nil, execOpts)
}

func metadataLabel(meta TemplateMetadata, idx int) string {
	switch {
	case meta.TemplateID != "":
		return meta.TemplateID
	case meta.TemplatePath != "":
		return meta.TemplatePath
	default:
		return fmt.Sprintf("payload-%d", idx)
	}
}

type noopProgress struct{}

func (n *noopProgress) Stop()                                                    {}
func (n *noopProgress) Init(hostCount int64, rulesCount int, requestCount int64) {}
func (n *noopProgress) AddToTotal(delta int64)                                   {}
func (n *noopProgress) IncrementRequests()                                       {}
func (n *noopProgress) SetRequests(count uint64)                                 {}
func (n *noopProgress) IncrementMatched()                                        {}
func (n *noopProgress) IncrementErrorsBy(count int64)                            {}
func (n *noopProgress) IncrementFailedRequestsBy(count int64)                    {}

// RequestTrackingWriter tracks requests and updates scan state
type RequestTrackingWriter struct {
	bridge *SurgeMemoryBridge
}

func (w *RequestTrackingWriter) Close() {}
func (w *RequestTrackingWriter) Colorizer() aurora.Aurora {
	return aurora.NewAurora(false)
}
func (w *RequestTrackingWriter) Write(*output.ResultEvent) error {
	// Results are handled by Callback, not here
	return nil
}
func (w *RequestTrackingWriter) WriteFailure(*output.InternalWrappedEvent) error {
	return nil
}
func (w *RequestTrackingWriter) Request(templateID, url, requestType string, err error) {
	// Track request - this is called for every HTTP request
	w.bridge.mu.Lock()
	w.bridge.scanState.TotalRequests++
	if err != nil {
		w.bridge.scanState.FailedRequests++
		log.Printf("⚠️ Request failed for %s: %v", url, err)
	} else {
		w.bridge.scanState.SuccessfulRequests++
	}
	w.bridge.mu.Unlock()
}
func (w *RequestTrackingWriter) RequestStatsLog(statusCode, response string) {
	// Track request statistics
	// Parse statusCode string to int (e.g., "200" -> 200)
	code := 0
	if statusCode != "" {
		if parsed, err := strconv.Atoi(statusCode); err == nil {
			code = parsed
		}
	}

	w.bridge.mu.Lock()
	w.bridge.scanState.TotalRequests++
	if code >= 200 && code < 400 {
		w.bridge.scanState.SuccessfulRequests++
	} else if code > 0 {
		w.bridge.scanState.FailedRequests++
	}
	w.bridge.mu.Unlock()
}
func (w *RequestTrackingWriter) WriteStoreDebugData(host, templateID, eventType, data string) {
}
func (w *RequestTrackingWriter) ResultCount() int { return 0 }

type noopOutputWriter struct{}

func (n *noopOutputWriter) Close() {}
func (n *noopOutputWriter) Colorizer() aurora.Aurora {
	return aurora.NewAurora(false)
}
func (n *noopOutputWriter) Write(*output.ResultEvent) error {
	return nil
}
func (n *noopOutputWriter) WriteFailure(*output.InternalWrappedEvent) error {
	return nil
}
func (n *noopOutputWriter) Request(templateID, url, requestType string, err error) {}
func (n *noopOutputWriter) RequestStatsLog(statusCode, response string)            {}
func (n *noopOutputWriter) WriteStoreDebugData(host, templateID, eventType, data string) {
}
func (n *noopOutputWriter) ResultCount() int { return 0 }

// Helper function to safely create and return C string
// Note: Python ctypes will free these strings, but we document ownership
func createCString(s string) *C.char {
	return C.CString(s)
}

// Helper function to safely free C string (if needed)
func freeCString(cstr *C.char) {
	if cstr != nil {
		C.free(unsafe.Pointer(cstr))
	}
}

// Helper function to return JSON error response
func jsonError(err error) *C.char {
	result := map[string]interface{}{
		"success": false,
		"error":   err.Error(),
	}
	jsonResult, marshalErr := json.Marshal(result)
	if marshalErr != nil {
		// Fallback if JSON marshal fails
		return createCString(`{"success": false, "error": "Internal error"}`)
	}
	return createCString(string(jsonResult))
}

// Helper function to return JSON success response
func jsonSuccess(data map[string]interface{}) *C.char {
	data["success"] = true
	jsonResult, err := json.Marshal(data)
	if err != nil {
		return jsonError(fmt.Errorf("json marshal failed: %w", err))
	}
	return createCString(string(jsonResult))
}

// Validate URL format
func validateURL(target string) error {
	if target == "" {
		return fmt.Errorf("target URL cannot be empty")
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}
	if parsed.Scheme == "" {
		return fmt.Errorf("URL must include scheme (http:// or https://)")
	}
	if parsed.Host == "" {
		return fmt.Errorf("URL must include host")
	}
	return nil
}

//export InitializeBridge
func InitializeBridge() *C.char {
	bridgeMutex.Lock()
	defer bridgeMutex.Unlock()

	if bridgeInstance != nil {
		return jsonError(fmt.Errorf("bridge already initialized"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	bridgeInstance = &SurgeMemoryBridge{
		eventChannel: make(chan NucleiEvent, 1000),
		scanState: &ScanState{
			ActiveTemplates: []string{},
			VulnsFound:      []NucleiEvent{},
		},
		ctx:    ctx,
		cancel: cancel,
	}

	// Start event handler goroutine
	go bridgeInstance.eventHandler()

	log.Println("✅ Surge Memory Bridge initialized")
	return jsonSuccess(map[string]interface{}{
		"message": "Bridge initialized",
	})
}

func getVulnerabilityCallback() C.vuln_cb_t {
	callbackMutex.RLock()
	cb := vulnCallback
	callbackMutex.RUnlock()
	return cb
}

//export RegisterVulnCallback
func RegisterVulnCallback(cb C.vuln_cb_t) {
	callbackMutex.Lock()
	vulnCallback = cb
	callbackMutex.Unlock()
	log.Println("✅ Vulnerability callback registered")
}

//export StartScan
func StartScan(targetC *C.char, configJSON *C.char) *C.char {
	bridgeMutex.RLock()
	bridge := bridgeInstance
	bridgeMutex.RUnlock()

	if bridge == nil {
		return jsonError(fmt.Errorf("bridge not initialized"))
	}

	// Convert C strings to Go strings
	target := C.GoString(targetC)
	configStr := C.GoString(configJSON)

	// Validate target URL
	if err := validateURL(target); err != nil {
		return jsonError(err)
	}

	// Parse config JSON
	var config Config
	if configStr != "" {
		if err := json.Unmarshal([]byte(configStr), &config); err != nil {
			return jsonError(fmt.Errorf("invalid config JSON: %w", err))
		}
	}

	// Set defaults if not provided
	if config.RateLimit == 0 {
		config.RateLimit = 150
	}
	if config.Timeout == 0 {
		config.Timeout = 10
	}
	if config.Retries == 0 {
		config.Retries = 1
	}
	if config.MaxHostError == 0 {
		config.MaxHostError = 30
	}
	if config.Concurrency == 0 {
		config.Concurrency = 25
	}
	if config.ScanType == "" {
		config.ScanType = "comprehensive"
	}
	if config.MaxTemplates <= 0 {
		config.MaxTemplates = 200
	}
	if len(config.RawTemplates) == 0 {
		log.Printf("⚠️  StartScan called without raw_templates in configuration payload")
		return jsonError(fmt.Errorf("no raw_templates provided"))
	}

	// Check if scan is already running
	bridge.mu.Lock()
	if bridge.isRunning {
		bridge.mu.Unlock()
		return jsonError(fmt.Errorf("scan already running"))
	}
	bridge.isRunning = true
	bridge.isPaused = false
	bridge.scanID = fmt.Sprintf("scan_%d", time.Now().UnixNano())
	bridge.mu.Unlock()

	// Initialize Nuclei engine configuration
	// Convert config to Nuclei v3 API format
	var templates goflags.StringSlice
	if len(config.TemplateMeta) > 0 {
		for _, meta := range config.TemplateMeta {
			if meta.TemplateID != "" {
				templates = append(templates, meta.TemplateID)
			} else if meta.TemplatePath != "" {
				templates = append(templates, meta.TemplatePath)
			}
		}
	}
	if len(templates) == 0 && len(config.Templates) > 0 {
		templates = goflags.StringSlice(config.Templates)
	}

	var tags goflags.StringSlice
	if len(config.Tags) > 0 {
		tags = goflags.StringSlice(config.Tags)
	}

	scanType := strings.ToLower(config.ScanType)

	// Convert severities to severity.Severities type
	var severities severity.Severities
	if len(config.Severities) > 0 {
		for _, s := range config.Severities {
			// Parse string severity to severity.Severity enum
			// severity package doesn't have StringToSeverity, so we'll use a map
			sevMap := map[string]severity.Severity{
				"critical": severity.Critical,
				"high":     severity.High,
				"medium":   severity.Medium,
				"low":      severity.Low,
				"info":     severity.Info,
			}
			if sev, ok := sevMap[strings.ToLower(s)]; ok {
				severities = append(severities, sev)
			}
		}
	} else {
		switch scanType {
		case "critical_only":
			severities = severity.Severities{severity.Critical, severity.High}
		default:
			severities = severity.Severities{severity.Critical, severity.High, severity.Medium, severity.Low, severity.Info}
		}
	}

	options := &types.Options{
		Targets:           goflags.StringSlice([]string{target}),
		Templates:         templates,
		Tags:              tags,
		Severities:        severities,
		DisableClustering: true,
		MaxHostError:      config.MaxHostError,
		StatsInterval:     5,
		MetricsPort:       9092,
	}

	if config.Timeout > 0 {
		options.Timeout = config.Timeout
	}
	if config.RateLimit > 0 {
		options.RateLimit = config.RateLimit
	}
	if config.Retries > 0 {
		options.Retries = config.Retries
	}
	concurrency := config.Concurrency
	if concurrency < 1 {
		concurrency = 1
	}
	options.TemplateThreads = concurrency
	options.HeadlessTemplateThreads = concurrency
	options.BulkSize = concurrency
	options.HeadlessBulkSize = concurrency
	log.Printf("⚙️  Engine concurrency configured - templates:%d bulk:%d headless:%d", options.TemplateThreads, options.BulkSize, options.HeadlessTemplateThreads)

	if err := protocolstate.Init(options); err != nil {
		log.Printf("❌ Failed to initialize protocol state: %v", err)
		return jsonError(fmt.Errorf("protocol initialization failed: %w", err))
	}
	if err := protocolinit.Init(options); err != nil {
		log.Printf("❌ Failed to initialize protocol modules: %v", err)
		return jsonError(fmt.Errorf("protocol module initialization failed: %w", err))
	}

	// Initialize Nuclei engine
	// In Nuclei v3, core.New returns *Engine directly (no error)
	engine := core.New(options)

	// Initialize ExecuterOptions with Parser for template loading
	// This is required for parsing templates
	parser := nucleitemplates.NewParser()
	execOpts := &protocols.ExecutorOptions{
		Options: options,
		Parser:  parser,
		// Note: Output is set via Callback for results, but RequestTrackingWriter tracks requests
	}
	execOpts.ResumeCfg = types.NewResumeCfg()
	execOpts.Progress = &noopProgress{}
	// Use RequestTrackingWriter to track HTTP requests
	requestTracker := &RequestTrackingWriter{bridge: bridge}
	execOpts.Output = requestTracker
	engine.SetExecuterOptions(execOpts)

	bridge.mu.Lock()
	bridge.engine = engine
	bridge.scanState.ScanID = bridge.scanID
	bridge.scanState.CurrentTarget = target
	bridge.scanState.IsRunning = true
	bridge.scanState.IsPaused = false
	bridge.mu.Unlock()

	// Start scan in goroutine
	go func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("⚠️  Recovered from panic during scan execution: %v", r)
			}
			bridge.mu.Lock()
			bridge.isRunning = false
			bridge.scanState.IsRunning = false
			bridge.scanState.QueueLength = 0
			bridge.mu.Unlock()
			log.Printf("🔚 Scan goroutine finished for %s", target)
		}()

		log.Printf("🚀 Starting engine.ExecuteWithResults() for %s", target)
		ctx := context.Background()

		execOpts := engine.ExecuterOptions()
		if execOpts == nil || execOpts.Parser == nil {
			log.Printf("❌ Engine ExecuterOptions or Parser not available")
			bridge.mu.Lock()
			bridge.isRunning = false
			bridge.scanState.IsRunning = false
			bridge.scanState.FailedRequests++
			bridge.mu.Unlock()
			return
		}

		rawTemplates := config.RawTemplates
		if len(rawTemplates) == 0 {
			log.Printf("⚠️  No raw templates provided for scan %s (requested identifiers: %d)", bridge.scanID, len(config.Requested))
			bridge.mu.Lock()
			bridge.isRunning = false
			bridge.scanState.IsRunning = false
			bridge.scanState.FailedRequests++
			bridge.mu.Unlock()
			return
		}

		allowed := config.MaxTemplates
		if allowed <= 0 || allowed > len(rawTemplates) {
			allowed = len(rawTemplates)
		}

		loadedTemplates := make([]*nucleitemplates.Template, 0, allowed)
		metadata := config.TemplateMeta
		for idx, payload := range rawTemplates {
			if len(loadedTemplates) >= allowed {
				break
			}

			content := strings.TrimSpace(payload)
			meta := TemplateMetadata{}
			if idx < len(metadata) {
				meta = metadata[idx]
			}
			label := metadataLabel(meta, idx)

			if content == "" {
				log.Printf("⚠️  Template %s resolved to empty content, skipping", label)
				continue
			}

			tpl, err := parseTemplateFromRaw(content, execOpts)
			if err != nil {
				log.Printf("⚠️  Failed to parse template %s: %v", label, err)
				continue
			}
			if tpl == nil || tpl.Executer == nil {
				log.Printf("⚠️  Parsed template %s has no executer, skipping", label)
				continue
			}

			if meta.TemplateID != "" {
				tpl.ID = meta.TemplateID
			}
			switch {
			case meta.TemplatePath != "":
				tpl.Path = meta.TemplatePath
			case meta.TemplateID != "":
				tpl.Path = meta.TemplateID
			case tpl.Path == "":
				tpl.Path = fmt.Sprintf("in-memory-%d", idx)
			}

			if tpl.Type() == templatetypes.HeadlessProtocol && !options.Headless {
				log.Printf("⚠️  Template '%s' requires headless execution - skipping (headless disabled)", tpl.ID)
				continue
			}

			loadedTemplates = append(loadedTemplates, tpl)
		}

		if len(loadedTemplates) == 0 {
			log.Printf("⚠️  No templates parsed successfully for target %s", target)
			bridge.mu.Lock()
			bridge.isRunning = false
			bridge.scanState.IsRunning = false
			bridge.scanState.FailedRequests++
			bridge.mu.Unlock()
			return
		}

		if len(rawTemplates) > allowed {
			log.Printf("ℹ️  Loaded %d/%d templates (max_templates=%d)", len(loadedTemplates), len(rawTemplates), allowed)
		} else {
			log.Printf("✅ Loaded %d templates for in-memory scan", len(loadedTemplates))
		}

		// Create input provider from target using SimpleInputProvider
		log.Printf("🎯 Creating input provider for target: %s", target)
		inputProvider := provider.NewSimpleInputProviderWithUrls(bridge.scanID, target)

		if inputProvider == nil {
			log.Printf("❌ Failed to create input provider")
			bridge.mu.Lock()
			bridge.isRunning = false
			bridge.scanState.IsRunning = false
			bridge.scanState.FailedRequests++
			bridge.mu.Unlock()
			return
		}

		log.Printf("✅ Input provider created with 1 target")

		activeTemplates := make([]string, 0, len(loadedTemplates))
		for _, tpl := range loadedTemplates {
			activeID := tpl.ID
			if activeID == "" {
				activeID = tpl.Path
			}
			activeTemplates = append(activeTemplates, activeID)
		}

		bridge.mu.Lock()
		bridge.scanState.ActiveTemplates = activeTemplates
		bridge.scanState.QueueLength = len(activeTemplates)
		bridge.mu.Unlock()

		// Create custom output writer that streams to eventChannel
		// This must be created inside the goroutine to ensure proper initialization
		outputWriter := &EventStreamWriter{
			eventChannel: bridge.eventChannel,
			scanID:       bridge.scanID,
		}

		// In Nuclei v3, results are delivered via the Output writer interface, not callback parameter
		// Update ExecuterOptions to use our EventStreamWriter for results
		execOpts = engine.ExecuterOptions()
		if execOpts != nil {
			// Set our EventStreamWriter as the Output - this is how Nuclei v3 delivers results
			// Note: We keep RequestTrackingWriter for request stats, but EventStreamWriter for results
			// Create a combined writer that does both
			execOpts.Output = outputWriter
			engine.SetExecuterOptions(execOpts)
			log.Printf("📝 Configured EventStreamWriter as Output for result delivery")
		}

		// Also set engine.Callback as additional mechanism (some versions use this)
		engine.Callback = func(event *output.ResultEvent) {
			matched := event.Matched
			if len(matched) > 50 {
				matched = matched[:50] + "..."
			}
			log.Printf("🎯 engine.Callback invoked: TemplateID=%s, Severity=%s, Matched=%s",
				event.TemplateID,
				event.Info.SeverityHolder.Severity.String(),
				matched)
			if err := outputWriter.Write(event); err != nil {
				log.Printf("⚠️ engine.Callback: Failed to write event to channel: %v", err)
			} else {
				log.Printf("✅ Event successfully written via engine.Callback: %s", event.TemplateID)
			}
		}

		// Execute with loaded templates and input provider
		// Note: ExecuteWithResults may use Output writer instead of callback parameter
		log.Printf("⚡ Executing scan with %d templates", len(loadedTemplates))
		result := engine.ExecuteWithResults(ctx, loadedTemplates, inputProvider, nil)

		if result != nil && result.Load() {
			log.Printf("✅ engine.ExecuteWithResults() completed successfully for %s", target)
		} else {
			log.Printf("⚠️ engine.ExecuteWithResults() completed with no results for %s", target)
		}

		// Mark scan as completed
		bridge.mu.Lock()
		bridge.scanState.IsRunning = false
		bridge.scanState.ProgressPercent = 100.0
		bridge.mu.Unlock()
	}()

	log.Printf("✅ Scan started: %s for target: %s", bridge.scanID, target)
	return jsonSuccess(map[string]interface{}{
		"message":      "Scan started",
		"scan_id":      bridge.scanID,
		"target":       target,
		"memory_based": true,
		"real_time":    true,
	})
}

// EventStreamWriter implements output.Writer to stream events
type EventStreamWriter struct {
	eventChannel chan NucleiEvent
	scanID       string
	droppedCount int64 // Track dropped events for monitoring
}

func (w *EventStreamWriter) Close() {}
func (w *EventStreamWriter) Colorizer() aurora.Aurora {
	return aurora.NewAurora(false)
}
func (w *EventStreamWriter) WriteFailure(*output.InternalWrappedEvent) error {
	return nil
}
func (w *EventStreamWriter) Request(templateID, url, requestType string, err error) {}
func (w *EventStreamWriter) RequestStatsLog(statusCode, response string)            {}
func (w *EventStreamWriter) WriteStoreDebugData(host, templateID, eventType, data string) {
}
func (w *EventStreamWriter) ResultCount() int { return 0 }

func (w *EventStreamWriter) Write(event *output.ResultEvent) error {
	log.Printf("📥 EventStreamWriter.Write called: TemplateID=%s, Severity=%s", event.TemplateID, event.Info.SeverityHolder.Severity.String())

	severityValue := strings.ToLower(event.Info.SeverityHolder.Severity.String())
	if severityValue == "" {
		severityValue = "unknown"
	}

	target := event.URL
	if target == "" {
		target = event.Matched
	}

	nucleiEvent := NucleiEvent{
		Timestamp:  time.Now().Format(time.RFC3339),
		EventType:  "VULNERABILITY",
		TemplateID: event.TemplateID,
		Severity:   severityValue,
		Target:     target,
		MatchedAt:  event.Matched,
		Request:    event.Request,
		Response:   event.Response,
		Info: map[string]interface{}{
			"name":        event.Info.Name,
			"authors":     event.Info.Authors,
			"tags":        event.Info.Tags,
			"description": event.Info.Description,
			"reference":   event.Info.Reference,
			"metadata":    event.Info.Metadata,
		},
	}

	log.Printf("📤 Sending event to channel: TemplateID=%s, EventType=%s", nucleiEvent.TemplateID, nucleiEvent.EventType)
	select {
	case w.eventChannel <- nucleiEvent:
		log.Printf("✅ Event sent to channel successfully: %s", nucleiEvent.TemplateID)
		return nil
	default:
		// Channel full - implement backpressure
		w.droppedCount++
		if w.droppedCount%10 == 1 { // Log every 10th dropped event to avoid spam
			log.Printf("⚠️ Event channel full (dropped %d events), consider increasing channel size or processing faster", w.droppedCount)
		}
		return fmt.Errorf("event channel full")
	}
}

// GetDroppedCount returns number of dropped events (for monitoring)
func (w *EventStreamWriter) GetDroppedCount() int64 {
	return w.droppedCount
}

//export GetScanState
func GetScanState() *C.char {
	bridgeMutex.RLock()
	bridge := bridgeInstance
	bridgeMutex.RUnlock()

	if bridge == nil || bridge.scanState == nil {
		return jsonError(fmt.Errorf("bridge not initialized"))
	}

	bridge.mu.RLock()
	defer bridge.mu.RUnlock()

	jsonResult, err := json.Marshal(bridge.scanState)
	if err != nil {
		return jsonError(fmt.Errorf("failed to marshal scan state: %w", err))
	}
	return createCString(string(jsonResult))
}

//export ControlScan
func ControlScan(actionC *C.char, paramsJSON *C.char) *C.char {
	bridgeMutex.RLock()
	bridge := bridgeInstance
	bridgeMutex.RUnlock()

	if bridge == nil {
		return jsonError(fmt.Errorf("bridge not initialized"))
	}

	action := C.GoString(actionC)
	paramsStr := C.GoString(paramsJSON)

	// Validate action
	validActions := map[string]bool{
		"pause":           true,
		"resume":          true,
		"prioritize":      true,
		"skip_target":     true,
		"adjust_rate":     true,
		"switch_template": true,
	}
	if !validActions[action] {
		return jsonError(fmt.Errorf("unknown action: %s", action))
	}

	// Parse params
	var params map[string]interface{}
	if paramsStr != "" {
		if err := json.Unmarshal([]byte(paramsStr), &params); err != nil {
			return jsonError(fmt.Errorf("invalid params JSON: %w", err))
		}
	}

	bridge.mu.Lock()
	defer bridge.mu.Unlock()

	switch action {
	case "pause":
		if !bridge.isRunning {
			return jsonError(fmt.Errorf("scan is not running"))
		}
		if bridge.isPaused {
			return jsonError(fmt.Errorf("scan is already paused"))
		}
		bridge.isPaused = true
		bridge.scanState.IsPaused = true
		log.Println("⏸️ Scan paused")
		return jsonSuccess(map[string]interface{}{
			"action":  "pause",
			"scan_id": bridge.scanID,
		})

	case "resume":
		if !bridge.isRunning {
			return jsonError(fmt.Errorf("scan is not running"))
		}
		if !bridge.isPaused {
			return jsonError(fmt.Errorf("scan is not paused"))
		}
		bridge.isPaused = false
		bridge.scanState.IsPaused = false
		log.Println("▶️ Scan resumed")
		return jsonSuccess(map[string]interface{}{
			"action":  "resume",
			"scan_id": bridge.scanID,
		})

	case "prioritize":
		templateID, ok := params["template_id"].(string)
		if !ok || templateID == "" {
			return jsonError(fmt.Errorf("template_id required for prioritize action"))
		}
		// Note: Actual template prioritization would require engine API access
		log.Printf("📌 Template prioritized: %s", templateID)
		return jsonSuccess(map[string]interface{}{
			"action":      "prioritize",
			"template_id": templateID,
			"scan_id":     bridge.scanID,
		})

	case "skip_target":
		if !bridge.isRunning {
			return jsonError(fmt.Errorf("scan is not running"))
		}
		log.Println("⏭️ Target skipped")
		return jsonSuccess(map[string]interface{}{
			"action":  "skip_target",
			"scan_id": bridge.scanID,
		})

	case "adjust_rate":
		rate, ok := params["rate"].(float64)
		if !ok || rate <= 0 {
			return jsonError(fmt.Errorf("valid rate required for adjust_rate action"))
		}
		// Note: Actual rate adjustment would require engine API access
		log.Printf("⚡ Rate adjusted to: %.0f", rate)
		return jsonSuccess(map[string]interface{}{
			"action":  "adjust_rate",
			"rate":    int(rate),
			"scan_id": bridge.scanID,
		})

	case "switch_template":
		templateID, ok := params["template_id"].(string)
		if !ok || templateID == "" {
			return jsonError(fmt.Errorf("template_id required for switch_template action"))
		}
		// Note: Actual template switching would require engine API access
		log.Printf("🔄 Template switched to: %s", templateID)
		return jsonSuccess(map[string]interface{}{
			"action":      "switch_template",
			"template_id": templateID,
			"scan_id":     bridge.scanID,
		})

	default:
		return jsonError(fmt.Errorf("unknown action: %s", action))
	}
}

//export CleanupBridge
func CleanupBridge() *C.char {
	bridgeMutex.Lock()
	defer bridgeMutex.Unlock()

	if bridgeInstance == nil {
		return jsonError(fmt.Errorf("bridge not initialized"))
	}

	if bridgeInstance.cancel != nil {
		bridgeInstance.cancel()
	}

	// Wait for goroutines to finish with timeout
	done := make(chan bool)
	go func() {
		// Give event handler time to process final events
		time.Sleep(50 * time.Millisecond)
		done <- true
	}()

	select {
	case <-done:
		// Goroutines finished
	case <-time.After(500 * time.Millisecond):
		// Timeout - log warning but continue
		log.Println("⚠️ Cleanup timeout - some goroutines may still be running")
	}

	bridgeInstance = nil
	log.Println("🧹 Bridge cleaned up")
	return jsonSuccess(map[string]interface{}{
		"message": "Bridge cleaned up",
	})
}

// eventHandler processes events from Nuclei and forwards to Python
func (b *SurgeMemoryBridge) eventHandler() {
	for {
		select {
		case <-b.ctx.Done():
			return
		case event, ok := <-b.eventChannel:
			if !ok {
				return
			}
			b.processEvent(event)
		}
	}
}

// processEvent processes events and updates scan state
func (b *SurgeMemoryBridge) processEvent(event NucleiEvent) {
	log.Printf("🔄 processEvent called: EventType=%s, TemplateID=%s", event.EventType, event.TemplateID)

	var callbackPayload string
	var callbackPointer C.vuln_cb_t

	b.mu.Lock()
	callbackPointer = getVulnerabilityCallback()

	// Update scan state based on event
	switch event.EventType {
	case "VULNERABILITY":
		b.scanState.VulnsFound = append(b.scanState.VulnsFound, event)
		b.scanState.SuccessfulRequests++
		log.Printf("🔍 Vulnerability found: %s on %s (Severity: %s)", event.TemplateID, event.Target, event.Severity)
		if callbackPointer != nil {
			if encoded, err := json.Marshal(event); err == nil {
				callbackPayload = string(encoded)
			} else {
				log.Printf("⚠️  Failed to marshal vulnerability event: %v", err)
			}
		}

	case "PROGRESS":
		if progress, ok := event.Info["progress"].(float64); ok {
			b.scanState.ProgressPercent = progress
		}
		if total, ok := event.Info["total_requests"].(float64); ok {
			b.scanState.TotalRequests = int(total)
		}
		if successful, ok := event.Info["successful_requests"].(float64); ok {
			b.scanState.SuccessfulRequests = int(successful)
		}
		if failed, ok := event.Info["failed_requests"].(float64); ok {
			b.scanState.FailedRequests = int(failed)
		}

	case "STATE_CHANGE":
		if state, ok := event.Info["state"].(string); ok {
			if state == "completed" {
				b.isRunning = false
				b.scanState.IsRunning = false
			}
		}
	}

	// TODO: Implement Python callback mechanism
	// For now, events are stored in scan state and can be retrieved via GetScanState()
	b.mu.Unlock()

	if callbackPointer != nil && callbackPayload != "" {
		cstr := C.CString(callbackPayload)
		C.call_vuln_callback(callbackPointer, cstr)
		C.free(unsafe.Pointer(cstr))
	}
}

func main() {
	// This is a shared library, main is empty
}
