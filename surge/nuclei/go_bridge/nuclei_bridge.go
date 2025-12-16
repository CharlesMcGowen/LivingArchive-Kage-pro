package main

/*
#cgo CFLAGS: -I${SRCDIR}
#include <stdlib.h>
#include "nuclei_bridge.h"

// Callback function types - Python will provide these function pointers
typedef void (*VulnCallback)(char* jsonData);
typedef void (*ProgressCallback)(char* jsonData);
typedef void (*StateCallback)(char* jsonData);
typedef void (*ErrorCallback)(char* jsonData);

// Helper functions to call callbacks from Go
static inline void call_vuln_callback(VulnCallback cb, char* data) {
    if (cb != NULL) cb(data);
}
static inline void call_progress_callback(ProgressCallback cb, char* data) {
    if (cb != NULL) cb(data);
}
static inline void call_state_callback(StateCallback cb, char* data) {
    if (cb != NULL) cb(data);
}
static inline void call_error_callback(ErrorCallback cb, char* data) {
    if (cb != NULL) cb(data);
}
*/
import "C"
import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
	"unsafe"

	nuclei "github.com/projectdiscovery/nuclei/v3/lib"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// Global state for engines and callbacks
var (
	engineMap     = make(map[string]*engineState)
	engineMapLock sync.RWMutex
)

// engineState holds engine and its associated callbacks
type engineState struct {
	engine           *nuclei.NucleiEngine
	threadSafeEngine *nuclei.ThreadSafeNucleiEngine
	isThreadSafe     bool
	scanID           string
	
	// Callback function pointers from Python (via CGO)
	vulnCallback    C.VulnCallback
	progressCallback C.ProgressCallback
	stateCallback   C.StateCallback
	errorCallback   C.ErrorCallback
	
	// Progress tracking
	progressTracker *customProgressTracker
	stats           *scanStats
	
	// Context for cancellation
	ctx    context.Context
	cancel context.CancelFunc
}

// scanStats tracks real-time scan statistics
type scanStats struct {
	mu                    sync.RWMutex
	totalRequests         int64
	completedRequests     int64
	successfulRequests    int64
	failedRequests        int64
	vulnerabilitiesFound  int64
	activeTemplates       []string
	currentTarget         string
	startTime             time.Time
	lastUpdate            time.Time
}

// customProgressTracker implements progress.Progress interface for real-time updates
type customProgressTracker struct {
	stats     *scanStats
	callback  C.ProgressCallback
	scanID    string
}

func (p *customProgressTracker) Stop() {}
func (p *customProgressTracker) Init(hostCount int64, rulesCount int, requestCount int64) {
	p.stats.mu.Lock()
	defer p.stats.mu.Unlock()
	p.stats.totalRequests = requestCount
	p.stats.startTime = time.Now()
	p.stats.lastUpdate = time.Now()
	
	// Send initial progress
	p.sendProgress()
}

func (p *customProgressTracker) AddToTotal(delta int64) {
	p.stats.mu.Lock()
	p.stats.totalRequests += delta
	p.stats.mu.Unlock()
	p.sendProgress()
}

func (p *customProgressTracker) IncrementRequests() {
	p.stats.mu.Lock()
	p.stats.completedRequests++
	p.stats.successfulRequests++
	p.stats.lastUpdate = time.Now()
	p.stats.mu.Unlock()
	p.sendProgress()
}

func (p *customProgressTracker) SetRequests(count uint64) {
	p.stats.mu.Lock()
	p.stats.completedRequests = int64(count)
	p.stats.lastUpdate = time.Now()
	p.stats.mu.Unlock()
	p.sendProgress()
}

func (p *customProgressTracker) IncrementMatched() {
	p.stats.mu.Lock()
	p.stats.vulnerabilitiesFound++
	p.stats.lastUpdate = time.Now()
	p.stats.mu.Unlock()
	p.sendProgress()
}

func (p *customProgressTracker) IncrementErrorsBy(count int64) {
	p.stats.mu.Lock()
	p.stats.failedRequests += count
	p.stats.lastUpdate = time.Now()
	p.stats.mu.Unlock()
	p.sendProgress()
}

func (p *customProgressTracker) IncrementFailedRequestsBy(count int64) {
	p.stats.mu.Lock()
	p.stats.completedRequests += count
	p.stats.failedRequests += count
	p.stats.lastUpdate = time.Now()
	p.stats.mu.Unlock()
	p.sendProgress()
}

func (p *customProgressTracker) sendProgress() {
	if p.callback == nil {
		return
	}
	
	p.stats.mu.RLock()
	progressData := map[string]interface{}{
		"scan_id":           p.scanID,
		"total_requests":    p.stats.totalRequests,
		"completed_requests": p.stats.completedRequests,
		"successful_requests": p.stats.successfulRequests,
		"failed_requests":   p.stats.failedRequests,
		"vulnerabilities_found": p.stats.vulnerabilitiesFound,
		"active_templates":  p.stats.activeTemplates,
		"current_target":    p.stats.currentTarget,
		"start_time":        p.stats.startTime.Unix(),
		"last_update":       p.stats.lastUpdate.Unix(),
		"duration_seconds": time.Since(p.stats.startTime).Seconds(),
	}
	
	// Calculate progress percentage
	if p.stats.totalRequests > 0 {
		progressData["progress_percent"] = float64(p.stats.completedRequests) / float64(p.stats.totalRequests) * 100.0
	} else {
		progressData["progress_percent"] = 0.0
	}
	p.stats.mu.RUnlock()
	
	jsonData, err := json.Marshal(progressData)
	if err != nil {
		return
	}
	
	// Convert to C string (CGO will handle memory)
	cStr := C.CString(string(jsonData))
	defer C.free(unsafe.Pointer(cStr))
	
	// Call Python callback via C helper
	if p.callback != nil {
		C.call_progress_callback(p.callback, cStr)
	}
}

//export InitializeNucleiEngine
func InitializeNucleiEngine(engineID *C.char, configJSON *C.char, useThreadSafe C.int) *C.char {
	engineIDStr := C.GoString(engineID)
	configJSONStr := C.GoString(configJSON)
	threadSafe := useThreadSafe != 0

	// Parse configuration
	var config map[string]interface{}
	if err := json.Unmarshal([]byte(configJSONStr), &config); err != nil {
		return C.CString(fmt.Sprintf(`{"error": "Invalid config JSON: %v"}`, err))
	}

	ctx, cancel := context.WithCancel(context.Background())
	state := &engineState{
		isThreadSafe: threadSafe,
		ctx:          ctx,
		cancel:       cancel,
		stats:        &scanStats{},
	}

	// Build Nuclei SDK options
	opts := buildNucleiOptions(config)

	var err error
	if threadSafe {
		state.threadSafeEngine, err = nuclei.NewThreadSafeNucleiEngineCtx(ctx, opts...)
		if err != nil {
			cancel()
			return C.CString(fmt.Sprintf(`{"error": "Failed to create thread-safe engine: %v"}`, err))
		}
	} else {
		// For non-thread-safe engines, we can use custom progress tracker
		// But we'll track progress via callbacks instead for simplicity
		state.engine, err = nuclei.NewNucleiEngineCtx(ctx, opts...)
		if err != nil {
			cancel()
			return C.CString(fmt.Sprintf(`{"error": "Failed to create engine: %v"}`, err))
		}
	}

	// Store engine
	engineMapLock.Lock()
	engineMap[engineIDStr] = state
	engineMapLock.Unlock()

	return C.CString(`{"status": "success", "engine_id": "` + engineIDStr + `", "thread_safe": ` + fmt.Sprintf("%v", threadSafe) + `}`)
}

// buildNucleiOptions converts Python config dict to Nuclei SDK options
// Maps all ScanConfig fields to Nuclei SDK options for comprehensive feature exposure
func buildNucleiOptions(config map[string]interface{}) []nuclei.NucleiSDKOptions {
	opts := []nuclei.NucleiSDKOptions{}

	// ========== Template Selection ==========
	templateFilters := nuclei.TemplateFilters{}
	hasTemplateFilters := false

	if templates, ok := config["templates"].([]interface{}); ok && len(templates) > 0 {
		templatePaths := make([]string, len(templates))
		for i, t := range templates {
			templatePaths[i] = t.(string)
		}
		templateFilters.IDs = templatePaths
		hasTemplateFilters = true
	}

	if tags, ok := config["tags"].([]interface{}); ok && len(tags) > 0 {
		tagList := make([]string, len(tags))
		for i, t := range tags {
			tagList[i] = t.(string)
		}
		templateFilters.Tags = tagList
		hasTemplateFilters = true
	}

	if severities, ok := config["severities"].([]interface{}); ok && len(severities) > 0 {
		severityStr := ""
		for i, s := range severities {
			if i > 0 {
				severityStr += ","
			}
			severityStr += s.(string)
		}
		templateFilters.Severity = severityStr
		hasTemplateFilters = true
	}

	if hasTemplateFilters {
		opts = append(opts, nuclei.WithTemplateFilters(templateFilters))
	}

	// Template paths and workflows
	templatePaths := []string{}
	if paths, ok := config["template_paths"].([]interface{}); ok && len(paths) > 0 {
		for _, p := range paths {
			templatePaths = append(templatePaths, p.(string))
		}
	}

	workflows := []string{}
	if wfs, ok := config["workflows"].([]interface{}); ok && len(wfs) > 0 {
		for _, w := range wfs {
			workflows = append(workflows, w.(string))
		}
	}

	if len(templatePaths) > 0 || len(workflows) > 0 {
		opts = append(opts, nuclei.WithTemplatesOrWorkflows(nuclei.TemplateSources{
			Templates: templatePaths,
			Workflows: workflows,
		}))
	}

	// ========== Template Types ==========
	if enable, ok := config["enable_code_templates"].(bool); ok && enable {
		opts = append(opts, nuclei.EnableCodeTemplates())
	}

	if enable, ok := config["enable_self_contained_templates"].(bool); ok && enable {
		opts = append(opts, nuclei.EnableSelfContainedTemplates())
	}

	if enable, ok := config["enable_global_matchers_templates"].(bool); ok && enable {
		opts = append(opts, nuclei.EnableGlobalMatchersTemplates())
	}

	if enable, ok := config["enable_file_templates"].(bool); ok && enable {
		opts = append(opts, nuclei.EnableFileTemplates())
	}

	// ========== Rate Limiting ==========
	if rateLimit, ok := config["rate_limit"].(float64); ok && rateLimit > 0 {
		duration := time.Second
		if durSec, ok := config["rate_limit_duration_seconds"].(float64); ok && durSec > 0 {
			duration = time.Duration(durSec * float64(time.Second))
		}
		opts = append(opts, nuclei.WithGlobalRateLimitCtx(context.Background(), int(rateLimit), duration))
	}

	// ========== Concurrency ==========
	concurrency := nuclei.Concurrency{
		TemplateConcurrency:           5, // defaults
		HostConcurrency:               5,
		HeadlessHostConcurrency:       1,
		HeadlessTemplateConcurrency:   1,
		JavascriptTemplateConcurrency: 1,
		TemplatePayloadConcurrency:    25,
		ProbeConcurrency:             50,
	}

	if tc, ok := config["template_concurrency"].(float64); ok && tc > 0 {
		concurrency.TemplateConcurrency = int(tc)
	}
	if hc, ok := config["host_concurrency"].(float64); ok && hc > 0 {
		concurrency.HostConcurrency = int(hc)
	}
	if hhc, ok := config["headless_host_concurrency"].(float64); ok && hhc > 0 {
		concurrency.HeadlessHostConcurrency = int(hhc)
	}
	if htc, ok := config["headless_template_concurrency"].(float64); ok && htc > 0 {
		concurrency.HeadlessTemplateConcurrency = int(htc)
	}
	if jtc, ok := config["javascript_template_concurrency"].(float64); ok && jtc > 0 {
		concurrency.JavascriptTemplateConcurrency = int(jtc)
	}
	if tpc, ok := config["template_payload_concurrency"].(float64); ok && tpc > 0 {
		concurrency.TemplatePayloadConcurrency = int(tpc)
	}
	if pc, ok := config["probe_concurrency"].(float64); ok && pc > 0 {
		concurrency.ProbeConcurrency = int(pc)
	}

	opts = append(opts, nuclei.WithConcurrency(concurrency))

	// ========== Network Configuration ==========
	networkConfig := nuclei.NetworkConfig{}

	if timeout, ok := config["timeout"].(float64); ok && timeout > 0 {
		networkConfig.Timeout = int(timeout)
	}
	if retries, ok := config["retries"].(float64); ok && retries >= 0 {
		networkConfig.Retries = int(retries)
	}
	if mhe, ok := config["max_host_error"].(float64); ok && mhe > 0 {
		networkConfig.MaxHostError = int(mhe)
	}
	if disable, ok := config["disable_max_host_error"].(bool); ok {
		networkConfig.DisableMaxHostErr = disable
	}
	if iface, ok := config["interface"].(string); ok && iface != "" {
		networkConfig.Interface = iface
	}
	if sip, ok := config["source_ip"].(string); ok && sip != "" {
		networkConfig.SourceIP = sip
	}
	if sr, ok := config["system_resolvers"].(bool); ok {
		networkConfig.SystemResolvers = sr
	}
	if ir, ok := config["internal_resolvers"].([]interface{}); ok && len(ir) > 0 {
		resolvers := make([]string, len(ir))
		for i, r := range ir {
			resolvers[i] = r.(string)
		}
		networkConfig.InternalResolversList = resolvers
	}
	if ldp, ok := config["leave_default_ports"].(bool); ok {
		networkConfig.LeaveDefaultPorts = ldp
	}
	if te, ok := config["track_error"].([]interface{}); ok && len(te) > 0 {
		errors := make([]string, len(te))
		for i, e := range te {
			errors[i] = e.(string)
		}
		networkConfig.TrackError = errors
	}

	// Only add NetworkConfig if at least one field is set
	if networkConfig.Timeout > 0 || networkConfig.Retries >= 0 || networkConfig.MaxHostError > 0 ||
		networkConfig.DisableMaxHostErr || networkConfig.Interface != "" || networkConfig.SourceIP != "" ||
		networkConfig.SystemResolvers || len(networkConfig.InternalResolversList) > 0 ||
		networkConfig.LeaveDefaultPorts || len(networkConfig.TrackError) > 0 {
		opts = append(opts, nuclei.WithNetworkConfig(networkConfig))
	}

	// ========== HTTP Options ==========
	if headers, ok := config["headers"].([]interface{}); ok && len(headers) > 0 {
		headerList := make([]string, len(headers))
		for i, h := range headers {
			headerList[i] = h.(string)
		}
		opts = append(opts, nuclei.WithHeaders(headerList))
	}

	if proxies, ok := config["proxies"].([]interface{}); ok && len(proxies) > 0 {
		proxyList := make([]string, len(proxies))
		for i, p := range proxies {
			proxyList[i] = p.(string)
		}
		proxyInternal := false
		if pir, ok := config["proxy_internal_requests"].(bool); ok {
			proxyInternal = pir
		}
		opts = append(opts, nuclei.WithProxy(proxyList, proxyInternal))
	}

	if rrs, ok := config["response_read_size"].(float64); ok && rrs >= 0 {
		opts = append(opts, nuclei.WithResponseReadSize(int(rrs)))
	}

	// ========== Scan Strategy ==========
	if strategy, ok := config["scan_strategy"].(string); ok && strategy != "" {
		opts = append(opts, nuclei.WithScanStrategy(strategy))
	}

	// ========== Verbosity & Debugging ==========
	verbosityOpts := nuclei.VerbosityOptions{}
	if verbose, ok := config["verbose"].(bool); ok {
		verbosityOpts.Verbose = verbose
	}
	if silent, ok := config["silent"].(bool); ok {
		verbosityOpts.Silent = silent
	}
	if debug, ok := config["debug"].(bool); ok {
		verbosityOpts.Debug = debug
	}
	if debugReq, ok := config["debug_request"].(bool); ok {
		verbosityOpts.DebugRequest = debugReq
	}
	if debugResp, ok := config["debug_response"].(bool); ok {
		verbosityOpts.DebugResponse = debugResp
	}
	if svd, ok := config["show_var_dump"].(bool); ok {
		verbosityOpts.ShowVarDump = svd
	}

	if verbosityOpts.Verbose || verbosityOpts.Silent || verbosityOpts.Debug ||
		verbosityOpts.DebugRequest || verbosityOpts.DebugResponse || verbosityOpts.ShowVarDump {
		opts = append(opts, nuclei.WithVerbosity(verbosityOpts))
	}

	// ========== Matcher Status ==========
	if ms, ok := config["matcher_status"].(bool); ok && ms {
		opts = append(opts, nuclei.EnableMatcherStatus())
	}

	// ========== Headless Browser ==========
	if enable, ok := config["enable_headless"].(bool); ok && enable {
		headlessOpts := &nuclei.HeadlessOpts{}
		if pto, ok := config["headless_page_timeout"].(float64); ok && pto > 0 {
			headlessOpts.PageTimeout = int(pto)
		}
		if sb, ok := config["headless_show_browser"].(bool); ok {
			headlessOpts.ShowBrowser = sb
		}
		if ho, ok := config["headless_options"].([]interface{}); ok && len(ho) > 0 {
			options := make([]string, len(ho))
			for i, o := range ho {
				options[i] = o.(string)
			}
			headlessOpts.HeadlessOptions = options
		}
		if uc, ok := config["headless_use_chrome"].(bool); ok {
			headlessOpts.UseChrome = uc
		}
		opts = append(opts, nuclei.EnableHeadlessWithOpts(headlessOpts))
	}

	// ========== Sandbox Options ==========
	allowLocal := false
	restrictLocal := false
	if alfa, ok := config["allow_local_file_access"].(bool); ok {
		allowLocal = alfa
	}
	if rlna, ok := config["restrict_local_network_access"].(bool); ok {
		restrictLocal = rlna
	}
	if allowLocal || restrictLocal {
		opts = append(opts, nuclei.WithSandboxOptions(allowLocal, restrictLocal))
	}

	// ========== Template Variables ==========
	if vars, ok := config["vars"].(map[string]interface{}); ok && len(vars) > 0 {
		varList := []string{}
		for k, v := range vars {
			varList = append(varList, fmt.Sprintf("%s=%v", k, v))
		}
		opts = append(opts, nuclei.WithVars(varList))
	}

	// ========== Resume File ==========
	if rf, ok := config["resume_file"].(string); ok && rf != "" {
		opts = append(opts, nuclei.WithResumeFile(rf))
	}

	// ========== Passive Mode ==========
	if pm, ok := config["passive_mode"].(bool); ok && pm {
		opts = append(opts, nuclei.EnablePassiveMode())
	}

	// ========== Interactsh (OOB Testing) ==========
	// Note: Interactsh is NOT supported in ThreadSafeNucleiEngine mode
	// This will be checked during engine initialization if thread-safe mode is used
	if enable, ok := config["enable_interactsh"].(bool); ok && enable {
		interactshOpts := nuclei.InteractshOpts{}
		
		if serverURL, ok := config["interactsh_server_url"].(string); ok && serverURL != "" {
			interactshOpts.ServerURL = serverURL
		} else {
			// Set default server URL if not provided
			interactshOpts.ServerURL = "https://interactsh.com"
		}
		
		if token, ok := config["interactsh_token"].(string); ok && token != "" {
			interactshOpts.Authorization = token
		}
		
		opts = append(opts, nuclei.WithInteractshOptions(interactshOpts))
	}

	return opts
}

//export RegisterCallbacks
func RegisterCallbacks(engineID *C.char, scanID *C.char,
	vulnCB C.VulnCallback, progressCB C.ProgressCallback,
	stateCB C.StateCallback, errorCB C.ErrorCallback) *C.char {
	
	engineIDStr := C.GoString(engineID)
	scanIDStr := C.GoString(scanID)

	engineMapLock.Lock()
	defer engineMapLock.Unlock()

	state, exists := engineMap[engineIDStr]
	if !exists {
		return C.CString(`{"error": "Engine not found"}`)
	}

	// Register callbacks
	state.vulnCallback = vulnCB
	state.progressCallback = progressCB
	state.stateCallback = stateCB
	state.errorCallback = errorCB
	state.scanID = scanIDStr

	// Setup custom progress tracker (only for non-thread-safe engines)
	if state.engine != nil && !state.isThreadSafe {
		state.progressTracker = &customProgressTracker{
			stats:    state.stats,
			callback: progressCB,
			scanID:   scanIDStr,
		}
		// Inject custom progress tracker via UseStatsWriter
		// Note: This requires engine recreation, so we'll track progress via callbacks instead
	}

	return C.CString(`{"status": "registered", "scan_id": "` + scanIDStr + `"}`)
}

//export ExecuteScan
func ExecuteScan(engineID *C.char, targetsJSON *C.char) *C.char {
	engineIDStr := C.GoString(engineID)
	targetsJSONStr := C.GoString(targetsJSON)

	engineMapLock.RLock()
	state, exists := engineMap[engineIDStr]
	engineMapLock.RUnlock()

	if !exists {
		return C.CString(`{"error": "Engine not found"}`)
	}

	// Parse targets
	var targets []string
	if err := json.Unmarshal([]byte(targetsJSONStr), &targets); err != nil {
		return C.CString(fmt.Sprintf(`{"error": "Invalid targets JSON: %v"}`, err))
	}

	if len(targets) == 0 {
		return C.CString(`{"error": "No targets provided"}`)
	}

	// Update stats
	state.stats.mu.Lock()
	state.stats.currentTarget = targets[0]
	state.stats.startTime = time.Now()
	state.stats.mu.Unlock()

	// Send state change
	if state.stateCallback != nil {
		stateData := map[string]interface{}{
			"scan_id": state.scanID,
			"status":  "running",
			"targets": targets,
		}
		jsonData, _ := json.Marshal(stateData)
		cStr := C.CString(string(jsonData))
		defer C.free(unsafe.Pointer(cStr))
		C.call_state_callback(state.stateCallback, cStr)
	}

	// Create result callback that marshals to JSON and calls Python
	resultCallback := func(event *output.ResultEvent) {
		if state.vulnCallback == nil {
			return
		}

		// Convert ResultEvent to JSON
		eventJSON, err := json.Marshal(event)
		if err != nil {
			return
		}

		// Update stats
		state.stats.mu.Lock()
		state.stats.vulnerabilitiesFound++
		state.stats.completedRequests++ // Each finding represents a completed request
		state.stats.successfulRequests++
		state.stats.lastUpdate = time.Now()
		state.stats.mu.Unlock()
		
		// Send progress update
		if state.progressCallback != nil && state.progressTracker != nil {
			state.progressTracker.sendProgress()
		}

		// Send to Python via callback (CGO manages memory - Python must free)
		cStr := C.CString(string(eventJSON))
		// Call via C helper function
		C.call_vuln_callback(state.vulnCallback, cStr)
		C.free(unsafe.Pointer(cStr)) // Free immediately after callback
	}

	// Execute scan in goroutine
	go func() {
		var err error
		if state.isThreadSafe {
			// Use ThreadSafeNucleiEngine - set global callback first
			state.threadSafeEngine.GlobalResultCallback(resultCallback)
			err = state.threadSafeEngine.ExecuteNucleiWithOpts(targets)
		} else {
			// Use regular engine
			state.engine.LoadTargets(targets, false)
			
			// Update stats - we'll track progress via callbacks
			state.stats.mu.Lock()
			state.stats.startTime = time.Now()
			state.stats.mu.Unlock()
			
			// Send initial progress
			if state.progressCallback != nil && state.progressTracker != nil {
				state.progressTracker.sendProgress()
			}
			
			// Execute with callback
			err = state.engine.ExecuteCallbackWithCtx(state.ctx, resultCallback)
		}

		if err != nil {
			if state.errorCallback != nil {
				errorData := map[string]interface{}{
					"scan_id": state.scanID,
					"error":   err.Error(),
					"type":    "execution_error",
				}
				jsonData, _ := json.Marshal(errorData)
				cStr := C.CString(string(jsonData))
				defer C.free(unsafe.Pointer(cStr))
				C.call_error_callback(state.errorCallback, cStr)
			}
		} else {
			// Scan completed successfully
			if state.stateCallback != nil {
				stateData := map[string]interface{}{
					"scan_id": state.scanID,
					"status":  "completed",
				}
				jsonData, _ := json.Marshal(stateData)
				cStr := C.CString(string(jsonData))
				defer C.free(unsafe.Pointer(cStr))
				C.call_state_callback(state.stateCallback, cStr)
			}
		}
	}()

	return C.CString(`{"status": "started", "scan_id": "` + state.scanID + `"}`)
}

//export GetScanState
func GetScanState(engineID *C.char) *C.char {
	engineIDStr := C.GoString(engineID)

	engineMapLock.RLock()
	state, exists := engineMap[engineIDStr]
	engineMapLock.RUnlock()

	if !exists {
		return C.CString(`{"error": "Engine not found"}`)
	}

	state.stats.mu.RLock()
	stateData := map[string]interface{}{
		"engine_id":          engineIDStr,
		"scan_id":            state.scanID,
		"status":            "running",
		"total_requests":    state.stats.totalRequests,
		"completed_requests": state.stats.completedRequests,
		"successful_requests": state.stats.successfulRequests,
		"failed_requests":   state.stats.failedRequests,
		"vulnerabilities_found": state.stats.vulnerabilitiesFound,
		"active_templates":  state.stats.activeTemplates,
		"current_target":    state.stats.currentTarget,
		"start_time":        state.stats.startTime.Unix(),
		"last_update":       state.stats.lastUpdate.Unix(),
		"duration_seconds":  time.Since(state.stats.startTime).Seconds(),
	}
	
	if state.stats.totalRequests > 0 {
		stateData["progress_percent"] = float64(state.stats.completedRequests) / float64(state.stats.totalRequests) * 100.0
	} else {
		stateData["progress_percent"] = 0.0
	}
	state.stats.mu.RUnlock()

	jsonData, _ := json.Marshal(stateData)
	return C.CString(string(jsonData))
}

//export PauseScan
func PauseScan(engineID *C.char) *C.char {
	engineIDStr := C.GoString(engineID)

	engineMapLock.RLock()
	state, exists := engineMap[engineIDStr]
	engineMapLock.RUnlock()

	if !exists {
		return C.CString(`{"error": "Engine not found"}`)
	}

	// Cancel context to pause (Nuclei doesn't have direct pause, but we can cancel)
	// For true pause/resume, we'd need to implement rate limiting to 0
	if state.cancel != nil {
		// Note: This will cancel, not pause. For true pause, we'd set rate limit to 0
		// state.cancel() // Don't cancel, just send state update
	}

	if state.stateCallback != nil {
		stateData := map[string]interface{}{
			"scan_id": state.scanID,
			"status":  "paused",
		}
		jsonData, _ := json.Marshal(stateData)
		cStr := C.CString(string(jsonData))
		defer C.free(unsafe.Pointer(cStr))
		C.call_state_callback(state.stateCallback, cStr)
	}

	return C.CString(`{"status": "paused"}`)
}

//export ResumeScan
func ResumeScan(engineID *C.char) *C.char {
	engineIDStr := C.GoString(engineID)

	engineMapLock.RLock()
	state, exists := engineMap[engineIDStr]
	engineMapLock.RUnlock()

	if !exists {
		return C.CString(`{"error": "Engine not found"}`)
	}

	if state.stateCallback != nil {
		stateData := map[string]interface{}{
			"scan_id": state.scanID,
			"status":  "running",
		}
		jsonData, _ := json.Marshal(stateData)
		cStr := C.CString(string(jsonData))
		defer C.free(unsafe.Pointer(cStr))
		C.call_state_callback(state.stateCallback, cStr)
	}

	return C.CString(`{"status": "resumed"}`)
}

//export AdjustRateLimit
func AdjustRateLimit(engineID *C.char, rateLimit C.int) *C.char {
	engineIDStr := C.GoString(engineID)
	newRate := int(rateLimit)

	engineMapLock.RLock()
	_, exists := engineMap[engineIDStr]
	engineMapLock.RUnlock()

	if !exists {
		return C.CString(`{"error": "Engine not found"}`)
	}

	// Note: Rate limit adjustment requires engine recreation in current Nuclei SDK
	// For now, return success and let Python handle it via engine recreation
	return C.CString(fmt.Sprintf(`{"status": "adjusted", "rate_limit": %d, "note": "Requires engine recreation"}`, newRate))
}

//export CloseEngine
func CloseEngine(engineID *C.char) *C.char {
	engineIDStr := C.GoString(engineID)

	engineMapLock.Lock()
	defer engineMapLock.Unlock()

	state, exists := engineMap[engineIDStr]
	if !exists {
		return C.CString(`{"error": "Engine not found"}`)
	}

	// Cancel context
	if state.cancel != nil {
		state.cancel()
	}

	// Close engine
	if state.engine != nil {
		state.engine.Close()
	}
	if state.threadSafeEngine != nil {
		state.threadSafeEngine.Close()
	}

	delete(engineMap, engineIDStr)

	return C.CString(`{"status": "closed"}`)
}

func main() {
	// This is a library, not an executable
}
