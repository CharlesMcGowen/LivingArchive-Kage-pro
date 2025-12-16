package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
)

// PathProcessingRequest represents the input for path processing
type PathProcessingRequest struct {
	Paths            []string `json:"paths"`
	FilenameCMSHint  string   `json:"filename_cms_hint,omitempty"`
	WordlistName     string   `json:"wordlist_name"`
	CMSName          string   `json:"cms_name,omitempty"`
	PerPathDetection bool     `json:"per_path_detection"`
}

// PathResult represents the processed result for a single path
type PathResult struct {
	Path              string    `json:"path"`
	DetectedCMS       string    `json:"detected_cms"`
	Confidence        float64   `json:"confidence"`
	Weight            float64   `json:"weight"`
	Category          string    `json:"category"`
	StructuralFeatures []float32 `json:"structural_features"`
}

// PathProcessingResponse represents the output
type PathProcessingResponse struct {
	Results []PathResult `json:"results"`
	Error   string       `json:"error,omitempty"`
}

// processPath processes a single path (CMS detection, weight calculation, feature extraction)
func processPath(path string, filenameHint string) PathResult {
	// Parallel CMS detection (can use goroutines for pattern matching)
	detectedCMS, confidence := detectCMS(path, filenameHint)
	
	// Parallel weight calculation
	weight := calculateWeight(path, detectedCMS, confidence)
	
	// Parallel structural feature generation
	features := generateStructuralFeatures(path)
	
	// Infer category
	category := inferCategory(path)
	
	return PathResult{
		Path:              path,
		DetectedCMS:       detectedCMS,
		Confidence:        confidence,
		Weight:            weight,
		Category:          category,
		StructuralFeatures: features,
	}
}

// detectCMS detects CMS from path patterns (simplified version)
func detectCMS(path string, filenameHint string) (string, float64) {
	pathLower := path
	if len(path) > 0 {
		// Simple lowercase conversion
		for i, r := range path {
			if r >= 'A' && r <= 'Z' {
				pathLower = pathLower[:i] + string(r+32) + pathLower[i+1:]
			}
		}
	}
	
	// CMS pattern matching (simplified - can be expanded)
	cmsPatterns := map[string][]string{
		"wordpress": {"wp-", "wp-content", "wp-admin", "wordpress"},
		"drupal":    {"drupal", "sites/default", "modules/"},
		"joomla":    {"joomla", "administrator", "components/"},
		"aem":       {"aem", "adobe", "cq5", "geometrixx"},
		"swagger":   {"swagger", "swagger-ui", "api-docs"},
		"spring-boot": {"spring-boot", "actuator", "springframework"},
		"tomcat":    {"tomcat", "manager", "catalina"},
		"sunappserver": {"sunappserver", "glassfish", "admin", "console"},
	}
	
	// Check filename hint first
	if filenameHint != "" {
		for cms, patterns := range cmsPatterns {
			if filenameHint == cms {
				// Boost confidence if filename matches
				return cms, 0.8
			}
		}
	}
	
	// Check path patterns
	bestCMS := ""
	bestConfidence := 0.0
	
	for cms, patterns := range cmsPatterns {
		for _, pattern := range patterns {
			if contains(pathLower, pattern) {
				confidence := 0.6
				if len(pattern) > 5 {
					confidence = 0.7
				}
				if confidence > bestConfidence {
					bestConfidence = confidence
					bestCMS = cms
				}
			}
		}
	}
	
	if bestCMS == "" {
		return "general", 0.3
	}
	
	return bestCMS, bestConfidence
}

// calculateWeight calculates weight for a path
func calculateWeight(path string, detectedCMS string, confidence float64) float64 {
	baseWeight := 0.4
	cmsBoost := confidence * 0.4 // Max +0.4
	
	// High-value pattern boost
	highValuePatterns := []string{"admin", "api", "config", "backup"}
	highValueBoost := 0.0
	for _, pattern := range highValuePatterns {
		if contains(path, pattern) {
			highValueBoost = 0.1
			break
		}
	}
	
	weight := baseWeight + cmsBoost + highValueBoost
	
	// Clamp between 0.3 and 0.9
	if weight < 0.3 {
		weight = 0.3
	}
	if weight > 0.9 {
		weight = 0.9
	}
	
	return weight
}

// generateStructuralFeatures generates structural features for a path
func generateStructuralFeatures(path string) []float32 {
	features := make([]float32, 7)
	
	// 1. Normalized length (max 200 chars)
	length := float32(len(path))
	if length > 200 {
		length = 200
	}
	features[0] = length / 200.0
	
	// 2. Number of slashes (depth)
	slashCount := float32(0)
	for _, r := range path {
		if r == '/' {
			slashCount++
		}
	}
	if slashCount > 10 {
		slashCount = 10
	}
	features[1] = slashCount / 10.0
	
	// 3. Has file extension
	hasExtension := float32(0.0)
	lastSegment := path
	if idx := lastIndex(path, '/'); idx >= 0 {
		lastSegment = path[idx+1:]
	}
	if contains(lastSegment, ".") && len(lastSegment) > 0 {
		parts := split(lastSegment, ".")
		if len(parts) > 1 {
			hasExtension = 1.0
		}
	}
	features[2] = hasExtension
	
	// 4. Has digits
	hasDigits := float32(0.0)
	for _, r := range path {
		if r >= '0' && r <= '9' {
			hasDigits = 1.0
			break
		}
	}
	features[3] = hasDigits
	
	// 5. Starts with dot (hidden file/directory)
	startsWithDot := float32(0.0)
	if len(path) > 0 && (path[0] == '.' || contains(path, "/.")) {
		startsWithDot = 1.0
	}
	features[4] = startsWithDot
	
	// 6. Contains common security-relevant patterns
	adminPattern := float32(0.0)
	if contains(path, "admin") || contains(path, "administrator") || contains(path, "manage") {
		adminPattern = 1.0
	}
	features[5] = adminPattern
	
	apiPattern := float32(0.0)
	if contains(path, "api") {
		apiPattern = 1.0
	}
	features[6] = apiPattern
	
	return features
}

// inferCategory infers category from path
func inferCategory(path string) string {
	pathLower := path
	if len(path) > 0 {
		for i, r := range path {
			if r >= 'A' && r <= 'Z' {
				pathLower = pathLower[:i] + string(r+32) + pathLower[i+1:]
			}
		}
	}
	
	if contains(pathLower, "admin") || contains(pathLower, "administrator") || contains(pathLower, "manage") || contains(pathLower, "panel") {
		return "admin"
	}
	if contains(pathLower, "api") {
		return "api"
	}
	if contains(pathLower, "config") || contains(pathLower, "conf") || contains(pathLower, "setting") || contains(pathLower, ".env") {
		return "config"
	}
	if contains(pathLower, "login") || contains(pathLower, "auth") || contains(pathLower, "signin") {
		return "authentication"
	}
	if contains(pathLower, "backup") || contains(pathLower, "bak") || contains(pathLower, "old") {
		return "backup"
	}
	if hasSuffix(pathLower, ".php") || hasSuffix(pathLower, ".jsp") || hasSuffix(pathLower, ".asp") || hasSuffix(pathLower, ".aspx") || hasSuffix(pathLower, ".py") || hasSuffix(pathLower, ".rb") {
		return "script"
	}
	return "general"
}

// Helper functions (simplified string operations)
func contains(s, substr string) bool {
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func lastIndex(s string, r rune) int {
	for i := len(s) - 1; i >= 0; i-- {
		if rune(s[i]) == r {
			return i
		}
	}
	return -1
}

func split(s, sep string) []string {
	if sep == "" {
		return []string{s}
	}
	var result []string
	start := 0
	for i := 0; i <= len(s)-len(sep); i++ {
		if s[i:i+len(sep)] == sep {
			result = append(result, s[start:i])
			start = i + len(sep)
			i += len(sep) - 1
		}
	}
	result = append(result, s[start:])
	return result
}

func hasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// processPathsParallel processes paths in parallel using worker pool
func processPathsParallel(req PathProcessingRequest) PathProcessingResponse {
	results := make([]PathResult, len(req.Paths))
	
	// Use worker pool pattern for parallel processing
	numWorkers := 32
	if len(req.Paths) < numWorkers {
		numWorkers = len(req.Paths)
	}
	
	pathChan := make(chan int, len(req.Paths))
	var wg sync.WaitGroup
	
	// Start workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range pathChan {
				results[idx] = processPath(
					req.Paths[idx],
					req.FilenameCMSHint,
				)
			}
		}()
	}
	
	// Send work
	for i := range req.Paths {
		pathChan <- i
	}
	close(pathChan)
	
	// Wait for completion
	wg.Wait()
	
	return PathProcessingResponse{Results: results}
}

func main() {
	// Read JSON request from stdin
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		response := PathProcessingResponse{
			Error: fmt.Sprintf("Error reading input: %v", err),
		}
		output, _ := json.Marshal(response)
		fmt.Println(string(output))
		os.Exit(1)
	}
	
	var req PathProcessingRequest
	if err := json.Unmarshal(input, &req); err != nil {
		response := PathProcessingResponse{
			Error: fmt.Sprintf("Error parsing JSON: %v", err),
		}
		output, _ := json.Marshal(response)
		fmt.Println(string(output))
		os.Exit(1)
	}
	
	// Process paths in parallel
	response := processPathsParallel(req)
	
	// Output JSON response
	output, err := json.Marshal(response)
	if err != nil {
		response := PathProcessingResponse{
			Error: fmt.Sprintf("Error marshaling response: %v", err),
		}
		output, _ := json.Marshal(response)
		fmt.Println(string(output))
		os.Exit(1)
	}
	
	fmt.Println(string(output))
}

