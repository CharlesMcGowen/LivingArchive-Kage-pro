package suzu

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Enumerator handles directory enumeration
type Enumerator struct {
	config ToolConfig
	tools  *ToolExecutor
}

// NewEnumerator creates a new enumerator
func NewEnumerator(config ToolConfig) *Enumerator {
	return &Enumerator{
		config: config,
		tools:  NewToolExecutor(config),
	}
}

// EnumerateTarget performs directory enumeration on target
func (e *Enumerator) EnumerateTarget(
	ctx context.Context,
	targetURL string,
) (*EnumerationResult, error) {
	// Try dirsearch first (most reliable)
	result, err := e.RunDirsearch(ctx, targetURL)
	if err != nil {
		return result, err
	}

	// If dirsearch fails, try ffuf
	if !result.Success {
		result, err = e.RunFFuf(ctx, targetURL)
		if err != nil {
			return result, err
		}
	}

	return result, nil
}

// RunDirsearch runs dirsearch tool
func (e *Enumerator) RunDirsearch(
	ctx context.Context,
	targetURL string,
) (*EnumerationResult, error) {
	output, err := e.tools.ExecuteDirsearch(ctx, targetURL)
	if err != nil {
		return &EnumerationResult{
			Success: false,
			Tool:    "dirsearch",
			Error:   err.Error(),
		}, nil
	}

	return e.ParseDirsearchOutput(output)
}

// RunFFuf runs ffuf tool
func (e *Enumerator) RunFFuf(
	ctx context.Context,
	targetURL string,
) (*EnumerationResult, error) {
	// Check if ffuf is available
	if !e.tools.CheckToolAvailability("ffuf") {
		return &EnumerationResult{
			Success: false,
			Tool:    "ffuf",
			Error:   "ffuf not available",
		}, nil
	}

	output, err := e.tools.ExecuteFFuf(ctx, targetURL)
	if err != nil {
		return &EnumerationResult{
			Success: false,
			Tool:    "ffuf",
			Error:   err.Error(),
		}, nil
	}

	return e.ParseFFufOutput(output)
}

// ParseDirsearchOutput parses dirsearch JSON/text output
func (e *Enumerator) ParseDirsearchOutput(output []byte) (*EnumerationResult, error) {
	// Try to parse as JSON first
	var jsonData map[string]interface{}
	if err := json.Unmarshal(output, &jsonData); err == nil {
		// JSON format
		results, ok := jsonData["results"].([]interface{})
		if !ok {
			return &EnumerationResult{
				Success: false,
				Tool:    "dirsearch",
				Error:   "invalid JSON format",
			}, nil
		}

		var paths []string
		for _, result := range results {
			if resultMap, ok := result.(map[string]interface{}); ok {
				if path, ok := resultMap["path"].(string); ok {
					paths = append(paths, path)
				}
			}
		}

		// Limit to 100 paths
		if len(paths) > 100 {
			paths = paths[:100]
		}

		rawOutput := string(output)
		if len(rawOutput) > 1000 {
			rawOutput = rawOutput[:1000]
		}

		return &EnumerationResult{
			Success:    true,
			Tool:       "dirsearch",
			PathsFound: len(paths),
			Paths:      paths,
			RawOutput:  rawOutput,
		}, nil
	}

	// Fallback: parse text output
	lines := strings.Split(string(output), "\n")
	var paths []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && strings.Contains(line, "Status:") {
			// Extract path from line (simplified parsing)
			parts := strings.Fields(line)
			if len(parts) > 0 {
				paths = append(paths, parts[0])
			}
		}
	}

	if len(paths) > 100 {
		paths = paths[:100]
	}

	rawOutput := string(output)
	if len(rawOutput) > 1000 {
		rawOutput = rawOutput[:1000]
	}

	return &EnumerationResult{
		Success:    true,
		Tool:       "dirsearch",
		PathsFound: len(paths),
		Paths:      paths,
		RawOutput:  rawOutput,
	}, nil
}

// ParseFFufOutput parses ffuf JSON output
func (e *Enumerator) ParseFFufOutput(output []byte) (*EnumerationResult, error) {
	var jsonData map[string]interface{}
	if err := json.Unmarshal(output, &jsonData); err != nil {
		return &EnumerationResult{
			Success: false,
			Tool:    "ffuf",
			Error:   fmt.Sprintf("JSON parse error: %v", err),
		}, nil
	}

	results, ok := jsonData["results"].([]interface{})
	if !ok {
		return &EnumerationResult{
			Success: false,
			Tool:    "ffuf",
			Error:   "invalid JSON format",
		}, nil
	}

	var paths []string
	for _, result := range results {
		if resultMap, ok := result.(map[string]interface{}); ok {
			if url, ok := resultMap["url"].(string); ok {
				paths = append(paths, url)
			}
		}
	}

	// Limit to 100 paths
	if len(paths) > 100 {
		paths = paths[:100]
	}

	rawOutput := string(output)
	if len(rawOutput) > 1000 {
		rawOutput = rawOutput[:1000]
	}

	return &EnumerationResult{
		Success:    true,
		Tool:       "ffuf",
		PathsFound: len(paths),
		Paths:      paths,
		RawOutput:  rawOutput,
	}, nil
}
