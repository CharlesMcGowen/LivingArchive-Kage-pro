package suzu

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
)

// ParseConfig holds configuration for wordlist parsing
type ParseConfig struct {
	BatchSize      int    `json:"batch_size"`      // Number of paths per batch
	MaxPaths       int    `json:"max_paths"`       // Maximum paths to parse (0 = unlimited)
	SkipComments   bool   `json:"skip_comments"`  // Skip lines starting with #
	NormalizePaths bool   `json:"normalize_paths"` // Ensure paths start with /
	Filename       string `json:"filename"`        // Original filename for CMS detection
}

// ParseResult contains the parsed paths and statistics
type ParseResult struct {
	Paths      []string          `json:"paths"`
	Batches    [][]string        `json:"batches"`
	Stats      ParseStats        `json:"stats"`
	Error      string            `json:"error,omitempty"`
}

// ParseStats contains parsing statistics
type ParseStats struct {
	TotalLines    int `json:"total_lines"`
	ValidPaths    int `json:"valid_paths"`
	SkippedLines  int `json:"skipped_lines"`
	CommentLines  int `json:"comment_lines"`
	EmptyLines    int `json:"empty_lines"`
	BatchesCount  int `json:"batches_count"`
}

// ParseWordlistFile parses a wordlist file efficiently using buffered I/O
// Returns paths in batches for efficient processing
func ParseWordlistFile(filePath string, config ParseConfig) (*ParseResult, error) {
	if config.BatchSize <= 0 {
		config.BatchSize = 1000 // Default batch size
	}
	if !config.SkipComments {
		config.SkipComments = true // Default to skipping comments
	}
	if !config.NormalizePaths {
		config.NormalizePaths = true // Default to normalizing paths
	}

	file, err := os.Open(filePath)
	if err != nil {
		return &ParseResult{
			Error: fmt.Sprintf("Failed to open file: %v", err),
		}, err
	}
	defer file.Close()

	stats := ParseStats{}
	allPaths := make([]string, 0)
	currentBatch := make([]string, 0, config.BatchSize)
	batches := make([][]string, 0)

	scanner := bufio.NewScanner(file)
	// Use larger buffer for better performance on large files
	buf := make([]byte, 0, 64*1024) // 64KB buffer
	scanner.Buffer(buf, 1024*1024)  // Max 1MB line length

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		stats.TotalLines++

		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines
		if line == "" {
			stats.EmptyLines++
			continue
		}

		// Skip comment lines
		if config.SkipComments && strings.HasPrefix(line, "#") {
			stats.CommentLines++
			continue
		}

		// Normalize path (ensure it starts with /)
		if config.NormalizePaths && !strings.HasPrefix(line, "/") {
			line = "/" + line
		}

		// Add to current batch
		currentBatch = append(currentBatch, line)
		allPaths = append(allPaths, line)
		stats.ValidPaths++

		// If batch is full, save it and start new batch
		if len(currentBatch) >= config.BatchSize {
			batches = append(batches, currentBatch)
			stats.BatchesCount++
			currentBatch = make([]string, 0, config.BatchSize)

			// Check max paths limit
			if config.MaxPaths > 0 && stats.ValidPaths >= config.MaxPaths {
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return &ParseResult{
			Error: fmt.Sprintf("Error reading file: %v", err),
		}, err
	}

	// Add remaining paths as final batch
	if len(currentBatch) > 0 {
		batches = append(batches, currentBatch)
		stats.BatchesCount++
	}

	stats.SkippedLines = stats.CommentLines + stats.EmptyLines

	return &ParseResult{
		Paths:   allPaths,
		Batches: batches,
		Stats:   stats,
	}, nil
}

// ParseWordlistStream parses a wordlist from an io.Reader (for Django file uploads)
// This allows streaming without writing to disk first
func ParseWordlistStream(reader io.Reader, config ParseConfig) (*ParseResult, error) {
	if config.BatchSize <= 0 {
		config.BatchSize = 1000
	}
	if !config.SkipComments {
		config.SkipComments = true
	}
	if !config.NormalizePaths {
		config.NormalizePaths = true
	}

	stats := ParseStats{}
	allPaths := make([]string, 0)
	currentBatch := make([]string, 0, config.BatchSize)
	batches := make([][]string, 0)

	scanner := bufio.NewScanner(reader)
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		stats.TotalLines++

		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			stats.EmptyLines++
			continue
		}

		if config.SkipComments && strings.HasPrefix(line, "#") {
			stats.CommentLines++
			continue
		}

		if config.NormalizePaths && !strings.HasPrefix(line, "/") {
			line = "/" + line
		}

		currentBatch = append(currentBatch, line)
		allPaths = append(allPaths, line)
		stats.ValidPaths++

		if len(currentBatch) >= config.BatchSize {
			batches = append(batches, currentBatch)
			stats.BatchesCount++
			currentBatch = make([]string, 0, config.BatchSize)

			if config.MaxPaths > 0 && stats.ValidPaths >= config.MaxPaths {
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return &ParseResult{
			Error: fmt.Sprintf("Error reading stream: %v", err),
		}, err
	}

	if len(currentBatch) > 0 {
		batches = append(batches, currentBatch)
		stats.BatchesCount++
	}

	stats.SkippedLines = stats.CommentLines + stats.EmptyLines

	return &ParseResult{
		Paths:   allPaths,
		Batches: batches,
		Stats:   stats,
	}, nil
}

// ParseWordlistJSON is a CLI-friendly function that reads config JSON + file content from stdin
// Format: First line is JSON config, rest is file content
// Used by Python subprocess calls
func ParseWordlistJSON() {
	// Read first line (JSON config)
	reader := bufio.NewReader(os.Stdin)
	configLine, err := reader.ReadString('\n')
	if err != nil && err != io.EOF {
		result := &ParseResult{
			Error: fmt.Sprintf("Failed to read config: %v", err),
		}
		json.NewEncoder(os.Stdout).Encode(result)
		os.Exit(1)
	}

	var config ParseConfig
	if err := json.Unmarshal([]byte(strings.TrimSpace(configLine)), &config); err != nil {
		result := &ParseResult{
			Error: fmt.Sprintf("Failed to decode config: %v", err),
		}
		json.NewEncoder(os.Stdout).Encode(result)
		os.Exit(1)
	}

	// Parse remaining stdin as file content
	result, err := ParseWordlistStream(reader, config)
	if err != nil {
		if result == nil {
			result = &ParseResult{}
		}
		result.Error = err.Error()
	}

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(result); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to encode result: %v\n", err)
		os.Exit(1)
	}
}
