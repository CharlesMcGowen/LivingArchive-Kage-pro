package suzu

import (
	"context"
	"fmt"
	"os/exec"
	"time"
)

// ToolExecutor executes external enumeration tools
type ToolExecutor struct {
	config ToolConfig
}

// NewToolExecutor creates a new tool executor
func NewToolExecutor(config ToolConfig) *ToolExecutor {
	return &ToolExecutor{
		config: config,
	}
}

// ExecuteDirsearch executes dirsearch command
func (te *ToolExecutor) ExecuteDirsearch(
	ctx context.Context,
	targetURL string,
) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "python3", te.config.DirsearchPath,
		"-u", targetURL,
		"-e", "php,html,js,txt,json,xml",
		"--random-agent",
		"--timeout", "10",
		"--max-time", fmt.Sprintf("%.0f", te.config.MaxTime.Seconds()),
		"--format", "json",
		"--quiet",
	)

	// Set timeout
	ctx, cancel := context.WithTimeout(ctx, te.config.MaxTime+20*time.Second)
	defer cancel()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("dirsearch failed: %w", err)
	}

	return output, nil
}

// ExecuteFFuf executes ffuf command
func (te *ToolExecutor) ExecuteFFuf(
	ctx context.Context,
	targetURL string,
) ([]byte, error) {
	cmd := exec.CommandContext(ctx, te.config.FFufPath,
		"-u", fmt.Sprintf("%s/FUZZ", targetURL),
		"-w", te.config.WordlistPath,
		"-t", fmt.Sprintf("%d", te.config.Threads),
		"-timeout", fmt.Sprintf("%.0f", te.config.Timeout.Seconds()),
		"-mc", "200,204,301,302,307,401,403",
		"-o", "-",
		"-of", "json",
	)

	// Set timeout
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()

	output, err := cmd.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("ffuf failed: %w", err)
	}

	return output, nil
}

// CheckToolAvailability checks if a tool is available
func (te *ToolExecutor) CheckToolAvailability(toolName string) bool {
	var cmd *exec.Cmd

	switch toolName {
	case "dirsearch":
		cmd = exec.Command("python3", te.config.DirsearchPath, "--version")
	case "ffuf":
		cmd = exec.Command(te.config.FFufPath, "-V")
	default:
		return false
	}

	err := cmd.Run()
	return err == nil
}

