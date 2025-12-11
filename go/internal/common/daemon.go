package common

import (
	"context"
	"fmt"
	"os"
	"sync"
)

// Daemon manages daemon lifecycle
type Daemon struct {
	name        string
	pidFile     string
	running     bool
	paused      bool
	currentTask string
	mu          sync.RWMutex
	ctx         context.Context
	cancel      context.CancelFunc
}

// NewDaemon creates a new daemon instance
func NewDaemon(name, pidFile string) *Daemon {
	ctx, cancel := context.WithCancel(context.Background())
	return &Daemon{
		name:    name,
		pidFile: pidFile,
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Start starts the daemon
func (d *Daemon) Start() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return fmt.Errorf("daemon already running")
	}

	d.running = true
	d.setupSignalHandlers()
	return d.writePIDFile()
}

// Stop stops the daemon
func (d *Daemon) Stop() error {
	d.mu.Lock()
	defer d.mu.Unlock()

	d.running = false
	d.cancel()
	return d.removePIDFile()
}

// Pause pauses the daemon
func (d *Daemon) Pause() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paused = true
}

// Resume resumes the daemon
func (d *Daemon) Resume() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.paused = false
}

// IsRunning returns if daemon is running
func (d *Daemon) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
}

// IsPaused returns if daemon is paused
func (d *Daemon) IsPaused() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.paused
}

// SetCurrentTask sets the current task ID
func (d *Daemon) SetCurrentTask(taskID string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.currentTask = taskID
}

// ClearCurrentTask clears the current task ID
func (d *Daemon) ClearCurrentTask() {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.currentTask = ""
}

// GetCurrentTask returns the current task ID
func (d *Daemon) GetCurrentTask() string {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.currentTask
}

// writePIDFile writes PID to file
func (d *Daemon) writePIDFile() error {
	pid := os.Getpid()
	return os.WriteFile(d.pidFile, []byte(fmt.Sprintf("%d\n", pid)), 0644)
}

// removePIDFile removes PID file
func (d *Daemon) removePIDFile() error {
	if _, err := os.Stat(d.pidFile); os.IsNotExist(err) {
		return nil
	}
	return os.Remove(d.pidFile)
}

// setupSignalHandlers sets up signal handlers
func (d *Daemon) setupSignalHandlers() {
	// Signal handling is done in main() for better control
	// This is a placeholder for future signal handling logic
}

