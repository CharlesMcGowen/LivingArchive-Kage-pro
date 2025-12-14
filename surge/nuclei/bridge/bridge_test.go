package main

/*
#cgo LDFLAGS: -lpthread
#include <stdlib.h>
#include <string.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
	"unsafe"
)

// Test helper functions
func TestCreateCString(t *testing.T) {
	testStr := "test string"
	cstr := createCString(testStr)
	defer C.free(unsafe.Pointer(cstr))

	// Verify it's not nil
	if cstr == nil {
		t.Error("createCString returned nil")
	}

	// Verify content
	goStr := C.GoString(cstr)
	if goStr != testStr {
		t.Errorf("Expected %s, got %s", testStr, goStr)
	}
}

func TestJsonError(t *testing.T) {
	err := fmt.Errorf("test error")
	result := jsonError(err)
	defer C.free(unsafe.Pointer(result))

	// Parse JSON
	goStr := C.GoString(result)
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(goStr), &data); err != nil {
		t.Errorf("Failed to parse JSON: %v", err)
	}

	// Verify structure
	if data["success"] != false {
		t.Error("Expected success=false")
	}
	if data["error"] != "test error" {
		t.Errorf("Expected error='test error', got %v", data["error"])
	}
}

func TestJsonSuccess(t *testing.T) {
	testData := map[string]interface{}{
		"message": "test",
		"value":   42,
	}
	result := jsonSuccess(testData)
	defer C.free(unsafe.Pointer(result))

	// Parse JSON
	goStr := C.GoString(result)
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(goStr), &data); err != nil {
		t.Errorf("Failed to parse JSON: %v", err)
	}

	// Verify structure
	if data["success"] != true {
		t.Error("Expected success=true")
	}
	if data["message"] != "test" {
		t.Errorf("Expected message='test', got %v", data["message"])
	}
}

func TestValidateURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"valid http", "http://example.com", false},
		{"valid https", "https://example.com", false},
		{"valid with path", "https://example.com/path", false},
		{"empty", "", true},
		{"no scheme", "example.com", true},
		{"no host", "http://", true},
		{"invalid format", "not-a-url", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateURL() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Test bridge initialization (requires CGO, may need special build tags)
func TestInitializeBridge(t *testing.T) {
	// Reset global state
	bridgeMutex.Lock()
	bridgeInstance = nil
	bridgeMutex.Unlock()

	// Test initialization
	result := InitializeBridge()
	defer C.free(unsafe.Pointer(result))

	goStr := C.GoString(result)
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(goStr), &data); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if data["success"] != true {
		t.Errorf("Expected success=true, got %v", data["success"])
	}

	// Test double initialization
	result2 := InitializeBridge()
	defer C.free(unsafe.Pointer(result2))

	goStr2 := C.GoString(result2)
	var data2 map[string]interface{}
	json.Unmarshal([]byte(goStr2), &data2)

	if data2["success"] != false {
		t.Error("Expected second initialization to fail")
	}

	// Cleanup
	CleanupBridge()
}

// Test event channel handling
func TestEventChannel(t *testing.T) {
	bridge := &SurgeMemoryBridge{
		eventChannel: make(chan NucleiEvent, 10),
		scanState:    &ScanState{},
	}
	ctx, cancel := context.WithCancel(context.Background())
	bridge.ctx = ctx
	bridge.cancel = cancel

	// Test event processing
	event := NucleiEvent{
		Timestamp:  time.Now().Format(time.RFC3339),
		EventType:  "VULNERABILITY",
		TemplateID: "test-template",
		Severity:   "high",
		Target:     "http://test.com",
	}

	// Send event
	select {
	case bridge.eventChannel <- event:
	case <-time.After(time.Second):
		t.Error("Failed to send event to channel")
	}

	// Process event
	bridge.processEvent(event)

	// Verify state updated
	if len(bridge.scanState.VulnsFound) != 1 {
		t.Errorf("Expected 1 vulnerability, got %d", len(bridge.scanState.VulnsFound))
	}

	cancel()
}

// Test thread safety
func TestThreadSafety(t *testing.T) {
	bridge := &SurgeMemoryBridge{
		scanState: &ScanState{},
		mu:        sync.RWMutex{},
	}

	// Concurrent access test
	done := make(chan bool)

	// Writer goroutine
	go func() {
		for i := 0; i < 100; i++ {
			bridge.mu.Lock()
			bridge.scanState.TotalRequests++
			bridge.mu.Unlock()
		}
		done <- true
	}()

	// Reader goroutine
	go func() {
		for i := 0; i < 100; i++ {
			bridge.mu.RLock()
			_ = bridge.scanState.TotalRequests
			bridge.mu.RUnlock()
		}
		done <- true
	}()

	// Wait for both
	<-done
	<-done

	// Verify final state
	if bridge.scanState.TotalRequests != 100 {
		t.Errorf("Expected 100 requests, got %d", bridge.scanState.TotalRequests)
	}
}

// Benchmark JSON operations
func BenchmarkJsonMarshal(b *testing.B) {
	data := map[string]interface{}{
		"success": true,
		"message": "test",
		"target":  "http://example.com",
	}

	for i := 0; i < b.N; i++ {
		json.Marshal(data)
	}
}

// Benchmark C string creation
func BenchmarkCreateCString(b *testing.B) {
	testStr := "test string for benchmark"

	for i := 0; i < b.N; i++ {
		cstr := createCString(testStr)
		C.free(unsafe.Pointer(cstr))
	}
}
