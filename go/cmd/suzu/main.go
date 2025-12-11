package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"recon/internal/api"
	"recon/internal/common"
	"recon/internal/suzu"
)

func main() {
	// Parse flags
	apiBase := flag.String("api-base", "http://127.0.0.1:9000", "Django API base URL")
	interval := flag.Duration("interval", 60*time.Second, "Enumeration interval")
	maxEnums := flag.Int("max-enums", 2, "Max enumerations per cycle")
	flag.Parse()

	// Create daemon
	daemon := common.NewDaemon("suzu", "/tmp/suzu_daemon.pid")

	// Create API client
	apiClient := api.NewClient(*apiBase, 30*time.Second)

	// Create enumerator
	toolConfig := suzu.ToolConfig{
		DirsearchPath: "/opt/dirsearch/dirsearch.py",
		FFufPath:      "/usr/local/bin/ffuf",
		WordlistPath:  "/opt/dirsearch/db/dicc.txt",
		Timeout:       10 * time.Second,
		MaxTime:       5 * time.Minute,
		Threads:       20,
	}
	enumerator := suzu.NewEnumerator(toolConfig)

	// Start daemon
	if err := daemon.Start(); err != nil {
		log.Fatalf("Failed to start daemon: %v", err)
	}
	defer daemon.Stop()

	// Setup signal handlers
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGUSR1, syscall.SIGUSR2)

	// Main loop
	cycleCount := 0
	for daemon.IsRunning() {
		// Handle signals
		select {
		case sig := <-sigChan:
			switch sig {
			case syscall.SIGINT, syscall.SIGTERM:
				daemon.Stop()
				return
			case syscall.SIGUSR1:
				daemon.Pause()
			case syscall.SIGUSR2:
				daemon.Resume()
			}
		default:
		}

		// Check pause state
		for daemon.IsPaused() && daemon.IsRunning() {
			time.Sleep(1 * time.Second)
		}

		if !daemon.IsRunning() {
			break
		}

		cycleCount++
		log.Printf("🔄 Suzu enumeration cycle #%d", cycleCount)

		// Get eggrecords
		ctx := context.Background()
		eggRecords, err := apiClient.GetEggRecords(ctx, "suzu", *maxEnums)
		if err != nil {
			log.Printf("Error getting eggrecords: %v", err)
			time.Sleep(*interval)
			continue
		}

		if len(eggRecords.EggRecords) == 0 {
			log.Println("No eggrecords to enumerate, waiting...")
			time.Sleep(*interval)
			continue
		}

		log.Printf("📋 Found %d eggrecords to enumerate", len(eggRecords.EggRecords))

		// Enumerate each eggrecord
		enumerated := 0
		for _, eggRecord := range eggRecords.EggRecords {
			if !daemon.IsRunning() || daemon.IsPaused() {
				break
			}

			daemon.SetCurrentTask(eggRecord.ID)
			targetURL := buildTargetURL(eggRecord)

			log.Printf("🔔 Enumerating directories for %s (%s)", targetURL, eggRecord.ID)

			// Perform enumeration
			result, err := enumerator.EnumerateTarget(ctx, targetURL)
			if err != nil {
				log.Printf("❌ Enumeration failed: %v", err)
				daemon.ClearCurrentTask()
				continue
			}

			if result.Success {
				// Convert suzu.EnumerationResult to api.EnumerationResult
				apiResult := api.EnumerationResult{
					Success:    result.Success,
					Tool:       result.Tool,
					PathsFound: result.PathsFound,
					Paths:      result.Paths,
					RawOutput:  result.RawOutput,
					Error:      result.Error,
				}

				// Submit result
				req := &api.SubmitEnumRequest{
					EggRecordID: eggRecord.ID,
					Target:      targetURL,
					Result:      apiResult,
				}
				if _, err := apiClient.SubmitEnumerationResult(ctx, req); err != nil {
					log.Printf("Error submitting result: %v", err)
				} else {
					enumerated++
				}
			}

			daemon.ClearCurrentTask()
			time.Sleep(1 * time.Second)
		}

		if enumerated > 0 {
			log.Printf("✅ Completed %d enumerations this cycle", enumerated)
		}

		time.Sleep(*interval)
	}
}

func buildTargetURL(eggRecord api.EggRecord) string {
	target := eggRecord.SubDomain
	if target == "" {
		target = eggRecord.DomainName
	}
	if !strings.HasPrefix(target, "http") {
		return "http://" + target
	}
	return target
}

