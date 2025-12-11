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
	"recon/internal/kumo"
)

func main() {
	// Parse flags
	apiBase := flag.String("api-base", "http://127.0.0.1:9000", "Django API base URL")
	interval := flag.Duration("interval", 45*time.Second, "Spider interval")
	maxSpiders := flag.Int("max-spiders", 3, "Max spiders per cycle")
	flag.Parse()

	// Create daemon
	daemon := common.NewDaemon("kumo", "/tmp/kumo_daemon.pid")

	// Create API client
	apiClient := api.NewClient(*apiBase, 30*time.Second)

	// Create spider
	spiderConfig := kumo.SpiderConfig{
		ParallelEnabled:   true,
		RequestTimeout:    10 * time.Second,
		MaxWorkers:        32,
		MaxPagesPerDomain: 50,
		SpiderDepth:       2,
		UserAgent:         "Kumo-Spider/2.0 (EGO Security Scanner)",
	}
	spider, err := kumo.NewSpider(spiderConfig)
	if err != nil {
		log.Fatalf("Failed to create spider: %v", err)
	}
	spider.SetAPIClient(apiClient)

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
		log.Printf("🔄 Kumo spider cycle #%d", cycleCount)

		// Get eggrecords
		ctx := context.Background()
		eggRecords, err := apiClient.GetEggRecords(ctx, "kumo", *maxSpiders)
		if err != nil {
			log.Printf("Error getting eggrecords: %v", err)
			time.Sleep(*interval)
			continue
		}

		if len(eggRecords.EggRecords) == 0 {
			log.Println("No eggrecords to spider, waiting...")
			time.Sleep(*interval)
			continue
		}

		log.Printf("📋 Found %d eggrecords to spider", len(eggRecords.EggRecords))

		// Spider each eggrecord
		spidered := 0
		for _, eggRecord := range eggRecords.EggRecords {
			if !daemon.IsRunning() || daemon.IsPaused() {
				break
			}

			daemon.SetCurrentTask(eggRecord.ID)
			targetURL := buildTargetURL(eggRecord)

			log.Printf("🕷️  Spidering %s (%s)", targetURL, eggRecord.ID)

			// Convert api.EggRecord to kumo.EggRecord
			kumoEggRecord := kumo.EggRecord{
				ID:         eggRecord.ID,
				SubDomain:  eggRecord.SubDomain,
				DomainName: eggRecord.DomainName,
				Alive:      eggRecord.Alive,
				UpdatedAt:  eggRecord.UpdatedAt,
			}

			// Perform spidering
			result, err := spider.SpiderEggRecord(ctx, eggRecord.ID, &kumoEggRecord, 2)
			if err != nil {
				log.Printf("❌ Spider failed: %v", err)
				daemon.ClearCurrentTask()
				continue
			}

			if result.Success {
				// Convert pages to request_metadata format expected by Django API
				requestMetadata := make([]map[string]interface{}, 0)
				for _, page := range result.Pages {
					metadata := map[string]interface{}{
						"target_url":       page.URL,
						"request_method":   "GET",
						"response_status":  page.StatusCode,
						"response_time_ms": 0, // Will be calculated if available
						"user_agent":       "Kumo-Spider/2.0 (EGO Security Scanner)",
					}
					requestMetadata = append(requestMetadata, metadata)
				}

				// Convert result to map for JSON (Django expects request_metadata array)
				resultMap := map[string]interface{}{
					"success":          result.Success,
					"target":           result.Target,
					"pages_spidered":   result.PagesSpidered,
					"spider_duration":  result.SpiderDuration,
					"request_metadata": requestMetadata,
				}

				// Submit result
				req := &api.SubmitSpiderRequest{
					EggRecordID: eggRecord.ID,
					Target:      targetURL,
					Result:      resultMap,
				}
				if _, err := apiClient.SubmitSpiderResult(ctx, req); err != nil {
					log.Printf("Error submitting result: %v", err)
				} else {
					spidered++
				}
			}

			daemon.ClearCurrentTask()
			time.Sleep(100 * time.Millisecond)
		}

		if spidered > 0 {
			log.Printf("✅ Completed %d spiders this cycle", spidered)
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

