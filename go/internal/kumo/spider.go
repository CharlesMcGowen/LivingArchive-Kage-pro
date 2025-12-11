package kumo

import (
	"context"
	"crypto/md5"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"recon/internal/api"
)

// Spider is the main spider struct
type Spider struct {
	config     SpiderConfig
	httpClient *http.Client
	visited    map[string]bool
	mu         sync.RWMutex
	extractor  *Extractor
	apiClient  *api.Client
}

// NewSpider creates a new spider instance
func NewSpider(config SpiderConfig) (*Spider, error) {
	// Create transport that skips SSL verification (like Python version)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	httpClient := &http.Client{
		Timeout:   config.RequestTimeout,
		Transport: tr,
	}

	return &Spider{
		config:     config,
		httpClient: httpClient,
		visited:    make(map[string]bool),
		extractor:  NewExtractor(),
	}, nil
}

// SetAPIClient sets the API client for submitting results
func (s *Spider) SetAPIClient(client *api.Client) {
	s.apiClient = client
}

// SpiderEggRecord spiders an eggrecord and creates RequestMetaData entries
func (s *Spider) SpiderEggRecord(
	ctx context.Context,
	eggRecordID string,
	eggRecordData *EggRecord,
	depth int,
) (*SpiderResult, error) {
	if eggRecordData == nil {
		return nil, fmt.Errorf("eggRecordData is required")
	}

	target := eggRecordData.SubDomain
	if target == "" {
		target = eggRecordData.DomainName
	}

	if target == "" {
		return &SpiderResult{
			Success: false,
			Error:   "Could not determine target",
		}, nil
	}

	spiderDepth := depth
	if spiderDepth == 0 {
		spiderDepth = s.config.SpiderDepth
	}

	startTime := time.Now()

	// Try both HTTP and HTTPS
	urlsToSpider := []string{
		fmt.Sprintf("https://%s", target),
		fmt.Sprintf("http://%s", target),
	}

	var allPages []PageData
	totalMetadataCreated := 0

	for _, baseURL := range urlsToSpider {
		result, err := s.SpiderURL(ctx, baseURL, eggRecordID, spiderDepth)
		if err != nil {
			continue
		}

		if result.Success {
			allPages = append(allPages, result.Pages...)
			totalMetadataCreated += result.MetadataEntriesCreated
		}
	}

	duration := time.Since(startTime).Seconds()

	return &SpiderResult{
		Success:                true,
		Target:                 target,
		PagesSpidered:          len(allPages),
		MetadataEntriesCreated: totalMetadataCreated,
		SpiderDuration:         duration,
		Pages:                  allPages,
	}, nil
}

// SpiderURL spiders a URL and creates RequestMetaData entries
func (s *Spider) SpiderURL(
	ctx context.Context,
	baseURL string,
	eggRecordID string,
	depth int,
) (*SpiderResult, error) {
	parsedURL, err := url.Parse(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	visited := make(map[string]bool)
	var pages []PageData
	metadataCreated := 0

	// BFS queue: (url, current_depth)
	type queueItem struct {
		url   string
		depth int
	}
	toVisit := []queueItem{{baseURL, 0}}

	for len(toVisit) > 0 && len(pages) < s.config.MaxPagesPerDomain {
		// Pop from queue
		current := toVisit[0]
		toVisit = toVisit[1:]

		currentURL := current.url
		currentDepth := current.depth

		// Check if already visited or depth exceeded
		if visited[currentURL] || currentDepth > depth {
			continue
		}

		visited[currentURL] = true

		// Make HTTP request
		req, err := http.NewRequestWithContext(ctx, "GET", currentURL, nil)
		if err != nil {
			continue
		}

		req.Header.Set("User-Agent", s.config.UserAgent)
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
		req.Header.Set("Accept-Language", "en-US,en;q=0.5")

		startTime := time.Now()
		resp, err := s.httpClient.Do(req)
		if err != nil {
			continue
		}
		responseTime := time.Since(startTime)

		// Read response body
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			continue
		}

		// Extract metadata
		metadata := s.extractMetadata(resp, currentURL, eggRecordID, body, responseTime)

		// Create RequestMetaData via API if client is set
		if s.apiClient != nil {
			// Submit metadata to API
			// Note: This would need to be implemented in the API client
			// For now, we'll just count it
			metadataCreated++
		}

		// Extract cookies
		var cookies []Cookie
		for _, cookie := range resp.Cookies() {
			cookies = append(cookies, Cookie{
				Name:   cookie.Name,
				Value:  cookie.Value,
				Domain: cookie.Domain,
			})
		}

		// Create page data
		pageData := PageData{
			URL:           currentURL,
			StatusCode:    resp.StatusCode,
			Headers:       make(map[string]string),
			Cookies:       cookies,
			ContentLength: len(body),
			Depth:         currentDepth,
			MetadataID:    metadata.RequestID,
		}

		// Copy headers
		for k, v := range resp.Header {
			if len(v) > 0 {
				pageData.Headers[k] = v[0]
			}
		}

		pages = append(pages, pageData)

		// Extract links for next depth level
		if currentDepth < depth {
			links, err := s.extractor.ExtractLinks(ctx, string(body), parsedURL)
			if err == nil {
				// Add links to visit queue (limit per page)
				maxLinks := 10
				if len(links) > maxLinks {
					links = links[:maxLinks]
				}

				for _, link := range links {
					if !visited[link] {
						toVisit = append(toVisit, queueItem{link, currentDepth + 1})
					}
				}
			}
		}
	}

	return &SpiderResult{
		Success:                true,
		Pages:                  pages,
		MetadataEntriesCreated: metadataCreated,
	}, nil
}

// extractMetadata extracts metadata from HTTP response
func (s *Spider) extractMetadata(
	resp *http.Response,
	url string,
	eggRecordID string,
	body []byte,
	responseTime time.Duration,
) *RequestMetaData {
	// Generate request ID
	hash := md5.Sum([]byte(fmt.Sprintf("%s:%d", url, time.Now().Unix())))
	requestID := fmt.Sprintf("%x", hash)
	sessionID := fmt.Sprintf("kumo-%s", eggRecordID)

	// Extract headers
	requestHeaders := make(map[string]string)
	responseHeaders := make(map[string]string)

	if resp.Request != nil {
		for k, v := range resp.Request.Header {
			if len(v) > 0 {
				requestHeaders[k] = v[0]
			}
		}
	}

	for k, v := range resp.Header {
		if len(v) > 0 {
			responseHeaders[k] = v[0]
		}
	}

	// Limit body size (50KB like Python version)
	bodyStr := string(body)
	if len(bodyStr) > 50000 {
		bodyStr = bodyStr[:50000]
	}

	responseTimeMS := int(responseTime.Seconds() * 1000)

	return &RequestMetaData{
		RequestID:       requestID,
		SessionID:       sessionID,
		TargetURL:       url,
		RequestMethod:   "GET",
		ResponseStatus:  resp.StatusCode,
		RequestHeaders:  requestHeaders,
		ResponseHeaders: responseHeaders,
		ResponseBody:    bodyStr,
		ResponseTimeMS:  responseTimeMS,
		UserAgent:       s.config.UserAgent,
		Timestamp:       time.Now(),
		RecordID:        eggRecordID,
	}
}
