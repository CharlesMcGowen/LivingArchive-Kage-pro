package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client handles Django API communication
type Client struct {
	baseURL    string
	httpClient *http.Client
	timeout    time.Duration
}

// NewClient creates a new API client
func NewClient(baseURL string, timeout time.Duration) *Client {
	return &Client{
		baseURL: baseURL,
		httpClient: &http.Client{
			Timeout: timeout,
		},
		timeout: timeout,
	}
}

// GetEggRecords fetches eggrecords for a personality
func (c *Client) GetEggRecords(
	ctx context.Context,
	personality string,
	limit int,
) (*EggRecordResponse, error) {
	// Build URL
	endpoint := fmt.Sprintf("%s/reconnaissance/api/daemon/%s/eggrecords/", c.baseURL, personality)
	reqURL, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %w", err)
	}

	// Add query parameters
	q := reqURL.Query()
	q.Set("limit", fmt.Sprintf("%d", limit))
	reqURL.RawQuery = q.Encode()

	// Make request with retry
	resp, err := c.getWithRetry(ctx, reqURL.String(), 5)
	if err != nil {
		return nil, fmt.Errorf("failed to get eggrecords: %w", err)
	}
	defer resp.Body.Close()

	// Parse response
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result EggRecordResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// SubmitSpiderResult submits spider results
func (c *Client) SubmitSpiderResult(
	ctx context.Context,
	req *SubmitSpiderRequest,
) (*APIResponse, error) {
	endpoint := fmt.Sprintf("%s/reconnaissance/api/daemon/kumo/spider/", c.baseURL)
	return c.postJSON(ctx, endpoint, req)
}

// SubmitEnumerationResult submits enumeration results
func (c *Client) SubmitEnumerationResult(
	ctx context.Context,
	req *SubmitEnumRequest,
) (*APIResponse, error) {
	endpoint := fmt.Sprintf("%s/reconnaissance/api/daemon/enumeration/", c.baseURL)
	return c.postJSON(ctx, endpoint, req)
}

// HealthCheck performs health check
func (c *Client) HealthCheck(
	ctx context.Context,
	personality string,
) (*APIResponse, error) {
	endpoint := fmt.Sprintf("%s/reconnaissance/api/daemon/%s/health/", c.baseURL, personality)
	resp, err := c.getWithRetry(ctx, endpoint, 3)
	if err != nil {
		return nil, fmt.Errorf("health check failed: %w", err)
	}
	defer resp.Body.Close()

	var result APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode health check response: %w", err)
	}

	return &result, nil
}

// postJSON posts JSON data to endpoint
func (c *Client) postJSON(ctx context.Context, endpoint string, data interface{}) (*APIResponse, error) {
	jsonData, err := json.Marshal(data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON: %w", err)
	}

	resp, err := c.postWithRetry(ctx, endpoint, jsonData, 5)
	if err != nil {
		return nil, fmt.Errorf("failed to post: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(body))
	}

	var result APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &result, nil
}

// getWithRetry performs GET request with exponential backoff
func (c *Client) getWithRetry(
	ctx context.Context,
	endpoint string,
	maxRetries int,
) (*http.Response, error) {
	baseWait := 2 * time.Second
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "GET", endpoint, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := c.httpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		if resp != nil {
			resp.Body.Close()
		}

		lastErr = err
		if err == nil {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		}

		if attempt < maxRetries-1 {
			waitTime := baseWait * time.Duration(1<<uint(attempt)) // Exponential backoff
			if waitTime > 60*time.Second {
				waitTime = 60 * time.Second
			}
			time.Sleep(waitTime)
		}
	}

	return nil, fmt.Errorf("max retries reached: %w", lastErr)
}

// postWithRetry performs POST request with exponential backoff
func (c *Client) postWithRetry(
	ctx context.Context,
	endpoint string,
	body []byte,
	maxRetries int,
) (*http.Response, error) {
	baseWait := 2 * time.Second
	var lastErr error

	for attempt := 0; attempt < maxRetries; attempt++ {
		req, err := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewBuffer(body))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}

		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "XMLHttpRequest") // Help Django identify as AJAX
		// Note: @csrf_exempt should handle CSRF, but if it doesn't work, we may need to
		// add a CSRF token or use a different approach

		resp, err := c.httpClient.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			return resp, nil
		}

		if resp != nil {
			resp.Body.Close()
		}

		lastErr = err
		if err == nil {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
		}

		if attempt < maxRetries-1 {
			waitTime := baseWait * time.Duration(1<<uint(attempt)) // Exponential backoff
			if waitTime > 60*time.Second {
				waitTime = 60 * time.Second
			}
			time.Sleep(waitTime)
		}
	}

	return nil, fmt.Errorf("max retries reached: %w", lastErr)
}
