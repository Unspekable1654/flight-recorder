package export

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

// httpClient builds a client with sane forensic-tool defaults.
//
// The recorder runs on every node of a cluster. A misconfigured export target
// that hangs would otherwise pin a goroutine per capture on every node
// simultaneously, so every request is bounded and connections are reused.
func httpClient(timeout time.Duration, insecureSkipVerify bool) *http.Client {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			MaxIdleConns:        8,
			MaxIdleConnsPerHost: 2,
			IdleConnTimeout:     60 * time.Second,
			TLSHandshakeTimeout: 10 * time.Second,
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
				//nolint:gosec // Operator-selected: some enterprise SIEMs use
				// internal CAs that the node does not trust. Off by default and
				// surfaced as an explicit --*-insecure flag.
				InsecureSkipVerify: insecureSkipVerify,
			},
		},
	}
}

// retryPolicy describes the backoff used by every HTTP exporter.
type retryPolicy struct {
	MaxAttempts int
	BaseDelay   time.Duration
	MaxDelay    time.Duration
}

func defaultRetryPolicy() retryPolicy {
	return retryPolicy{MaxAttempts: 3, BaseDelay: 500 * time.Millisecond, MaxDelay: 5 * time.Second}
}

func (r retryPolicy) delay(attempt int) time.Duration {
	d := time.Duration(float64(r.BaseDelay) * math.Pow(2, float64(attempt)))
	if d > r.MaxDelay {
		d = r.MaxDelay
	}
	return d
}

// retryableStatus reports whether an HTTP status warrants another attempt.
//
// 5xx and 429 are retried; 4xx are not, because a rejected payload will be
// rejected identically on every attempt and retrying only delays the
// operator's discovery of the misconfiguration.
func retryableStatus(code int) bool {
	return code >= 500 || code == http.StatusTooManyRequests
}

// doWithRetry executes an HTTP request with backoff.
func doWithRetry(ctx context.Context, client *http.Client, policy retryPolicy, build func() (*http.Request, error)) error {
	var lastErr error

	for attempt := 0; attempt < policy.MaxAttempts; attempt++ {
		if attempt > 0 {
			select {
			case <-ctx.Done():
				return fmt.Errorf("export: aborted during backoff: %w (last error: %w)", ctx.Err(), lastErr)
			case <-time.After(policy.delay(attempt - 1)):
			}
		}

		req, err := build()
		if err != nil {
			return err
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			continue
		}

		// The body must be drained for the connection to be reused.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		resp.Body.Close()

		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			return nil
		}

		lastErr = fmt.Errorf("HTTP %s: %s", resp.Status, truncate(string(body), 512))
		if !retryableStatus(resp.StatusCode) {
			return fmt.Errorf("export: request rejected: %w", lastErr)
		}
	}

	return fmt.Errorf("export: giving up after %d attempts: %w", policy.MaxAttempts, lastErr)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// WebhookConfig configures the generic webhook exporter.
type WebhookConfig struct {
	URL     string
	Headers map[string]string
	Timeout time.Duration
	// Insecure disables TLS certificate verification.
	Insecure bool
	// Retry overrides the default retry policy.
	Retry *retryPolicy
}

// Webhook posts notification JSON to an arbitrary HTTP endpoint.
//
// This is the primary SOAR integration point: Cortex XSOAR, Splunk SOAR, Tines
// and every homegrown automation platform accept an HTTP POST. The payload is
// the Notification structure, which carries the evidence URI rather than the
// evidence.
type Webhook struct {
	cfg    WebhookConfig
	client *http.Client
	retry  retryPolicy
}

// NewWebhook builds a webhook exporter.
func NewWebhook(cfg WebhookConfig) (*Webhook, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("export: webhook URL is required")
	}
	retry := defaultRetryPolicy()
	if cfg.Retry != nil {
		retry = *cfg.Retry
	}
	return &Webhook{
		cfg:    cfg,
		client: httpClient(cfg.Timeout, cfg.Insecure),
		retry:  retry,
	}, nil
}

// Name implements Exporter.
func (w *Webhook) Name() string { return "webhook" }

// Send implements Exporter.
func (w *Webhook) Send(ctx context.Context, n Notification) error {
	payload, err := json.Marshal(n)
	if err != nil {
		return fmt.Errorf("export: marshal webhook payload: %w", err)
	}

	return doWithRetry(ctx, w.client, w.retry, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.cfg.URL, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("export: build webhook request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("User-Agent", "flight-recorder")
		for k, v := range w.cfg.Headers {
			req.Header.Set(k, v)
		}
		return req, nil
	})
}

// Close implements Exporter.
func (w *Webhook) Close() error {
	w.client.CloseIdleConnections()
	return nil
}
