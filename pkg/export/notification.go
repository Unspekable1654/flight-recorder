// Package export delivers capture notifications to the systems a SOC already
// runs: SIEMs, SOAR platforms, and anything that speaks syslog.
//
// One design rule governs this entire package: the memory dump itself is never
// transmitted. Only metadata, hashes and a URI reference leave the node. A
// 512 MB dump forwarded into a SIEM would be both ruinously expensive and a
// data-protection incident in its own right, since the dump contains exactly
// the credentials and personal data the SIEM is least entitled to hold.
package export

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Notification is the evidence summary sent to external systems.
type Notification struct {
	CaseID    string    `json:"case_id"`
	Timestamp time.Time `json:"timestamp"`

	Rule     string `json:"rule"`
	Severity string `json:"severity"`
	MITRE    string `json:"mitre_technique,omitempty"`

	Comm         string   `json:"comm"`
	Cmdline      string   `json:"cmdline"`
	Args         []string `json:"args,omitempty"`
	HostPID      int      `json:"host_pid"`
	NamespacePID int      `json:"namespace_pid"`
	UID          uint32   `json:"uid"`

	ContainerID  string `json:"container_id,omitempty"`
	PodName      string `json:"pod_name,omitempty"`
	PodNamespace string `json:"pod_namespace,omitempty"`
	NodeName     string `json:"node_name,omitempty"`
	Runtime      string `json:"container_runtime,omitempty"`

	CaptureStart   time.Time `json:"capture_start"`
	CaptureEnd     time.Time `json:"capture_end"`
	LatencyMS      float64   `json:"latency_ms"`
	DumpSizeBytes  int64     `json:"dump_size_bytes"`
	DumpSHA256     string    `json:"dump_sha256"`
	RegionCount    int       `json:"region_count"`
	CaptureStatus  string    `json:"capture_status"`
	PartialRegions int       `json:"partial_regions"`

	MerkleRoot  string `json:"merkle_root"`
	SignerKeyID string `json:"signer_key_id"`

	// EvidenceURI points at the stored bundle. It is a reference, never the
	// content.
	EvidenceURI    string `json:"evidence_uri"`
	Classification string `json:"classification"`
	ToolName       string `json:"tool_name"`
	ToolVersion    string `json:"tool_version"`
	KernelVersion  string `json:"kernel_version,omitempty"`
}

// Exporter delivers notifications to one destination.
type Exporter interface {
	// Name identifies the exporter in logs and metrics.
	Name() string
	// Send delivers one notification. Implementations must respect ctx.
	Send(ctx context.Context, n Notification) error
	// Close releases any held resources.
	Close() error
}

// Result records the outcome of one delivery attempt.
type Result struct {
	Target   string
	Err      error
	Duration time.Duration
}

// Multi fans a notification out to several exporters concurrently.
//
// Delivery failures are collected and reported but never propagated as a
// capture failure: the evidence is already sealed on disk, and losing a SIEM
// notification must not be conflated with losing evidence.
type Multi struct {
	exporters []Exporter
	// Timeout bounds each individual delivery.
	Timeout time.Duration
	// OnResult receives every attempt, for metrics and the audit log.
	OnResult func(Result)
}

// NewMulti groups exporters.
func NewMulti(exporters ...Exporter) *Multi {
	return &Multi{exporters: exporters, Timeout: 10 * time.Second}
}

// Add appends an exporter.
func (m *Multi) Add(e Exporter) {
	if e != nil {
		m.exporters = append(m.exporters, e)
	}
}

// Len returns the number of configured exporters.
func (m *Multi) Len() int { return len(m.exporters) }

// Names lists the configured exporters.
func (m *Multi) Names() []string {
	out := make([]string, 0, len(m.exporters))
	for _, e := range m.exporters {
		out = append(out, e.Name())
	}
	return out
}

// Send delivers to every exporter and returns all results.
func (m *Multi) Send(ctx context.Context, n Notification) []Result {
	if len(m.exporters) == 0 {
		return nil
	}

	timeout := m.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	results := make([]Result, len(m.exporters))
	var wg sync.WaitGroup

	for i, e := range m.exporters {
		wg.Add(1)
		go func(i int, e Exporter) {
			defer wg.Done()

			sendCtx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()

			start := time.Now()
			err := e.Send(sendCtx, n)
			res := Result{Target: e.Name(), Err: err, Duration: time.Since(start)}
			results[i] = res

			if m.OnResult != nil {
				m.OnResult(res)
			}
		}(i, e)
	}

	wg.Wait()
	return results
}

// Close closes every exporter.
func (m *Multi) Close() error {
	var firstErr error
	for _, e := range m.exporters {
		if err := e.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// JSON renders the notification as compact JSON.
func (n Notification) JSON() ([]byte, error) {
	out, err := json.Marshal(n)
	if err != nil {
		return nil, fmt.Errorf("export: marshal notification: %w", err)
	}
	return out, nil
}

// Summary renders a single human-readable line, used in logs and syslog
// messages.
func (n Notification) Summary() string {
	where := n.NodeName
	if n.PodName != "" {
		where = fmt.Sprintf("%s/%s", n.PodNamespace, n.PodName)
	}
	return fmt.Sprintf("rule=%s severity=%s target=%s pid=%d comm=%s bytes=%d case=%s",
		n.Rule, n.Severity, where, n.HostPID, n.Comm, n.DumpSizeBytes, n.CaseID)
}
