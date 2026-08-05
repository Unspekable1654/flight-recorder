package telemetry

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// AuditAction names the kinds of entry written to the audit log.
type AuditAction string

// Audit actions. Every privileged or evidence-affecting operation has one.
const (
	AuditStart          AuditAction = "recorder_started"
	AuditStop           AuditAction = "recorder_stopped"
	AuditProbeAttached  AuditAction = "probe_attached"
	AuditProbeDetached  AuditAction = "probe_detached"
	AuditTriggerMatched AuditAction = "trigger_matched"
	AuditCaptureStarted AuditAction = "capture_started"
	AuditCaptureDone    AuditAction = "capture_completed"
	AuditCaptureFailed  AuditAction = "capture_failed"
	AuditCaptureDropped AuditAction = "capture_dropped"
	AuditBundleWritten  AuditAction = "bundle_written"
	AuditBundleDeleted  AuditAction = "bundle_deleted"
	AuditExportSent     AuditAction = "export_sent"
	AuditExportFailed   AuditAction = "export_failed"
	AuditConfigReloaded AuditAction = "config_reloaded"
	AuditConfigRejected AuditAction = "config_rejected"
	AuditKeyGenerated   AuditAction = "signing_key_generated"
	AuditVerify         AuditAction = "bundle_verified"
)

// AuditEntry is one line of the audit log.
//
// The schema is intentionally flat and stable: this file will be read by
// whatever tooling exists years from now, quite possibly by someone auditing
// whether this tool overstepped.
type AuditEntry struct {
	Time         time.Time   `json:"time"`
	Action       AuditAction `json:"action"`
	CaseID       string      `json:"case_id,omitempty"`
	Rule         string      `json:"rule,omitempty"`
	Severity     string      `json:"severity,omitempty"`
	HostPID      int         `json:"host_pid,omitempty"`
	NSPid        int         `json:"namespace_pid,omitempty"`
	Comm         string      `json:"comm,omitempty"`
	Cmdline      string      `json:"cmdline,omitempty"`
	ContainerID  string      `json:"container_id,omitempty"`
	PodName      string      `json:"pod_name,omitempty"`
	PodNS        string      `json:"pod_namespace,omitempty"`
	NodeName     string      `json:"node_name,omitempty"`
	Bytes        int64       `json:"bytes,omitempty"`
	DurationMS   float64     `json:"duration_ms,omitempty"`
	MerkleRoot   string      `json:"merkle_root,omitempty"`
	EvidencePath string      `json:"evidence_path,omitempty"`
	Target       string      `json:"target,omitempty"`
	Result       string      `json:"result,omitempty"`
	Reason       string      `json:"reason,omitempty"`
	Operator     string      `json:"operator,omitempty"`
	ToolVersion  string      `json:"tool_version,omitempty"`
}

// AuditLog is an append-only JSON Lines writer.
//
// Every entry is flushed and fsynced before the write returns. That is
// deliberately expensive: an audit record that is still in a page cache buffer
// when the node loses power did not happen, and the whole point of this file is
// that it can be relied upon after the fact. Capture throughput is bounded by
// rate limits well below the point where audit fsync matters.
type AuditLog struct {
	mu       sync.Mutex
	f        *os.File
	path     string
	enabled  bool
	nodeName string
	version  string
	operator string
}

// AuditOptions configures the audit log.
type AuditOptions struct {
	Path        string
	NodeName    string
	ToolVersion string
	Operator    string
}

// NewAuditLog opens (or creates) the audit log in append mode.
//
// A nil-safe disabled log is returned when Path is empty, so callers never
// need to nil-check.
func NewAuditLog(opts AuditOptions) (*AuditLog, error) {
	if opts.Path == "" {
		return &AuditLog{enabled: false}, nil
	}

	if err := os.MkdirAll(filepath.Dir(opts.Path), 0o750); err != nil {
		return nil, fmt.Errorf("telemetry: create audit log directory: %w", err)
	}

	// O_APPEND makes concurrent appends atomic for reasonably sized records,
	// which matters if an operator tails this file while it is being written.
	f, err := os.OpenFile(opts.Path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("telemetry: open audit log %s: %w", opts.Path, err)
	}

	return &AuditLog{
		f:        f,
		path:     opts.Path,
		enabled:  true,
		nodeName: opts.NodeName,
		version:  opts.ToolVersion,
		operator: opts.Operator,
	}, nil
}

// Write appends an entry.
func (a *AuditLog) Write(entry AuditEntry) error {
	if a == nil || !a.enabled {
		return nil
	}

	if entry.Time.IsZero() {
		entry.Time = time.Now().UTC()
	} else {
		entry.Time = entry.Time.UTC()
	}
	if entry.NodeName == "" {
		entry.NodeName = a.nodeName
	}
	if entry.ToolVersion == "" {
		entry.ToolVersion = a.version
	}
	if entry.Operator == "" {
		entry.Operator = a.operator
	}

	line, err := json.Marshal(entry)
	if err != nil {
		return fmt.Errorf("telemetry: marshal audit entry: %w", err)
	}
	line = append(line, '\n')

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, err := a.f.Write(line); err != nil {
		return fmt.Errorf("telemetry: write audit entry: %w", err)
	}
	if err := a.f.Sync(); err != nil {
		return fmt.Errorf("telemetry: sync audit log: %w", err)
	}
	return nil
}

// Path returns the audit log path ("" when disabled).
func (a *AuditLog) Path() string {
	if a == nil {
		return ""
	}
	return a.path
}

// Enabled reports whether entries are being written.
func (a *AuditLog) Enabled() bool { return a != nil && a.enabled }

// Close flushes and closes the log.
func (a *AuditLog) Close() error {
	if a == nil || !a.enabled {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := a.f.Close(); err != nil {
		return fmt.Errorf("telemetry: close audit log: %w", err)
	}
	a.enabled = false
	return nil
}
