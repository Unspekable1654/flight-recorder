package export

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// -----------------------------------------------------------------------------
// Splunk HTTP Event Collector
// -----------------------------------------------------------------------------

// SplunkConfig configures the Splunk HEC exporter.
type SplunkConfig struct {
	// URL is the collector endpoint, e.g. https://splunk:8088/services/collector/event
	URL        string
	Token      string
	Index      string
	SourceType string
	Source     string
	Host       string
	Timeout    time.Duration
	Insecure   bool
}

// Splunk sends notifications to a Splunk HTTP Event Collector.
type Splunk struct {
	cfg    SplunkConfig
	client *http.Client
	retry  retryPolicy
}

// NewSplunk builds a Splunk HEC exporter.
func NewSplunk(cfg SplunkConfig) (*Splunk, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("export: splunk URL is required")
	}
	if cfg.Token == "" {
		return nil, fmt.Errorf("export: splunk HEC token is required")
	}
	if cfg.SourceType == "" {
		cfg.SourceType = "flight_recorder"
	}
	if cfg.Source == "" {
		cfg.Source = "flight-recorder"
	}
	if cfg.Index == "" {
		cfg.Index = "forensics"
	}
	if cfg.Host == "" {
		cfg.Host, _ = os.Hostname()
	}
	return &Splunk{cfg: cfg, client: httpClient(cfg.Timeout, cfg.Insecure), retry: defaultRetryPolicy()}, nil
}

// Name implements Exporter.
func (s *Splunk) Name() string { return "splunk-hec" }

// splunkEnvelope is the HEC wire format.
type splunkEnvelope struct {
	Time       float64        `json:"time"`
	Host       string         `json:"host"`
	Source     string         `json:"source"`
	SourceType string         `json:"sourcetype"`
	Index      string         `json:"index"`
	Event      map[string]any `json:"event"`
}

// Send implements Exporter.
//
// Field names follow the Splunk Common Information Model where one applies, so
// that existing CIM-based dashboards and correlation searches pick these
// events up without custom field extractions.
func (s *Splunk) Send(ctx context.Context, n Notification) error {
	event := map[string]any{
		"action":          "captured",
		"vendor_product":  "Flight Recorder",
		"signature":       n.Rule,
		"signature_id":    n.MITRE,
		"severity":        n.Severity,
		"process":         n.Cmdline,
		"process_name":    n.Comm,
		"process_id":      n.HostPID,
		"user_id":         n.UID,
		"dest":            n.NodeName,
		"container_id":    n.ContainerID,
		"kubernetes_pod":  n.PodName,
		"kubernetes_ns":   n.PodNamespace,
		"file_hash":       n.DumpSHA256,
		"bytes":           n.DumpSizeBytes,
		"case_id":         n.CaseID,
		"merkle_root":     n.MerkleRoot,
		"signer_key_id":   n.SignerKeyID,
		"evidence_uri":    n.EvidenceURI,
		"capture_status":  n.CaptureStatus,
		"latency_ms":      n.LatencyMS,
		"classification":  n.Classification,
		"tool_version":    n.ToolVersion,
		"kernel_version":  n.KernelVersion,
		"namespace_pid":   n.NamespacePID,
		"region_count":    n.RegionCount,
		"partial_regions": n.PartialRegions,
	}

	envelope := splunkEnvelope{
		Time:       float64(n.Timestamp.UnixNano()) / 1e9,
		Host:       s.cfg.Host,
		Source:     s.cfg.Source,
		SourceType: s.cfg.SourceType,
		Index:      s.cfg.Index,
		Event:      event,
	}

	payload, err := json.Marshal(envelope)
	if err != nil {
		return fmt.Errorf("export: marshal splunk payload: %w", err)
	}

	return doWithRetry(ctx, s.client, s.retry, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.URL, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("export: build splunk request: %w", err)
		}
		req.Header.Set("Authorization", "Splunk "+s.cfg.Token)
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
}

// Close implements Exporter.
func (s *Splunk) Close() error {
	s.client.CloseIdleConnections()
	return nil
}

// -----------------------------------------------------------------------------
// Elasticsearch / Elastic Common Schema
// -----------------------------------------------------------------------------

// ElasticConfig configures the Elasticsearch exporter.
type ElasticConfig struct {
	// URL is the Elasticsearch base URL, e.g. https://elastic:9200
	URL      string
	Index    string
	Username string
	Password string
	APIKey   string
	Timeout  time.Duration
	Insecure bool
}

// Elastic indexes notifications as ECS documents.
type Elastic struct {
	cfg    ElasticConfig
	client *http.Client
	retry  retryPolicy
}

// NewElastic builds an Elasticsearch exporter.
func NewElastic(cfg ElasticConfig) (*Elastic, error) {
	if cfg.URL == "" {
		return nil, fmt.Errorf("export: elasticsearch URL is required")
	}
	if cfg.Index == "" {
		cfg.Index = "flight-recorder"
	}
	cfg.URL = strings.TrimRight(cfg.URL, "/")
	return &Elastic{cfg: cfg, client: httpClient(cfg.Timeout, cfg.Insecure), retry: defaultRetryPolicy()}, nil
}

// Name implements Exporter.
func (e *Elastic) Name() string { return "elastic-ecs" }

// Send implements Exporter.
//
// The document follows the Elastic Common Schema so that Kibana's prebuilt
// process, container and file views work without a custom mapping. Fields
// outside ECS live under the flight_recorder.* prefix, which is the convention
// ECS prescribes for vendor extensions.
func (e *Elastic) Send(ctx context.Context, n Notification) error {
	doc := map[string]any{
		"@timestamp": n.Timestamp.UTC().Format(time.RFC3339Nano),
		"event": map[string]any{
			"kind":     "alert",
			"category": []string{"intrusion_detection", "process"},
			"type":     []string{"info"},
			"action":   "memory-capture",
			"outcome":  ecsOutcome(n.CaptureStatus),
			"severity": ecsSeverity(n.Severity),
			"module":   "flight_recorder",
			"dataset":  "flight_recorder.capture",
			"duration": int64(n.LatencyMS * 1e6),
			"reason":   n.Rule,
		},
		"process": map[string]any{
			"pid":          n.HostPID,
			"name":         n.Comm,
			"command_line": n.Cmdline,
			"args":         n.Args,
		},
		"user": map[string]any{
			"id": fmt.Sprintf("%d", n.UID),
		},
		"file": map[string]any{
			"size": n.DumpSizeBytes,
			"hash": map[string]any{"sha256": n.DumpSHA256},
		},
		"host": map[string]any{
			"name": n.NodeName,
			"os":   map[string]any{"kernel": n.KernelVersion},
		},
		"rule": map[string]any{
			"name": n.Rule,
			"id":   n.MITRE,
		},
		"threat": map[string]any{
			"technique": map[string]any{"id": n.MITRE},
		},
		"observer": map[string]any{
			"vendor":  "Flight Recorder",
			"product": n.ToolName,
			"version": n.ToolVersion,
		},
		"flight_recorder": map[string]any{
			"case_id":         n.CaseID,
			"merkle_root":     n.MerkleRoot,
			"signer_key_id":   n.SignerKeyID,
			"evidence_uri":    n.EvidenceURI,
			"classification":  n.Classification,
			"namespace_pid":   n.NamespacePID,
			"region_count":    n.RegionCount,
			"partial_regions": n.PartialRegions,
			"capture_status":  n.CaptureStatus,
		},
	}

	if n.ContainerID != "" {
		doc["container"] = map[string]any{
			"id":      n.ContainerID,
			"runtime": n.Runtime,
		}
	}
	if n.PodName != "" {
		doc["orchestrator"] = map[string]any{
			"type":      "kubernetes",
			"namespace": n.PodNamespace,
			"resource":  map[string]any{"name": n.PodName, "type": "pod"},
			"cluster":   map[string]any{"name": ""},
		}
	}

	payload, err := json.Marshal(doc)
	if err != nil {
		return fmt.Errorf("export: marshal elastic document: %w", err)
	}

	url := fmt.Sprintf("%s/%s/_doc", e.cfg.URL, e.cfg.Index)
	return doWithRetry(ctx, e.client, e.retry, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("export: build elastic request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		switch {
		case e.cfg.APIKey != "":
			req.Header.Set("Authorization", "ApiKey "+e.cfg.APIKey)
		case e.cfg.Username != "":
			req.SetBasicAuth(e.cfg.Username, e.cfg.Password)
		}
		return req, nil
	})
}

// Close implements Exporter.
func (e *Elastic) Close() error {
	e.client.CloseIdleConnections()
	return nil
}

func ecsOutcome(status string) string {
	switch status {
	case "complete", "partial", "truncated":
		return "success"
	default:
		return "failure"
	}
}

func ecsSeverity(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 99
	case "high":
		return 73
	case "medium":
		return 47
	case "low":
		return 21
	default:
		return 1
	}
}

// -----------------------------------------------------------------------------
// Syslog (RFC 5424) and CEF
// -----------------------------------------------------------------------------

// SyslogFormat selects the message encoding.
type SyslogFormat string

// Syslog encodings.
const (
	// SyslogRFC5424 emits structured data elements, readable by any modern
	// syslog collector.
	SyslogRFC5424 SyslogFormat = "rfc5424"
	// SyslogCEF emits ArcSight Common Event Format inside the syslog message,
	// which is what QRadar and ArcSight deployments expect.
	SyslogCEF SyslogFormat = "cef"
)

// SyslogConfig configures the syslog exporter.
type SyslogConfig struct {
	// Address is host:port.
	Address string
	// Network is "udp", "tcp" or "tcp+tls".
	Network string
	Format  SyslogFormat
	// Facility is the syslog facility number (default 13, "log audit").
	Facility int
	Hostname string
	AppName  string
	Timeout  time.Duration
	Insecure bool
}

// Syslog writes notifications to a syslog collector.
//
// Universal SIEM compatibility is the point of this exporter: every SIEM ever
// deployed can ingest syslog, including the ones with no REST API and no
// appetite for a new agent.
type Syslog struct {
	cfg SyslogConfig

	mu   sync.Mutex
	conn net.Conn
}

// NewSyslog builds a syslog exporter. The connection is established lazily so
// that a temporarily unreachable collector does not prevent startup.
func NewSyslog(cfg SyslogConfig) (*Syslog, error) {
	if cfg.Address == "" {
		return nil, fmt.Errorf("export: syslog address is required")
	}
	if cfg.Network == "" {
		cfg.Network = "udp"
	}
	switch cfg.Network {
	case "udp", "tcp", "tcp+tls":
	default:
		return nil, fmt.Errorf("export: unsupported syslog network %q (want udp, tcp or tcp+tls)", cfg.Network)
	}
	if cfg.Format == "" {
		cfg.Format = SyslogRFC5424
	}
	if cfg.Facility == 0 {
		cfg.Facility = 13 // log audit
	}
	if cfg.Hostname == "" {
		cfg.Hostname, _ = os.Hostname()
	}
	if cfg.AppName == "" {
		cfg.AppName = "flight-recorder"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 5 * time.Second
	}
	return &Syslog{cfg: cfg}, nil
}

// Name implements Exporter.
func (s *Syslog) Name() string { return "syslog-" + string(s.cfg.Format) }

// Send implements Exporter.
func (s *Syslog) Send(ctx context.Context, n Notification) error {
	msg := s.format(n)

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.ensureConn(ctx); err != nil {
		return err
	}

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(s.cfg.Timeout)
	}
	_ = s.conn.SetWriteDeadline(deadline)

	if _, err := s.conn.Write([]byte(msg)); err != nil {
		// A broken stream connection is recoverable: drop it so the next send
		// reconnects rather than failing forever.
		_ = s.conn.Close()
		s.conn = nil
		return fmt.Errorf("export: write syslog message: %w", err)
	}
	return nil
}

func (s *Syslog) ensureConn(ctx context.Context) error {
	if s.conn != nil {
		return nil
	}

	dialer := &net.Dialer{Timeout: s.cfg.Timeout}
	var (
		conn net.Conn
		err  error
	)

	switch s.cfg.Network {
	case "tcp+tls":
		conn, err = tls.DialWithDialer(dialer, "tcp", s.cfg.Address, &tls.Config{
			MinVersion: tls.VersionTLS12,
			//nolint:gosec // Operator-selected, see httpClient.
			InsecureSkipVerify: s.cfg.Insecure,
		})
	default:
		conn, err = dialer.DialContext(ctx, s.cfg.Network, s.cfg.Address)
	}

	if err != nil {
		return fmt.Errorf("export: connect syslog %s/%s: %w", s.cfg.Network, s.cfg.Address, err)
	}
	s.conn = conn
	return nil
}

func (s *Syslog) format(n Notification) string {
	priority := s.cfg.Facility*8 + severityToSyslog(n.Severity)

	switch s.cfg.Format {
	case SyslogCEF:
		// CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|Extension
		ext := strings.Join([]string{
			"src=" + n.NodeName,
			fmt.Sprintf("dpt=%d", n.HostPID),
			"dproc=" + escapeCEF(n.Comm),
			"msg=" + escapeCEF(n.Cmdline),
			"fileHash=" + n.DumpSHA256,
			fmt.Sprintf("fsize=%d", n.DumpSizeBytes),
			"cs1Label=CaseID", "cs1=" + n.CaseID,
			"cs2Label=MerkleRoot", "cs2=" + n.MerkleRoot,
			"cs3Label=EvidenceURI", "cs3=" + escapeCEF(n.EvidenceURI),
			"cs4Label=Pod", "cs4=" + escapeCEF(n.PodNamespace+"/"+n.PodName),
			"cs5Label=ContainerID", "cs5=" + n.ContainerID,
			"cn1Label=LatencyMS", fmt.Sprintf("cn1=%.0f", n.LatencyMS),
		}, " ")

		return fmt.Sprintf("<%d>%s %s CEF:0|FlightRecorder|FlightRecorder|%s|%s|%s|%d|%s\n",
			priority,
			n.Timestamp.UTC().Format(time.RFC3339),
			s.cfg.Hostname,
			n.ToolVersion,
			nonEmpty(n.MITRE, n.Rule),
			"Memory Captured",
			cefSeverity(n.Severity),
			ext,
		)

	default:
		structured := fmt.Sprintf(
			`[flightRecorder@52913 caseId="%s" rule="%s" severity="%s" mitre="%s" hostPid="%d" nsPid="%d" comm="%s" containerId="%s" pod="%s" namespace="%s" node="%s" merkleRoot="%s" sha256="%s" bytes="%d" status="%s" latencyMs="%.1f" evidenceUri="%s"]`,
			escapeSD(n.CaseID), escapeSD(n.Rule), escapeSD(n.Severity), escapeSD(n.MITRE),
			n.HostPID, n.NamespacePID, escapeSD(n.Comm), escapeSD(n.ContainerID),
			escapeSD(n.PodName), escapeSD(n.PodNamespace), escapeSD(n.NodeName),
			escapeSD(n.MerkleRoot), escapeSD(n.DumpSHA256), n.DumpSizeBytes,
			escapeSD(n.CaptureStatus), n.LatencyMS, escapeSD(n.EvidenceURI),
		)

		return fmt.Sprintf("<%d>1 %s %s %s %d %s %s %s\n",
			priority,
			n.Timestamp.UTC().Format(time.RFC3339Nano),
			s.cfg.Hostname,
			s.cfg.AppName,
			os.Getpid(),
			"MEMORY_CAPTURE",
			structured,
			n.Summary(),
		)
	}
}

// Close implements Exporter.
func (s *Syslog) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

func severityToSyslog(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 2 // crit
	case "high":
		return 3 // err
	case "medium":
		return 4 // warning
	case "low":
		return 5 // notice
	default:
		return 6 // info
	}
}

func cefSeverity(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 1
	}
}

func escapeCEF(s string) string {
	r := strings.NewReplacer(`\`, `\\`, "=", `\=`, "\n", " ", "\r", " ", "|", `\|`)
	return r.Replace(s)
}

func escapeSD(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "]", `\]`, "\n", " ", "\r", " ")
	return r.Replace(s)
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// -----------------------------------------------------------------------------
// File exporter (local JSON Lines)
// -----------------------------------------------------------------------------

// FileExporter appends notifications to a local JSON Lines file.
//
// It exists so that the export path can be exercised - in tests, in a demo, and
// on an air-gapped node - without any external system.
type FileExporter struct {
	mu   sync.Mutex
	f    *os.File
	path string
}

// NewFileExporter opens (or creates) the target file in append mode.
func NewFileExporter(path string) (*FileExporter, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return nil, fmt.Errorf("export: open notification file %s: %w", path, err)
	}
	return &FileExporter{f: f, path: path}, nil
}

// Name implements Exporter.
func (f *FileExporter) Name() string { return "file" }

// Send implements Exporter.
func (f *FileExporter) Send(_ context.Context, n Notification) error {
	line, err := n.JSON()
	if err != nil {
		return err
	}

	f.mu.Lock()
	defer f.mu.Unlock()

	if _, err := f.f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("export: write notification: %w", err)
	}
	return f.f.Sync()
}

// Close implements Exporter.
func (f *FileExporter) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.f == nil {
		return nil
	}
	err := f.f.Close()
	f.f = nil
	return err
}
