//go:build integration && linux

// Package integration exercises the parts of Flight Recorder that need a real
// kernel: eBPF attachment, ring buffer delivery, and process_vm_readv against
// live processes.
//
// Run with:
//
//	sudo go test -tags=integration -v ./test/integration/...
//
// Root (or CAP_BPF + CAP_PERFMON + CAP_SYS_PTRACE) is required. Tests skip
// rather than fail when a capability is missing, so the suite is still useful
// on a developer machine, but CI runs it privileged and expects it to execute.
package integration

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/Unspekable1654/flight-recorder/pkg/capture"
	"github.com/Unspekable1654/flight-recorder/pkg/config"
	"github.com/Unspekable1654/flight-recorder/pkg/container"
	"github.com/Unspekable1654/flight-recorder/pkg/evidence"
	"github.com/Unspekable1654/flight-recorder/pkg/export"
	"github.com/Unspekable1654/flight-recorder/pkg/pipeline"
	"github.com/Unspekable1654/flight-recorder/pkg/probe"
	"github.com/Unspekable1654/flight-recorder/pkg/seal"
)

const testMarker = "FLIGHT_RECORDER_TEST_2026_SECRET_KEY"

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root (or CAP_BPF, CAP_PERFMON and CAP_SYS_PTRACE)")
	}
}

// -----------------------------------------------------------------------------
// The freeze-frame itself
// -----------------------------------------------------------------------------

// TestCaptureOwnMemoryFindsMarker is the core claim of the tool, reduced to its
// smallest verifiable form: a secret held in a live process's memory can be
// extracted without stopping that process.
//
// The target is this test process. That is not a shortcut - it makes the
// assertion exact, because the test knows precisely which bytes should be
// found and can prove they were still in memory at the moment of capture.
func TestCaptureOwnMemoryFindsMarker(t *testing.T) {
	requireRoot(t)

	// Hold the marker in a live heap allocation for the duration of the test.
	secret := make([]byte, 4<<20)
	for i := range secret {
		secret[i] = byte(i % 251)
	}
	copy(secret[len(secret)/2:], testMarker)
	defer runtime.KeepAlive(secret)

	dump, err := capture.DumpProcessMemory(context.Background(), os.Getpid(), capture.Options{
		ProcRoot: "/proc",
		Filter:   capture.DefaultFilterOptions(),
		MaxBytes: 512 << 20,
	})
	if err != nil {
		t.Fatalf("DumpProcessMemory: %v", err)
	}

	if dump.TotalBytes == 0 {
		t.Fatal("acquired no memory at all")
	}
	t.Logf("acquired %d bytes from %d regions in %s (maps->read gap %.2f ms, outcome %s)",
		dump.TotalBytes, len(dump.Regions), dump.Duration(), dump.MapsToFirstReadMS, dump.Outcome())

	if !bytes.Contains(dump.Bytes(), []byte(testMarker)) {
		t.Fatalf("the marker was not found in %d bytes of acquired memory", dump.TotalBytes)
	}

	// The process must still be alive and unmodified: acquisition is read-only.
	if err := capture.ProcessAlive(os.Getpid()); err != nil {
		t.Errorf("the target process is no longer healthy after acquisition: %v", err)
	}
	if !bytes.Contains(secret, []byte(testMarker)) {
		t.Error("the target's memory was modified by acquisition")
	}
}

// TestCaptureChildProcessMemory captures a different process, which is the
// real deployment shape.
func TestCaptureChildProcessMemory(t *testing.T) {
	requireRoot(t)

	// A shell that keeps a recognisable string in its own memory and stays
	// alive long enough to be captured.
	script := fmt.Sprintf(`SECRET=%s; export SECRET; sleep 30`, testMarker)
	cmd := exec.Command("/bin/sh", "-c", script)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start target process: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	time.Sleep(300 * time.Millisecond)

	start := time.Now()
	dump, err := capture.DumpProcessMemory(context.Background(), cmd.Process.Pid, capture.Options{
		ProcRoot: "/proc",
		Filter:   capture.DefaultFilterOptions(),
		MaxBytes: 512 << 20,
	})
	if err != nil {
		t.Fatalf("DumpProcessMemory: %v", err)
	}
	elapsed := time.Since(start)

	t.Logf("captured pid %d: %d bytes, %d regions, %s (%d full, %d partial, %d failed)",
		cmd.Process.Pid, dump.TotalBytes, len(dump.Regions), elapsed,
		dump.FullRegions, dump.PartialRegions, dump.FailedRegions)

	if dump.TotalBytes == 0 {
		t.Fatal("acquired no memory from the child process")
	}
	if !bytes.Contains(dump.Bytes(), []byte(testMarker)) {
		t.Error("the marker held by the child process was not recovered")
	}

	// The child must still be running: no SIGSTOP, no ptrace attach.
	if err := cmd.Process.Signal(os.Signal(nil)); err != nil {
		// Signal(nil) is not portable; fall back to the liveness check.
		if err := capture.ProcessAlive(cmd.Process.Pid); err != nil {
			t.Errorf("the child process did not survive acquisition: %v", err)
		}
	}
}

// TestCaptureExitedProcess covers the ESRCH path: the most common outcome for
// genuinely ephemeral workloads, and the one that must never panic.
func TestCaptureExitedProcess(t *testing.T) {
	requireRoot(t)

	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	pid := cmd.Process.Pid
	if err := cmd.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
	time.Sleep(50 * time.Millisecond)

	_, err := capture.DumpProcessMemory(context.Background(), pid, capture.Options{ProcRoot: "/proc"})
	if err == nil {
		t.Skip("the PID was reused before the check; not a failure of the code under test")
	}
	if !errors.Is(err, capture.ErrProcessGone) {
		t.Errorf("error = %v, want ErrProcessGone", err)
	}
}

// TestCaptureRejectsPIDReuse proves the identity guard works: a capture keyed
// to a start time must refuse to acquire a different process that inherited
// the PID.
func TestCaptureRejectsPIDReuse(t *testing.T) {
	requireRoot(t)

	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	realStart, err := capture.ProcessStartTime("/proc", cmd.Process.Pid)
	if err != nil {
		t.Fatalf("ProcessStartTime: %v", err)
	}

	// Correct start time: acquisition proceeds.
	if _, err := capture.DumpProcessMemory(context.Background(), cmd.Process.Pid, capture.Options{
		ProcRoot:          "/proc",
		Filter:            capture.DefaultFilterOptions(),
		ExpectedStartTime: realStart,
	}); err != nil {
		t.Fatalf("acquisition with the correct start time failed: %v", err)
	}

	// Wrong start time: the PID must be treated as a different process.
	_, err = capture.DumpProcessMemory(context.Background(), cmd.Process.Pid, capture.Options{
		ProcRoot:          "/proc",
		ExpectedStartTime: realStart + 1,
	})
	if !errors.Is(err, capture.ErrIdentityMismatch) {
		t.Errorf("error = %v, want ErrIdentityMismatch: a recycled PID must not be captured", err)
	}
}

// -----------------------------------------------------------------------------
// eBPF
// -----------------------------------------------------------------------------

// TestProbeObservesExec verifies the whole kernel-to-userspace path: the
// tracepoint fires, the ring buffer delivers, and the decoded record carries
// the argv the rule engine needs.
func TestProbeObservesExec(t *testing.T) {
	requireRoot(t)

	p, err := probe.Load(probe.LoadOptions{
		TrackExits: true,
		SelfTGID:   0, // observe everything, including processes we spawn
	})
	if err != nil {
		t.Fatalf("probe.Load: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	events := p.Events(ctx, 4096)

	// Give the reader a moment to start before generating the event.
	time.Sleep(200 * time.Millisecond)

	const sentinel = "/flight-recorder-integration-sentinel"
	cmd := exec.Command("/bin/cat", sentinel)
	_ = cmd.Run() // expected to fail: the file does not exist, but execve happened

	deadline := time.After(15 * time.Second)
	for {
		select {
		case event, ok := <-events:
			if !ok {
				t.Fatal("event channel closed before the sentinel exec was observed")
			}
			if event.Kind != probe.KindExec {
				continue
			}
			if !strings.Contains(event.CommandLine(), sentinel) {
				continue
			}

			t.Logf("observed: pid=%d ns_pid=%d tgid=%d uid=%d cgroup=%d comm=%q filename=%q args=%v",
				event.HostPID, event.NamespacePID, event.HostTGID, event.UID,
				event.CgroupID, event.Comm, event.Filename, event.Args)

			if event.HostPID == 0 {
				t.Error("event carries no host PID")
			}
			if event.TimestampNS == 0 {
				t.Error("event carries no monotonic timestamp")
			}
			if event.Filename == "" {
				t.Error("event carries no binary path")
			}
			if event.NamespacePID == 0 {
				t.Error("namespace PID resolution produced 0")
			}

			stats, err := p.Stats()
			if err != nil {
				t.Fatalf("Stats: %v", err)
			}
			t.Logf("kernel counters: seen=%d submitted=%d dropped=%d exits=%d",
				stats.ExecSeen, stats.ExecSubmitted, stats.RingbufDropped, stats.ExitSubmitted)
			if stats.ExecSubmitted == 0 {
				t.Error("kernel counter says no events were submitted")
			}
			return

		case <-deadline:
			stats, _ := p.Stats()
			t.Fatalf("timed out waiting for the sentinel exec (kernel saw %d execs, submitted %d, dropped %d)",
				stats.ExecSeen, stats.ExecSubmitted, stats.RingbufDropped)
		}
	}
}

// TestProbeHandlesEventStorm checks that a burst does not deadlock the reader
// and that any loss is accounted for rather than silent.
func TestProbeHandlesEventStorm(t *testing.T) {
	requireRoot(t)

	p, err := probe.Load(probe.LoadOptions{})
	if err != nil {
		t.Fatalf("probe.Load: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	events := p.Events(ctx, 8192)

	received := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range events {
			received++
		}
	}()

	time.Sleep(200 * time.Millisecond)

	const burst = 1000
	start := time.Now()
	cmd := exec.Command("/bin/sh", "-c", fmt.Sprintf("i=0; while [ $i -lt %d ]; do /bin/true; i=$((i+1)); done", burst))
	if err := cmd.Run(); err != nil {
		t.Fatalf("burst generator failed: %v", err)
	}
	elapsed := time.Since(start)

	time.Sleep(2 * time.Second)
	cancel()
	<-done

	stats, err := p.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}

	t.Logf("%d execs in %s: kernel saw %d, submitted %d, ring buffer dropped %d, userspace lost %d, delivered %d",
		burst, elapsed, stats.ExecSeen, stats.ExecSubmitted, stats.RingbufDropped, p.LostRecords(), received)

	if stats.ExecSeen < burst {
		t.Errorf("kernel observed %d execs, expected at least %d", stats.ExecSeen, burst)
	}
	if stats.RingbufDropped > 0 {
		t.Logf("note: %d events were dropped by the kernel ring buffer under this burst", stats.RingbufDropped)
	}
	if received == 0 {
		t.Error("no events reached userspace during the burst")
	}
}

// -----------------------------------------------------------------------------
// Full pipeline
// -----------------------------------------------------------------------------

// TestEndToEndTriggerToVerifiedBundle is the whole product in one test: a
// process executes something that matches a rule, its memory is acquired,
// sealed, exported as CASE/UCO, written to disk, and independently verified.
func TestEndToEndTriggerToVerifiedBundle(t *testing.T) {
	requireRoot(t)

	workDir := t.TempDir()
	evidenceRoot := filepath.Join(workDir, "evidence")

	signer, err := seal.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	writer, err := evidence.NewWriter(evidence.DefaultWriterOptions(evidenceRoot, signer))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	notifications := filepath.Join(workDir, "notifications.jsonl")
	fileExporter, err := export.NewFileExporter(notifications)
	if err != nil {
		t.Fatalf("NewFileExporter: %v", err)
	}
	exporters := export.NewMulti(fileExporter)
	defer exporters.Close()

	// A rule that matches a command this test controls exactly.
	cfg := config.Default()
	cfg.Rules = append(cfg.Rules, config.Rule{
		Name:        "integration_sentinel",
		Match:       "flight-recorder-e2e-sentinel",
		Severity:    config.SeverityCritical,
		Description: "Integration test sentinel",
	})
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}

	logger := zerolog.New(zerolog.NewConsoleWriter()).Level(zerolog.InfoLevel)

	pipe, err := pipeline.New(pipeline.Options{
		Config:         config.NewStore(cfg),
		Resolver:       container.NewResolver(container.WithProcRoot("/proc"), container.WithNodeName("integration")),
		Signer:         signer,
		Writer:         writer,
		Exporters:      exporters,
		Logger:         logger,
		Workers:        2,
		QueueSize:      8,
		CaptureTimeout: 30 * time.Second,
		ProcRoot:       "/proc",
		EvidenceRoot:   evidenceRoot,
		NodeName:       "integration",
		Operator:       "integration-test",
		KernelVersion:  probe.KernelVersion(),
	})
	if err != nil {
		t.Fatalf("pipeline.New: %v", err)
	}

	p, err := probe.Load(probe.LoadOptions{TrackExits: true})
	if err != nil {
		t.Fatalf("probe.Load: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	bootClock, _ := probe.BootWallClock()
	_ = bootClock

	events := p.Events(ctx, 4096)

	pipelineDone := make(chan struct{})
	go func() {
		_ = pipe.Run(ctx, events)
		close(pipelineDone)
	}()

	time.Sleep(300 * time.Millisecond)

	// The target: a shell that matches the rule and then stays alive long
	// enough for the capture to reach it.
	target := exec.Command("/bin/sh", "-c", "flight-recorder-e2e-sentinel=1 sleep 20")
	if err := target.Start(); err != nil {
		t.Fatalf("start target: %v", err)
	}
	defer func() {
		_ = target.Process.Kill()
		_, _ = target.Process.Wait()
	}()

	// Wait for a bundle to appear.
	var bundles []string
	deadline := time.Now().Add(40 * time.Second)
	for time.Now().Before(deadline) {
		bundles, _ = evidence.ListBundles(evidenceRoot)
		if len(bundles) > 0 {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	stats := pipe.Stats()
	t.Logf("pipeline: events=%d matched=%d captures=%d failed=%d dropped=%d bytes=%d",
		stats.EventsSeen, stats.EventsMatched, stats.CapturesDone, stats.CapturesFailed,
		stats.CapturesDropped, stats.BytesCaptured)

	if len(bundles) == 0 {
		t.Fatal("no evidence bundle was produced within the deadline")
	}

	bundleDir := filepath.Join(evidenceRoot, bundles[0])
	report, err := evidence.VerifyBundle(bundleDir, signer.Public(), signer)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !report.OK() {
		t.Fatalf("the produced bundle failed verification: %v", report.Errors)
	}
	t.Logf("verified: %s", report.Summary())

	// The CASE bundle must be present, valid, and contain the trigger.
	metaRaw, err := os.ReadFile(filepath.Join(bundleDir, evidence.FileMetadata))
	if err != nil {
		t.Fatalf("read CASE bundle: %v", err)
	}
	if !strings.Contains(string(metaRaw), "integration_sentinel") {
		t.Error("the CASE bundle does not name the rule that triggered the capture")
	}
	if !strings.Contains(string(metaRaw), "process_vm_readv") {
		t.Error("the CASE bundle does not record the acquisition method")
	}

	// The SIEM notification must have fired, and must not contain the payload.
	notifRaw, err := os.ReadFile(notifications)
	if err != nil {
		t.Fatalf("read notifications: %v", err)
	}
	if len(notifRaw) == 0 {
		t.Error("no notification was exported")
	}
	if bytes.Contains(notifRaw, []byte(testMarker)) {
		t.Error("the notification contains captured memory content")
	}

	cancel()
	<-pipelineDone
}
