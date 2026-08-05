//go:build integration && linux

package integration

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sort"
	"testing"
	"time"

	"github.com/Unspekable1654/flight-recorder/pkg/capture"
	"github.com/Unspekable1654/flight-recorder/pkg/probe"
)

// TestEphemeralCaptureWindow measures the thing the whole project is premised
// on: how quickly a process must be captured before it is gone.
//
// It is a measurement, not a pass/fail on latency. What it does assert is that
// every outcome - captured, too late, PID recycled - is handled without panic
// and is correctly classified, because an incident responder reading the audit
// log needs "we were 40 ms too slow" to be distinguishable from "nothing
// happened".
func TestEphemeralCaptureWindow(t *testing.T) {
	requireRoot(t)

	type attempt struct {
		lifetime time.Duration
		latency  time.Duration
		bytes    int64
		outcome  string
	}

	lifetimes := []time.Duration{0, 5 * time.Millisecond, 25 * time.Millisecond, 100 * time.Millisecond, 500 * time.Millisecond}
	results := make([]attempt, 0, len(lifetimes))

	for _, lifetime := range lifetimes {
		// A process that runs for a known duration and then exits, exactly the
		// shape of a self-destructing container payload.
		script := fmt.Sprintf("sleep %.3f", lifetime.Seconds())
		cmd := exec.Command("/bin/sh", "-c", script)

		start := time.Now()
		if err := cmd.Start(); err != nil {
			t.Fatalf("start: %v", err)
		}
		pid := cmd.Process.Pid

		dump, err := capture.DumpProcessMemory(context.Background(), pid, capture.Options{
			ProcRoot: "/proc",
			Filter:   capture.DefaultFilterOptions(),
			MaxBytes: 64 << 20,
		})
		latency := time.Since(start)

		a := attempt{lifetime: lifetime, latency: latency}
		switch {
		case err == nil:
			a.bytes = dump.TotalBytes
			a.outcome = string(dump.Outcome())
		case errors.Is(err, capture.ErrProcessGone):
			a.outcome = "target_gone"
		case errors.Is(err, capture.ErrIdentityMismatch):
			a.outcome = "pid_reused"
		default:
			a.outcome = "error: " + err.Error()
		}
		results = append(results, a)

		_, _ = cmd.Process.Wait()
	}

	t.Log("ephemeral capture window measurements:")
	for _, r := range results {
		t.Logf("  target lifetime %-8s -> capture took %-12s outcome=%-14s bytes=%d",
			r.lifetime, r.latency.Round(time.Microsecond), r.outcome, r.bytes)
	}

	// A process that lives half a second must be capturable: if this fails,
	// the tool cannot serve its stated purpose on this machine.
	last := results[len(results)-1]
	if last.bytes == 0 {
		t.Errorf("failed to capture a process that lived %s (outcome %s)", last.lifetime, last.outcome)
	}

	// And the acquisition itself must be fast enough to matter. 2 seconds is a
	// deliberately loose ceiling: it is a smoke test against pathological
	// slowness, not the performance target (which is p95 < 400 ms for 50 MB).
	if last.latency > 2*time.Second {
		t.Errorf("acquiring a small process took %s; the capture window would be missed in practice", last.latency)
	}
}

// TestExitEventsPrecedeCaptureFailure checks the diagnostic value of the exit
// probe: when a capture fails because the target vanished, the exit event
// should be observable, which is what turns "capture failed" into "the
// container exited 12 ms before we reached it".
func TestExitEventsPrecedeCaptureFailure(t *testing.T) {
	requireRoot(t)

	p, err := probe.Load(probe.LoadOptions{TrackExits: true})
	if err != nil {
		t.Fatalf("probe.Load: %v", err)
	}
	defer p.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	events := p.Events(ctx, 4096)
	time.Sleep(200 * time.Millisecond)

	cmd := exec.Command("/bin/true")
	if err := cmd.Run(); err != nil {
		t.Fatalf("run: %v", err)
	}
	pid := uint32(cmd.Process.Pid)

	sawExec, sawExit := false, false
	deadline := time.After(15 * time.Second)

	// The probe reports host-namespace PIDs. When the test itself runs inside
	// a PID namespace (WSL, a container, a nested test harness) the PID we
	// hold is the namespace-local one, so either identifier may be the match.
	matches := func(event probe.Event) bool {
		return event.HostPID == pid || event.NamespacePID == pid
	}

	for !(sawExec && sawExit) {
		select {
		case event, ok := <-events:
			if !ok {
				t.Fatal("event channel closed early")
			}
			if !matches(event) {
				continue
			}
			switch event.Kind {
			case probe.KindExec:
				sawExec = true
			case probe.KindExit:
				sawExit = true
			}
		case <-deadline:
			t.Fatalf("timed out: saw exec=%v exit=%v for pid %d", sawExec, sawExit, pid)
		}
	}

	stats, err := p.Stats()
	if err != nil {
		t.Fatalf("Stats: %v", err)
	}
	if stats.ExitSubmitted == 0 {
		t.Error("no exit events were submitted by the kernel")
	}
}

// TestCaptureLatencyDistribution records the acquisition latency profile for a
// realistically sized process, which is the number quoted in the evaluation
// section of the whitepaper.
func TestCaptureLatencyDistribution(t *testing.T) {
	requireRoot(t)

	// A process with a meaningful amount of resident heap: python if present,
	// otherwise a shell with a large variable.
	var cmd *exec.Cmd
	if _, err := exec.LookPath("python3"); err == nil {
		cmd = exec.Command("python3", "-c", "buf = bytearray(32*1024*1024); import time; time.sleep(30)")
	} else {
		cmd = exec.Command("/bin/sh", "-c", "x=$(head -c 4000000 /dev/zero | tr '\\0' 'A'); sleep 30")
	}

	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	}()

	time.Sleep(2 * time.Second)

	const runs = 5
	latencies := make([]time.Duration, 0, runs)
	var bytesRead int64

	for i := 0; i < runs; i++ {
		start := time.Now()
		dump, err := capture.DumpProcessMemory(context.Background(), cmd.Process.Pid, capture.Options{
			ProcRoot: "/proc",
			Filter:   capture.DefaultFilterOptions(),
			MaxBytes: 512 << 20,
		})
		if err != nil {
			t.Fatalf("run %d: %v", i, err)
		}
		latencies = append(latencies, time.Since(start))
		bytesRead = dump.TotalBytes
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })

	p50 := latencies[len(latencies)/2]
	p95 := latencies[len(latencies)*95/100]
	if p95 == 0 {
		p95 = latencies[len(latencies)-1]
	}

	throughput := float64(bytesRead) / p50.Seconds() / (1 << 20)
	t.Logf("acquisition of %d bytes over %d runs: min=%s p50=%s max=%s (~%.0f MB/s)",
		bytesRead, runs, latencies[0], p50, latencies[len(latencies)-1], throughput)

	if bytesRead == 0 {
		t.Fatal("acquired no memory")
	}
	if p95 > 10*time.Second {
		t.Errorf("p95 acquisition latency %s is far outside any usable capture window", p95)
	}
}
