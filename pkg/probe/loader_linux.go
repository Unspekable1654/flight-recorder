//go:build linux

package probe

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"
)

// The eBPF object is generated from bpf/recorder.c by bpf2go. Only a
// little-endian target is produced: amd64 and arm64, the two architectures
// Kubernetes nodes actually run, are both little-endian. Adding bpfeb would
// double the build matrix for no deployed platform.
//
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package probe -target bpfel -no-strip -cc $BPF_CLANG -cflags $BPF_CFLAGS recorder ../../bpf/recorder.c -- -I../../bpf -I../../bpf/include

// LoadOptions configure probe loading.
type LoadOptions struct {
	// PinPath is a bpffs directory (typically /sys/fs/bpf/flight-recorder).
	// When set, maps, programs and links are pinned there so that a restart
	// re-attaches to the running programs instead of leaving a monitoring gap
	// during a DaemonSet rolling update. Empty disables pinning.
	PinPath string
	// TrackExits enables the sched_process_exit probe.
	TrackExits bool
	// Prefilter enables the kernel-side comm allowlist.
	Prefilter bool
	// TriggerComms populates the prefilter map.
	TriggerComms []string
	// MinUID drops events from users below this uid. 0 keeps everything.
	MinUID uint32
	// SelfTGID is excluded from monitoring so the recorder never captures
	// itself and cannot be driven into a feedback loop.
	SelfTGID uint32
	// RingbufSize is informational only: the ring buffer size is fixed in the
	// BPF object at 16 MiB, because BPF map sizes are compile-time constants.
	RingbufSize int
}

// Probe owns the loaded eBPF objects and their attachments.
type Probe struct {
	objs   recorderObjects
	links  []link.Link
	reader *ringbuf.Reader

	pinPath  string
	reused   bool
	closed   atomic.Bool
	lostRecs atomic.Uint64
}

// Load loads the eBPF programs, attaches them, and opens the ring buffer.
//
// Failure modes are reported with the operational remedy attached, because
// every one of them is a deployment problem rather than a bug: missing
// capabilities, missing BTF, or a kernel too old for BPF ring buffers.
func Load(opts LoadOptions) (*Probe, error) {
	// The kernel accounts BPF maps against RLIMIT_MEMLOCK on kernels before
	// 5.11. A 16 MiB ring buffer exceeds the usual 64 KiB default, so the
	// limit is raised before loading.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("probe: raise RLIMIT_MEMLOCK: %w (flight-recorder needs CAP_SYS_RESOURCE, or kernel 5.11+ which accounts BPF memory to the cgroup instead)", err)
	}

	p := &Probe{pinPath: opts.PinPath}

	collectionOpts := ebpf.CollectionOptions{}
	if opts.PinPath != "" {
		if err := ensureBPFFS(opts.PinPath); err != nil {
			return nil, err
		}
		collectionOpts.Maps.PinPath = opts.PinPath
	}

	if err := loadRecorderObjects(&p.objs, &collectionOpts); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			// The verifier log is the only useful artefact when a program is
			// rejected, and it is truncated by default. Print it in full.
			return nil, fmt.Errorf("probe: eBPF verifier rejected the program: %+v", verr)
		}
		if errors.Is(err, unix.EPERM) {
			return nil, fmt.Errorf("probe: loading eBPF was denied: %w (needs CAP_BPF and CAP_PERFMON on kernel 5.8+, or CAP_SYS_ADMIN on older kernels)", err)
		}
		return nil, fmt.Errorf("probe: load eBPF objects: %w", err)
	}

	if err := p.configure(opts); err != nil {
		p.objs.Close()
		return nil, err
	}

	if err := p.attach(opts); err != nil {
		p.objs.Close()
		return nil, err
	}

	reader, err := ringbuf.NewReader(p.objs.Events)
	if err != nil {
		p.detach()
		p.objs.Close()
		return nil, fmt.Errorf("probe: open ring buffer reader: %w (BPF_MAP_TYPE_RINGBUF requires kernel 5.8+)", err)
	}
	p.reader = reader

	return p, nil
}

func (p *Probe) configure(opts LoadOptions) error {
	cfg := Config{
		SelfTGID: opts.SelfTGID,
		MinUID:   opts.MinUID,
	}
	if opts.Prefilter && len(opts.TriggerComms) > 0 {
		cfg.Prefilter = 1
	}
	if opts.TrackExits {
		cfg.TrackExits = 1
	}

	if err := p.objs.FrConfigMap.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("probe: write config map: %w", err)
	}
	if len(opts.TriggerComms) > 0 {
		if err := p.SetTriggerComms(opts.TriggerComms); err != nil {
			return err
		}
	}
	return nil
}

func (p *Probe) attach(opts LoadOptions) error {
	type attachment struct {
		group   string
		name    string
		prog    *ebpf.Program
		pinName string
		enabled bool
	}

	attachments := []attachment{
		{group: "syscalls", name: "sys_enter_execve", prog: p.objs.FrTraceExecve, pinName: "link_execve", enabled: true},
		{group: "sched", name: "sched_process_exit", prog: p.objs.FrTraceExit, pinName: "link_exit", enabled: opts.TrackExits},
	}

	for _, a := range attachments {
		if !a.enabled {
			continue
		}

		if p.pinPath != "" {
			pin := filepath.Join(p.pinPath, a.pinName)
			if existing, err := link.LoadPinnedLink(pin, nil); err == nil {
				// A previous instance is still attached. Reusing its link is
				// what makes a rolling restart gapless.
				p.links = append(p.links, existing)
				p.reused = true
				continue
			}
		}

		l, err := link.Tracepoint(a.group, a.name, a.prog, nil)
		if err != nil {
			p.detach()
			return fmt.Errorf("probe: attach tracepoint %s/%s: %w (verify it exists: cat /sys/kernel/debug/tracing/available_events | grep %s)", a.group, a.name, err, a.name)
		}

		if p.pinPath != "" {
			pin := filepath.Join(p.pinPath, a.pinName)
			_ = os.Remove(pin)
			if err := l.Pin(pin); err != nil {
				// Pinning is an availability optimisation, not a correctness
				// requirement. A kernel without bpf_link pinning (pre-5.7)
				// still monitors correctly, it just loses events during a
				// restart.
				_ = err
			}
		}

		p.links = append(p.links, l)
	}

	if len(p.links) == 0 {
		return errors.New("probe: no tracepoints were attached")
	}
	return nil
}

func (p *Probe) detach() {
	for _, l := range p.links {
		_ = l.Close()
	}
	p.links = nil
}

// Reused reports whether the probe re-attached to pinned links from a previous
// process, meaning no events were missed across the restart.
func (p *Probe) Reused() bool { return p.reused }

// SetTriggerComms replaces the kernel-side prefilter allowlist.
//
// Called on config reload. Entries are truncated to 15 characters plus NUL,
// matching the kernel's TASK_COMM_LEN.
func (p *Probe) SetTriggerComms(comms []string) error {
	// Clear entries that are no longer configured.
	var key [taskCommLen]byte
	iter := p.objs.TriggerComms.Iterate()
	var existing [][taskCommLen]byte
	var value uint8
	for iter.Next(&key, &value) {
		existing = append(existing, key)
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("probe: iterate prefilter map: %w", err)
	}

	wanted := make(map[[taskCommLen]byte]struct{}, len(comms))
	for _, c := range comms {
		var k [taskCommLen]byte
		copy(k[:taskCommLen-1], c)
		wanted[k] = struct{}{}
	}

	for _, k := range existing {
		if _, keep := wanted[k]; !keep {
			if err := p.objs.TriggerComms.Delete(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
				return fmt.Errorf("probe: delete prefilter entry: %w", err)
			}
		}
	}

	for k := range wanted {
		if err := p.objs.TriggerComms.Put(k, uint8(1)); err != nil {
			return fmt.Errorf("probe: write prefilter entry: %w", err)
		}
	}
	return nil
}

// SetPrefilterEnabled toggles kernel-side filtering without reloading.
func (p *Probe) SetPrefilterEnabled(enabled bool, selfTGID, minUID uint32, trackExits bool) error {
	cfg := Config{SelfTGID: selfTGID, MinUID: minUID}
	if enabled {
		cfg.Prefilter = 1
	}
	if trackExits {
		cfg.TrackExits = 1
	}
	if err := p.objs.FrConfigMap.Put(uint32(0), cfg); err != nil {
		return fmt.Errorf("probe: update config map: %w", err)
	}
	return nil
}

// Stats reads the kernel-side counters.
func (p *Probe) Stats() (Stats, error) {
	var s Stats
	values := make([]uint64, statCount)
	for i := 0; i < statCount; i++ {
		var v uint64
		if err := p.objs.Stats.Lookup(uint32(i), &v); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				continue
			}
			return s, fmt.Errorf("probe: read stats slot %d: %w", i, err)
		}
		values[i] = v
	}

	s.ExecSeen = values[statExecSeen]
	s.ExecSubmitted = values[statExecSubmitted]
	s.RingbufDropped = values[statRingbufDropped]
	s.ExitSubmitted = values[statExitSubmitted]
	return s, nil
}

// LostRecords returns the number of ring buffer records userspace failed to
// decode (as opposed to those the kernel could not enqueue).
func (p *Probe) LostRecords() uint64 { return p.lostRecs.Load() }

// Events streams decoded events until ctx is cancelled or the probe is closed.
//
// The returned channel is closed when reading stops. The reader goroutine
// never blocks on the consumer for longer than the channel buffer allows:
// blocking here would let the kernel ring buffer fill and drop events, which
// is the one failure this design exists to avoid. Callers that cannot keep up
// must drop in their own layer, where the drop can be counted and audited.
func (p *Probe) Events(ctx context.Context, buffer int) <-chan Event {
	if buffer <= 0 {
		buffer = 1024
	}
	out := make(chan Event, buffer)

	go func() {
		defer close(out)

		// Unblocking Read on context cancellation: ringbuf.Reader.Read only
		// returns on data or Close, so cancellation closes the reader.
		go func() {
			<-ctx.Done()
			_ = p.reader.Close()
		}()

		for {
			record, err := p.reader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, os.ErrClosed) {
					return
				}
				if ctx.Err() != nil {
					return
				}
				// A malformed record is not a reason to stop monitoring.
				p.lostRecs.Add(1)
				continue
			}

			event, err := DecodeEvent(record.RawSample)
			if err != nil {
				p.lostRecs.Add(1)
				continue
			}

			select {
			case out <- event:
			case <-ctx.Done():
				return
			default:
				// Consumer is behind. Dropping here, in userspace, is
				// preferable to back-pressuring the kernel ring buffer.
				p.lostRecs.Add(1)
			}
		}
	}()

	return out
}

// Close detaches the probes and releases all resources.
//
// Pinned links are deliberately left in place when pinning is enabled: they
// are what allows the next process to re-attach without a monitoring gap.
// Unpin explicitly to stop monitoring entirely.
func (p *Probe) Close() error {
	if p.closed.Swap(true) {
		return nil
	}

	var firstErr error
	if p.reader != nil {
		if err := p.reader.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			firstErr = err
		}
	}
	p.detach()
	if err := p.objs.Close(); err != nil && firstErr == nil {
		firstErr = err
	}
	return firstErr
}

// Unpin removes pinned links, maps and programs, stopping monitoring
// completely.
func (p *Probe) Unpin() error {
	if p.pinPath == "" {
		return nil
	}
	entries, err := os.ReadDir(p.pinPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("probe: read pin directory: %w", err)
	}
	for _, e := range entries {
		if err := os.Remove(filepath.Join(p.pinPath, e.Name())); err != nil {
			return fmt.Errorf("probe: unpin %s: %w", e.Name(), err)
		}
	}
	return nil
}

// ensureBPFFS verifies that the pin directory lives on a bpffs mount and
// creates it if necessary. Pinning to a normal filesystem silently fails in
// confusing ways, so the filesystem type is checked explicitly.
func ensureBPFFS(path string) error {
	parent := filepath.Dir(path)

	var st unix.Statfs_t
	if err := unix.Statfs(parent, &st); err != nil {
		return fmt.Errorf("probe: statfs %s: %w (is /sys/fs/bpf mounted?)", parent, err)
	}
	if st.Type != unix.BPF_FS_MAGIC {
		return fmt.Errorf("probe: %s is not on a bpffs mount (found fs type %#x); mount it with: mount -t bpf bpf /sys/fs/bpf", parent, st.Type)
	}

	if err := os.MkdirAll(path, 0o700); err != nil {
		return fmt.Errorf("probe: create pin directory %s: %w", path, err)
	}
	return nil
}

// BootWallClock estimates the wall-clock time of system boot, used to convert
// the probes' CLOCK_BOOTTIME timestamps into absolute times.
//
// It is computed once at startup rather than per event: reading the clock twice
// per event would add measurable overhead to the hot path, and the drift over a
// capture window is far below the precision anyone claims for these timestamps.
func BootWallClock() (time.Time, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &ts); err != nil {
		return time.Time{}, fmt.Errorf("probe: read CLOCK_BOOTTIME: %w", err)
	}
	return time.Now().Add(-time.Duration(ts.Nano())), nil
}

// KernelVersion returns the running kernel release string, recorded in every
// evidence bundle as part of the acquisition environment.
func KernelVersion() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return "unknown"
	}
	return unix.ByteSliceToString(uts.Release[:])
}
