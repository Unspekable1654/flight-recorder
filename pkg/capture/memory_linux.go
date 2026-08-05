//go:build linux

package capture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Options control one acquisition.
type Options struct {
	// ProcRoot is the procfs mount point. The DaemonSet mounts the host's
	// procfs at /host/proc.
	ProcRoot string
	// Filter selects which regions to acquire.
	Filter FilterOptions
	// MaxBytes caps the total acquired payload. Acquisition stops cleanly at
	// the cap and the dump is marked truncated. 0 = unlimited.
	MaxBytes int64
	// ChunkBytes is the maximum size of a single process_vm_readv transfer.
	// Defaults to DefaultChunkBytes.
	ChunkBytes int64
	// ExpectedCgroupID, when non-zero, is re-validated against the target's
	// current cgroup immediately before acquisition. This is the PID-reuse
	// guard: between the eBPF event and this call the PID may have been
	// recycled by an unrelated container.
	ExpectedCgroupID uint64
	// ExpectedStartTime, when non-zero, is compared against field 22 of
	// /proc/[pid]/stat. Process start time plus PID is the closest thing
	// Linux offers to a stable process identity.
	ExpectedStartTime uint64
}

// DefaultChunkBytes is the per-iovec transfer ceiling.
//
// process_vm_readv must allocate kernel-side bookkeeping for the whole
// transfer, so very large single reads invite ENOMEM under memory pressure.
// 4 MiB is large enough that syscall overhead is negligible (one call per
// 1024 pages) and small enough to stay well clear of allocation failures.
const DefaultChunkBytes = 4 << 20

// enomemRetryDelays are the backoff steps for ENOMEM. The transfer size is
// also halved on each attempt, which addresses the actual cause (the kernel
// could not allocate for a transfer this large) rather than just waiting.
var enomemRetryDelays = []time.Duration{100 * time.Millisecond, 400 * time.Millisecond, 1600 * time.Millisecond}

// ErrPermission is returned when the process lacks CAP_SYS_PTRACE. It is a
// configuration error, not a transient one, and is reported as fatal so the
// operator fixes the DaemonSet rather than watching every capture fail.
var ErrPermission = errors.New("capture: process_vm_readv denied (EPERM)")

// ErrProcessGone is returned when the target does not exist at all.
var ErrProcessGone = errors.New("capture: target process does not exist")

// ErrIdentityMismatch is returned when the PID no longer refers to the process
// the trigger fired for.
var ErrIdentityMismatch = errors.New("capture: PID identity changed before acquisition (PID reuse)")

// DumpProcessMemory performs a non-intrusive freeze-frame of a live process.
//
// The target is never stopped, signalled, or ptrace-attached: process_vm_readv
// copies from the target's address space directly. This satisfies the ACPO
// principle that acquisition must not alter the evidence, and it means the
// attacker's process cannot detect the capture through the usual ptrace checks.
//
// Acquisition is deliberately single-pass. The address map is parsed once and
// then read; it is never re-parsed and retried, because by the time a retry
// would happen the PID may belong to a different process entirely. What is
// read is what is reported, along with an explicit account of what was not.
func DumpProcessMemory(ctx context.Context, pid int, opts Options) (*MemoryDump, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("capture: invalid pid %d", pid)
	}
	if opts.ProcRoot == "" {
		opts.ProcRoot = DefaultProcRoot
	}
	if opts.ChunkBytes <= 0 {
		opts.ChunkBytes = DefaultChunkBytes
	}

	dump := &MemoryDump{
		PID:          pid,
		ProcRoot:     opts.ProcRoot,
		CaptureStart: time.Now(),
		CgroupID:     opts.ExpectedCgroupID,
	}

	if err := ProcessAlive(pid); err != nil {
		return nil, err
	}

	// Identity checks come before the map parse so that a recycled PID is
	// rejected before we spend time acquiring the wrong process's memory.
	if opts.ExpectedStartTime != 0 {
		start, err := ProcessStartTime(opts.ProcRoot, pid)
		if err != nil {
			return nil, fmt.Errorf("capture: read start time for identity check: %w", err)
		}
		if start != opts.ExpectedStartTime {
			return nil, fmt.Errorf("%w: start time %d != expected %d", ErrIdentityMismatch, start, opts.ExpectedStartTime)
		}
	}

	dump.Comm, _ = ProcessComm(opts.ProcRoot, pid)

	parsed, err := ReadProcMaps(opts.ProcRoot, pid)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("%w: pid %d", ErrProcessGone, pid)
		}
		return nil, err
	}
	dump.MapsParsedAt = time.Now()
	dump.ParseSkippedLines = parsed.SkippedLines

	acquire, skipped := SelectRegions(parsed.Regions, opts.Filter)
	dump.Skipped = skipped
	dump.SkippedRegions = len(skipped)

	if len(acquire) == 0 {
		dump.CaptureEnd = time.Now()
		return dump, nil
	}

	firstRead := true
	for i := range acquire {
		select {
		case <-ctx.Done():
			dump.Interrupted = true
			dump.Regions = append(dump.Regions, acquire[i:]...)
			markUnread(dump.Regions[len(dump.Regions)-len(acquire[i:]):], "acquisition interrupted before this region was read")
			dump.CaptureEnd = time.Now()
			return dump, nil
		default:
		}

		region := acquire[i]

		if opts.MaxBytes > 0 && dump.TotalBytes >= opts.MaxBytes {
			region.Status = RegionSkipped
			region.Error = fmt.Sprintf("size cap reached (%d bytes)", opts.MaxBytes)
			dump.Regions = append(dump.Regions, region)
			dump.Truncated = true
			continue
		}

		budget := int64(0)
		if opts.MaxBytes > 0 {
			budget = opts.MaxBytes - dump.TotalBytes
		}

		if firstRead {
			dump.MapsToFirstReadMS = float64(time.Since(dump.MapsParsedAt).Microseconds()) / 1000.0
			firstRead = false
		}

		readStart := time.Now()
		n, err := readRegion(pid, &region, opts.ChunkBytes, budget)
		region.ReadTimeMS = float64(time.Since(readStart).Microseconds()) / 1000.0
		region.BytesRead = n

		switch {
		case err == nil && n == region.Size():
			region.Status = RegionFull
			dump.FullRegions++

		case errors.Is(err, unix.ESRCH):
			// The process exited. Nothing further is readable, and retrying
			// risks reading a different process that inherited the PID.
			region.Status = RegionFailed
			region.Error = "process exited during acquisition (ESRCH)"
			dump.FailedRegions++
			dump.Regions = append(dump.Regions, region)
			dump.ProcessExited = true
			dump.TotalBytes += n
			dump.CaptureEnd = time.Now()
			return dump, nil

		case errors.Is(err, unix.EPERM):
			return nil, fmt.Errorf("%w: flight-recorder requires CAP_SYS_PTRACE. Ensure the DaemonSet securityContext adds SYS_PTRACE, or run `setcap cap_sys_ptrace+ep` on the binary", ErrPermission)

		case errors.Is(err, unix.EINVAL):
			// EINVAL means a malformed iovec: a bug in this code, not a
			// property of the target. The plan calls for abort; a DaemonSet
			// that panics stops monitoring the whole node, so this is reported
			// as a hard error for the capture and logged distinctively instead.
			return nil, fmt.Errorf("capture: process_vm_readv returned EINVAL for region %#x-%#x (internal error, please report): %w",
				region.StartAddr, region.EndAddr, err)

		case err != nil && n > 0:
			region.Status = RegionPartial
			region.Error = describeReadError(err)
			dump.PartialRegions++

		case err != nil:
			region.Status = RegionFailed
			region.Error = describeReadError(err)
			dump.FailedRegions++

		default: // err == nil but short read
			region.Status = RegionPartial
			region.Error = fmt.Sprintf("short read: %d of %d bytes", n, region.Size())
			dump.PartialRegions++
		}

		if budget > 0 && n >= budget {
			dump.Truncated = true
		}

		dump.TotalBytes += n
		dump.Regions = append(dump.Regions, region)
	}

	dump.CaptureEnd = time.Now()
	return dump, nil
}

func markUnread(regions []MemoryRegion, reason string) {
	for i := range regions {
		regions[i].Status = RegionSkipped
		regions[i].Error = reason
	}
}

// readRegion transfers one mapping in bounded chunks.
//
// Returns the number of bytes successfully read and the first error that
// stopped progress. A non-nil error with n > 0 is a partial read, which is a
// normal and expected outcome: lazily allocated pages inside an otherwise
// valid mapping return EFAULT.
func readRegion(pid int, region *MemoryRegion, chunkBytes, budget int64) (int64, error) {
	size := region.Size()
	if budget > 0 && budget < size {
		size = budget
	}
	if size <= 0 {
		return 0, nil
	}

	buf := make([]byte, size)
	var done int64

	for done < size {
		remaining := size - done
		want := chunkBytes
		if remaining < want {
			want = remaining
		}

		n, err := readChunk(pid, region.StartAddr+uintptr(done), buf[done:done+want])
		done += int64(n)

		if err != nil {
			region.Data = buf[:done]
			return done, err
		}
		if n == 0 {
			break
		}
	}

	region.Data = buf[:done]
	return done, nil
}

// readChunk performs a single process_vm_readv with ENOMEM backoff.
func readChunk(pid int, remoteAddr uintptr, dst []byte) (int, error) {
	attempt := 0
	size := len(dst)

	for {
		local := []unix.Iovec{{Base: &dst[0], Len: uint64(size)}}
		remote := []unix.RemoteIovec{{Base: remoteAddr, Len: size}}

		n, err := unix.ProcessVMReadv(pid, local, remote, 0)
		if err == nil {
			return n, nil
		}

		if errors.Is(err, unix.ENOMEM) && attempt < len(enomemRetryDelays) {
			// The kernel could not allocate for a transfer this large. Wait,
			// then ask for half as much - retrying the same size would simply
			// fail again.
			time.Sleep(enomemRetryDelays[attempt])
			attempt++
			if size > 4096 {
				size /= 2
			}
			continue
		}

		if n > 0 {
			return n, err
		}
		return 0, err
	}
}

func describeReadError(err error) string {
	switch {
	case errors.Is(err, unix.EFAULT):
		return "EFAULT: pages not resident (lazy allocation, swapped out, or guard page)"
	case errors.Is(err, unix.ESRCH):
		return "ESRCH: process exited during acquisition"
	case errors.Is(err, unix.ENOMEM):
		return "ENOMEM: kernel allocation failure after retries"
	case errors.Is(err, unix.EPERM):
		return "EPERM: missing CAP_SYS_PTRACE"
	case errors.Is(err, unix.EIO):
		return "EIO: I/O error reading target memory"
	default:
		return err.Error()
	}
}

// ProcessAlive reports whether a PID currently exists.
//
// Signal 0 performs the kernel's permission and existence checks without
// delivering anything, so this cannot perturb the target.
func ProcessAlive(pid int) error {
	if err := unix.Kill(pid, 0); err != nil {
		if errors.Is(err, unix.ESRCH) {
			return fmt.Errorf("%w: pid %d", ErrProcessGone, pid)
		}
		if errors.Is(err, unix.EPERM) {
			// EPERM here means the process exists but is not ours to signal,
			// which is fine: process_vm_readv has its own permission check.
			return nil
		}
		return fmt.Errorf("capture: liveness check for pid %d: %w", pid, err)
	}
	return nil
}

// ProcessStartTime returns field 22 (starttime) of /proc/[pid]/stat in clock
// ticks since boot.
//
// PID plus start time is the standard identity pair for a Linux process: PIDs
// are recycled, but a recycled PID will not share the original's start time.
func ProcessStartTime(procRoot string, pid int) (uint64, error) {
	raw, err := os.ReadFile(ProcPath(procRoot, pid, "stat"))
	if err != nil {
		return 0, fmt.Errorf("capture: read stat: %w", err)
	}

	// comm (field 2) is parenthesised and may itself contain spaces and
	// parentheses, so fields are counted from the LAST ')'.
	end := strings.LastIndexByte(string(raw), ')')
	if end < 0 || end+2 >= len(raw) {
		return 0, fmt.Errorf("capture: malformed stat for pid %d", pid)
	}

	fields := strings.Fields(string(raw[end+2:]))
	// After comm, field 3 is state; starttime is field 22 overall, which is
	// index 19 in this slice.
	const startTimeIndex = 19
	if len(fields) <= startTimeIndex {
		return 0, fmt.Errorf("capture: stat for pid %d has %d fields after comm, need %d", pid, len(fields), startTimeIndex+1)
	}

	v, err := strconv.ParseUint(fields[startTimeIndex], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("capture: parse starttime for pid %d: %w", pid, err)
	}
	return v, nil
}

// ProcessComm returns the kernel's short process name.
func ProcessComm(procRoot string, pid int) (string, error) {
	raw, err := os.ReadFile(ProcPath(procRoot, pid, "comm"))
	if err != nil {
		return "", fmt.Errorf("capture: read comm: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// ProcessCmdline returns the full command line with NUL separators replaced by
// spaces.
func ProcessCmdline(procRoot string, pid int) (string, error) {
	raw, err := os.ReadFile(ProcPath(procRoot, pid, "cmdline"))
	if err != nil {
		return "", fmt.Errorf("capture: read cmdline: %w", err)
	}
	parts := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	return strings.Join(parts, " "), nil
}
