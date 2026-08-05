//go:build !linux

package capture

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// ErrUnsupportedPlatform is returned by acquisition entry points on non-Linux
// builds.
//
// The package still compiles and its parser, filter and sealing paths still run
// everywhere, which is what lets the unit and fuzz suites execute on a
// developer's macOS or Windows machine. Only the syscall itself is Linux-only.
var ErrUnsupportedPlatform = errors.New("capture: live memory acquisition requires Linux (process_vm_readv)")

// Options control one acquisition. See memory_linux.go for the semantics of
// each field.
type Options struct {
	ProcRoot          string
	Filter            FilterOptions
	MaxBytes          int64
	ChunkBytes        int64
	ExpectedCgroupID  uint64
	ExpectedStartTime uint64
}

// DefaultChunkBytes is the per-transfer ceiling used on Linux.
const DefaultChunkBytes = 4 << 20

// ErrPermission mirrors the Linux error for cross-platform error handling.
var ErrPermission = errors.New("capture: process_vm_readv denied (EPERM)")

// ErrProcessGone mirrors the Linux error for cross-platform error handling.
var ErrProcessGone = errors.New("capture: target process does not exist")

// ErrIdentityMismatch mirrors the Linux error for cross-platform error handling.
var ErrIdentityMismatch = errors.New("capture: PID identity changed before acquisition (PID reuse)")

// DumpProcessMemory is unavailable on this platform.
func DumpProcessMemory(_ context.Context, pid int, _ Options) (*MemoryDump, error) {
	_ = time.Now
	return nil, fmt.Errorf("%w (pid %d)", ErrUnsupportedPlatform, pid)
}

// ProcessAlive is unavailable on this platform.
func ProcessAlive(pid int) error {
	return fmt.Errorf("%w (pid %d)", ErrUnsupportedPlatform, pid)
}

// ProcessStartTime is unavailable on this platform.
func ProcessStartTime(_ string, pid int) (uint64, error) {
	return 0, fmt.Errorf("%w (pid %d)", ErrUnsupportedPlatform, pid)
}

// ProcessComm reads /proc/[pid]/comm if a procfs-like tree is available.
func ProcessComm(procRoot string, pid int) (string, error) {
	raw, err := os.ReadFile(ProcPath(procRoot, pid, "comm"))
	if err != nil {
		return "", fmt.Errorf("capture: read comm: %w", err)
	}
	return strings.TrimSpace(string(raw)), nil
}

// ProcessCmdline reads /proc/[pid]/cmdline if a procfs-like tree is available.
func ProcessCmdline(procRoot string, pid int) (string, error) {
	raw, err := os.ReadFile(ProcPath(procRoot, pid, "cmdline"))
	if err != nil {
		return "", fmt.Errorf("capture: read cmdline: %w", err)
	}
	parts := strings.Split(strings.TrimRight(string(raw), "\x00"), "\x00")
	return strings.Join(parts, " "), nil
}
