//go:build !linux

package probe

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"
)

// ErrUnsupportedPlatform is returned by the loader on non-Linux builds.
//
// The package still compiles everywhere so that the decoder, the rule engine
// and the whole evidence pipeline can be developed and tested off-Linux. Only
// the kernel attachment is platform-bound.
var ErrUnsupportedPlatform = errors.New("probe: eBPF requires Linux")

// LoadOptions mirrors the Linux definition. See loader_linux.go.
type LoadOptions struct {
	PinPath      string
	TrackExits   bool
	Prefilter    bool
	TriggerComms []string
	MinUID       uint32
	SelfTGID     uint32
	RingbufSize  int
}

// Probe is a non-functional placeholder on this platform.
type Probe struct{}

// Load always fails on non-Linux platforms.
func Load(LoadOptions) (*Probe, error) {
	return nil, fmt.Errorf("%w (running on %s/%s)", ErrUnsupportedPlatform, runtime.GOOS, runtime.GOARCH)
}

// Reused reports whether pinned links were reused. Always false here.
func (p *Probe) Reused() bool { return false }

// SetTriggerComms is unavailable on this platform.
func (p *Probe) SetTriggerComms([]string) error { return ErrUnsupportedPlatform }

// SetPrefilterEnabled is unavailable on this platform.
func (p *Probe) SetPrefilterEnabled(bool, uint32, uint32, bool) error { return ErrUnsupportedPlatform }

// Stats is unavailable on this platform.
func (p *Probe) Stats() (Stats, error) { return Stats{}, ErrUnsupportedPlatform }

// LostRecords is unavailable on this platform.
func (p *Probe) LostRecords() uint64 { return 0 }

// Events returns an immediately closed channel.
func (p *Probe) Events(context.Context, int) <-chan Event {
	ch := make(chan Event)
	close(ch)
	return ch
}

// Close is a no-op.
func (p *Probe) Close() error { return nil }

// Unpin is a no-op.
func (p *Probe) Unpin() error { return nil }

// BootWallClock approximates the boot time reference used for timestamps.
func BootWallClock() (time.Time, error) { return time.Now(), ErrUnsupportedPlatform }

// KernelVersion reports the platform, since no Linux kernel is present.
func KernelVersion() string { return runtime.GOOS + "-" + runtime.GOARCH }
