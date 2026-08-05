// Package probe loads the eBPF programs, consumes the ring buffer, and decodes
// kernel records into Go values.
//
// Everything in this file is portable: decoding is pure byte manipulation, so
// the wire format between kernel and userspace can be tested on any platform.
// The loader itself (loader_linux.go) is Linux-only.
package probe

import (
	"encoding/binary"
	"fmt"
	"strings"
	"time"
)

// Wire format constants. These MUST match bpf/headers/common.h.
const (
	// EventSize is the exact size of struct fr_event.
	EventSize = 448

	taskCommLen = 16
	filenameLen = 128
	argsLen     = 256

	offKind        = 0
	offHostPID     = 4
	offNSPid       = 8
	offHostTGID    = 12
	offUID         = 16
	offNSLevel     = 20
	offArgsLen     = 24
	offArgsCount   = 28
	offCgroupID    = 32
	offTimestampNS = 40
	offComm        = 48
	offFilename    = 64
	offArgs        = 192
)

// Kind distinguishes the lifecycle transitions the probes report.
type Kind uint32

// Event kinds, matching FR_EVENT_* in common.h.
const (
	KindExec Kind = 1
	KindExit Kind = 2
)

// String renders the kind for logs and metric labels.
func (k Kind) String() string {
	switch k {
	case KindExec:
		return "exec"
	case KindExit:
		return "exit"
	default:
		return fmt.Sprintf("unknown(%d)", uint32(k))
	}
}

// Event is one decoded kernel record.
type Event struct {
	Kind         Kind
	HostPID      uint32
	NamespacePID uint32
	HostTGID     uint32
	UID          uint32
	NSLevel      uint32
	CgroupID     uint64
	// TimestampNS is CLOCK_BOOTTIME nanoseconds. A monotonic clock source is
	// required: wall-clock time can jump backwards under NTP correction, and a
	// forensic timeline that goes backwards is worthless.
	TimestampNS uint64
	Comm        string
	Filename    string
	Args        []string
	// ReceivedAt is the userspace wall-clock time the record was decoded. The
	// pair (TimestampNS, ReceivedAt) is what makes the kernel-to-userspace
	// latency measurable.
	ReceivedAt time.Time
}

// ErrShortEvent is returned when a ring buffer record is too small to decode.
type ErrShortEvent struct {
	Got  int
	Want int
}

func (e ErrShortEvent) Error() string {
	return fmt.Sprintf("probe: ring buffer record is %d bytes, need %d", e.Got, e.Want)
}

// DecodeEvent parses a raw ring buffer record.
//
// Records are read little-endian: the eBPF object is compiled for bpfel, which
// covers amd64 and arm64. A big-endian target would need a separate object and
// a decoder switch, which is why the assumption is stated here rather than
// buried in a struct tag.
func DecodeEvent(raw []byte) (Event, error) {
	if len(raw) < EventSize {
		return Event{}, ErrShortEvent{Got: len(raw), Want: EventSize}
	}

	e := Event{
		Kind:         Kind(binary.LittleEndian.Uint32(raw[offKind:])),
		HostPID:      binary.LittleEndian.Uint32(raw[offHostPID:]),
		NamespacePID: binary.LittleEndian.Uint32(raw[offNSPid:]),
		HostTGID:     binary.LittleEndian.Uint32(raw[offHostTGID:]),
		UID:          binary.LittleEndian.Uint32(raw[offUID:]),
		NSLevel:      binary.LittleEndian.Uint32(raw[offNSLevel:]),
		CgroupID:     binary.LittleEndian.Uint64(raw[offCgroupID:]),
		TimestampNS:  binary.LittleEndian.Uint64(raw[offTimestampNS:]),
		Comm:         cString(raw[offComm : offComm+taskCommLen]),
		Filename:     cString(raw[offFilename : offFilename+filenameLen]),
		ReceivedAt:   time.Now(),
	}

	argsUsed := int(binary.LittleEndian.Uint32(raw[offArgsLen:]))
	if argsUsed > argsLen {
		argsUsed = argsLen
	}
	if argsUsed > 0 {
		e.Args = splitNulStrings(raw[offArgs : offArgs+argsUsed])
	}

	return e, nil
}

// cString converts a NUL-terminated, fixed-width C string.
func cString(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// splitNulStrings splits the packed argv buffer on NUL separators.
func splitNulStrings(b []byte) []string {
	var out []string
	start := 0
	for i := 0; i < len(b); i++ {
		if b[i] == 0 {
			if i > start {
				out = append(out, string(b[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}

// CommandLine reconstructs the command line the rule engine matches against.
//
// The eBPF probe copies at most four argv entries of 64 bytes each, so this is
// a prefix of the true command line, not the whole of it. That bound is a
// verifier and ring-buffer-bandwidth trade-off, and it is why rules match on
// substrings rather than requiring a full command.
func (e Event) CommandLine() string {
	if len(e.Args) > 0 {
		return strings.Join(e.Args, " ")
	}
	if e.Filename != "" {
		return e.Filename
	}
	return e.Comm
}

// Truncated reports whether the argv capture likely lost content.
func (e Event) Truncated() bool { return len(e.Args) >= 4 }

// BootTime converts the monotonic kernel timestamp to wall-clock time using a
// boot-time reference established once at startup.
func (e Event) BootTime(bootWallClock time.Time) time.Time {
	return bootWallClock.Add(time.Duration(e.TimestampNS))
}

// Stats are the kernel-side counters read from the stats map.
type Stats struct {
	ExecSeen       uint64 `json:"exec_seen"`
	ExecSubmitted  uint64 `json:"exec_submitted"`
	RingbufDropped uint64 `json:"ringbuf_dropped"`
	ExitSubmitted  uint64 `json:"exit_submitted"`
}

// Stat map slot indices, matching FR_STAT_* in common.h.
const (
	statExecSeen       = 0
	statExecSubmitted  = 1
	statRingbufDropped = 2
	statExitSubmitted  = 3
	statCount          = 4
)

// Config mirrors struct fr_config in common.h.
type Config struct {
	SelfTGID   uint32
	Prefilter  uint32
	TrackExits uint32
	MinUID     uint32
}
