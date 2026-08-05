// Package capture implements the freeze-frame: non-intrusive extraction of a
// live process's virtual memory.
//
// The two halves of the problem are separated deliberately. procmaps.go parses
// /proc/[pid]/maps and is pure, portable Go with no syscalls, so it can be unit
// tested and fuzzed on any platform. memory.go performs the actual
// process_vm_readv(2) and is Linux-only.
//
// The parser is treated as attacker-exposed input. A compromised process can
// influence the contents of its own maps file (long pathnames, unusual
// characters, FUSE mounts), so the parser must be total: it skips what it
// cannot understand and never panics. FuzzParseProcMaps enforces that.
package capture

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// RegionStatus records the acquisition outcome for one memory region.
type RegionStatus string

const (
	// RegionFull means every requested byte was read.
	RegionFull RegionStatus = "full"
	// RegionPartial means the kernel returned fewer bytes than requested.
	RegionPartial RegionStatus = "partial"
	// RegionFailed means no bytes could be read (typically EFAULT on
	// non-resident, lazily allocated pages).
	RegionFailed RegionStatus = "failed"
	// RegionSkipped means the filter excluded the region before any read.
	RegionSkipped RegionStatus = "skipped"
)

// MemoryRegion is one line of /proc/[pid]/maps plus whatever was acquired
// from it.
//
// Pathname is recorded exactly as the kernel reported it. Those paths are
// resolved inside the target's mount namespace, so "/usr/bin/python3" refers to
// the container's filesystem, not the host's. Rewriting them to host paths
// would be actively misleading in the forensic record.
type MemoryRegion struct {
	StartAddr uintptr `json:"start_addr"`
	EndAddr   uintptr `json:"end_addr"`
	Perms     string  `json:"perms"`
	Offset    uint64  `json:"offset"`
	Device    string  `json:"device"`
	Inode     uint64  `json:"inode"`
	Pathname  string  `json:"pathname"`

	Data       []byte       `json:"-"`
	Status     RegionStatus `json:"status"`
	BytesRead  int64        `json:"bytes_read"`
	BytesTotal int64        `json:"bytes_total"`
	Error      string       `json:"error,omitempty"`
	ReadTimeMS float64      `json:"read_time_ms,omitempty"`
}

// Size returns the length of the mapping in bytes.
func (r MemoryRegion) Size() int64 {
	if r.EndAddr <= r.StartAddr {
		return 0
	}
	return int64(r.EndAddr - r.StartAddr)
}

// Readable reports whether the mapping carries the read permission.
func (r MemoryRegion) Readable() bool { return strings.Contains(r.Perms, "r") }

// Writable reports whether the mapping carries the write permission.
func (r MemoryRegion) Writable() bool { return strings.Contains(r.Perms, "w") }

// Executable reports whether the mapping carries the execute permission.
func (r MemoryRegion) Executable() bool { return strings.Contains(r.Perms, "x") }

// Private reports whether the mapping is private (copy-on-write).
func (r MemoryRegion) Private() bool { return strings.HasSuffix(r.Perms, "p") }

// Anonymous reports whether the mapping is not backed by a file. Injected
// shellcode and fileless payloads live here.
func (r MemoryRegion) Anonymous() bool { return r.Pathname == "" }

// Pseudo reports whether the mapping is one of the kernel's bracketed
// pseudo-regions such as [heap], [stack] or [vdso].
func (r MemoryRegion) Pseudo() bool {
	return strings.HasPrefix(r.Pathname, "[") && strings.HasSuffix(r.Pathname, "]")
}

// Label returns a short human-readable name used in filenames and logs.
func (r MemoryRegion) Label() string {
	switch {
	case r.Pathname == "[heap]":
		return "heap"
	case r.Pathname == "[stack]":
		return "stack"
	case r.Pathname == "[vdso]":
		return "vdso"
	case r.Pseudo():
		return strings.Trim(r.Pathname, "[]")
	case r.Anonymous():
		return "anon"
	default:
		return sanitiseLabel(filepath.Base(r.Pathname))
	}
}

func sanitiseLabel(s string) string {
	var b strings.Builder
	for _, ch := range s {
		switch {
		case ch >= 'a' && ch <= 'z', ch >= 'A' && ch <= 'Z', ch >= '0' && ch <= '9', ch == '.', ch == '-', ch == '_':
			b.WriteRune(ch)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if len(out) > 48 {
		out = out[:48]
	}
	if out == "" {
		out = "region"
	}
	return out
}

// MaxPathnameLen bounds the pathname retained per region. PATH_MAX is 4096;
// anything longer is a malformed or hostile line and is truncated with a
// marker so the anomaly itself is preserved in the record.
const MaxPathnameLen = 4096

// maxMapsLine bounds a single line. Real lines are well under 4200 bytes; a
// larger one indicates corruption or an attempt to exhaust memory.
const maxMapsLine = 64 * 1024

// maxMapsRegions bounds how many regions are retained. The kernel's default
// vm.max_map_count is 65530; double that is a generous ceiling that still
// prevents unbounded allocation from a hostile maps file.
const maxMapsRegions = 131072

// ParseResult is the outcome of parsing a maps file.
type ParseResult struct {
	Regions []MemoryRegion
	// SkippedLines counts lines that could not be parsed. A non-zero value on
	// a real process is itself worth investigating and is recorded in the
	// evidence bundle.
	SkippedLines int
	// TruncatedPaths counts pathnames longer than MaxPathnameLen.
	TruncatedPaths int
	// Truncated is set when maxMapsRegions was hit and parsing stopped.
	Truncated bool
}

// ParseProcMaps parses the contents of a /proc/[pid]/maps file.
//
// Format (see proc(5)):
//
//	address           perms offset  dev   inode      pathname
//	7f8a1c000000-7f8a1c021000 r-xp 00000000 08:01 1052 /usr/lib/libc.so.6
//
// Malformed lines are skipped and counted rather than aborting the parse: a
// single unreadable line must not cost us the entire capture.
func ParseProcMaps(r io.Reader) (ParseResult, error) {
	var res ParseResult

	scanner := bufio.NewScanner(r)
	scanner.Buffer(make([]byte, 0, 8192), maxMapsLine)

	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}

		region, truncatedPath, ok := parseMapsLine(line)
		if !ok {
			res.SkippedLines++
			continue
		}
		if truncatedPath {
			res.TruncatedPaths++
		}

		res.Regions = append(res.Regions, region)
		if len(res.Regions) >= maxMapsRegions {
			res.Truncated = true
			break
		}
	}

	if err := scanner.Err(); err != nil {
		if err == bufio.ErrTooLong {
			// An over-long line is data we skip, not a fatal condition.
			res.SkippedLines++
			return res, nil
		}
		return res, fmt.Errorf("capture: read maps: %w", err)
	}

	return res, nil
}

func parseMapsLine(line string) (MemoryRegion, bool, bool) {
	var region MemoryRegion

	// Split off at most 6 fields; the pathname may contain spaces.
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return region, false, false
	}

	dash := strings.IndexByte(fields[0], '-')
	if dash <= 0 || dash == len(fields[0])-1 {
		return region, false, false
	}

	start, err := strconv.ParseUint(fields[0][:dash], 16, 64)
	if err != nil {
		return region, false, false
	}
	end, err := strconv.ParseUint(fields[0][dash+1:], 16, 64)
	if err != nil {
		return region, false, false
	}
	if end < start {
		return region, false, false
	}

	perms := fields[1]
	if len(perms) != 4 {
		return region, false, false
	}

	offset, err := strconv.ParseUint(fields[2], 16, 64)
	if err != nil {
		return region, false, false
	}

	device := fields[3]
	inode, err := strconv.ParseUint(fields[4], 10, 64)
	if err != nil {
		return region, false, false
	}

	pathname := ""
	truncated := false
	if len(fields) > 5 {
		// Recover the pathname with its internal spacing intact by locating
		// the inode field's end in the original line.
		idx := indexAfterFields(line, 5)
		if idx >= 0 && idx <= len(line) {
			pathname = strings.TrimSpace(line[idx:])
		} else {
			pathname = strings.Join(fields[5:], " ")
		}
		if len(pathname) > MaxPathnameLen {
			pathname = pathname[:MaxPathnameLen] + "...[truncated]"
			truncated = true
		}
	}

	region = MemoryRegion{
		StartAddr:  uintptr(start),
		EndAddr:    uintptr(end),
		Perms:      perms,
		Offset:     offset,
		Device:     device,
		Inode:      inode,
		Pathname:   pathname,
		Status:     RegionSkipped,
		BytesTotal: int64(end - start),
	}
	return region, truncated, true
}

// indexAfterFields returns the byte offset just past the nth whitespace
// separated field, or -1 if the line has fewer than n fields.
func indexAfterFields(line string, n int) int {
	i, seen := 0, 0
	for i < len(line) && seen < n {
		for i < len(line) && (line[i] == ' ' || line[i] == '\t') {
			i++
		}
		if i >= len(line) {
			return -1
		}
		for i < len(line) && line[i] != ' ' && line[i] != '\t' {
			i++
		}
		seen++
	}
	if seen < n {
		return -1
	}
	return i
}

// ReadProcMaps parses the maps file of a live process.
//
// procRoot allows the caller to point at /host/proc, which is where the
// DaemonSet mounts the host's procfs.
func ReadProcMaps(procRoot string, pid int) (ParseResult, error) {
	path := ProcPath(procRoot, pid, "maps")
	f, err := os.Open(path)
	if err != nil {
		return ParseResult{}, fmt.Errorf("capture: open %s: %w", path, err)
	}
	defer f.Close()

	res, err := ParseProcMaps(f)
	if err != nil {
		return res, fmt.Errorf("capture: parse %s: %w", path, err)
	}
	return res, nil
}

// ProcessExists reports whether a PID is visible in the given procfs.
//
// "Visible" is the operative word: a PID reported by an eBPF probe is numbered
// in the host PID namespace, and if the recorder is itself confined to a child
// namespace that number refers to nothing it can see. Checking before
// acquisition turns a confusing ESRCH into a decision the caller can act on.
func ProcessExists(procRoot string, pid int) bool {
	if pid <= 0 {
		return false
	}
	_, err := os.Stat(ProcPath(procRoot, pid, "stat"))
	return err == nil
}

// ProcPath builds a path inside the (possibly relocated) procfs.
func ProcPath(procRoot string, pid int, elems ...string) string {
	if procRoot == "" {
		procRoot = DefaultProcRoot
	}
	parts := append([]string{procRoot, strconv.Itoa(pid)}, elems...)
	return filepath.Join(parts...)
}

// DefaultProcRoot is the standard procfs mount point.
const DefaultProcRoot = "/proc"

// FilterOptions controls which regions are acquired.
type FilterOptions struct {
	// IncludeFileBacked acquires read-only file-backed mappings (shared
	// libraries, the executable image). Off by default: those bytes are
	// recoverable from the container image, they dominate the dump size, and
	// excluding them keeps captures inside the latency budget. Writable
	// file-backed mappings (a library's .data segment, mmap'd files) are
	// always included because they hold process-specific state.
	IncludeFileBacked bool
	// IncludeVDSO acquires [vdso] and [vvar]. Off by default: kernel-provided,
	// identical across processes, no forensic value.
	IncludeVDSO bool
	// MaxRegionBytes skips any single region larger than this. 0 = unlimited.
	// Guards against a process with a multi-gigabyte sparse mapping.
	MaxRegionBytes int64
}

// DefaultFilterOptions returns the production filter.
func DefaultFilterOptions() FilterOptions {
	return FilterOptions{
		IncludeFileBacked: false,
		IncludeVDSO:       false,
		MaxRegionBytes:    2 << 30, // 2 GiB
	}
}

// ShouldAcquire decides whether a region is worth reading, returning the
// reason when it is not. The reason is recorded in the evidence bundle so the
// exclusion is documented rather than silent.
func ShouldAcquire(r MemoryRegion, opts FilterOptions) (bool, string) {
	if !r.Readable() {
		return false, "region is not readable (perms " + r.Perms + ")"
	}
	if r.Size() == 0 {
		return false, "zero-length region"
	}
	if opts.MaxRegionBytes > 0 && r.Size() > opts.MaxRegionBytes {
		return false, fmt.Sprintf("region exceeds max_region_bytes (%d > %d)", r.Size(), opts.MaxRegionBytes)
	}

	// Device mappings are hardware windows, not process state. Reading them
	// can also have side effects on the device.
	if strings.HasPrefix(r.Pathname, "/dev/") {
		return false, "device mapping"
	}

	switch r.Pathname {
	case "[vvar]", "[vvar_vclock]", "[vsyscall]":
		// vvar is not readable via process_vm_readv on most kernels and
		// vsyscall is a fixed kernel page.
		return false, "kernel pseudo-mapping"
	case "[vdso]":
		if !opts.IncludeVDSO {
			return false, "vdso excluded by filter"
		}
		return true, ""
	}

	if r.Anonymous() || r.Pseudo() {
		return true, "" // heap, stack, thread stacks, anonymous: always take
	}

	// File-backed from here on.
	if r.Writable() {
		return true, "" // private/dirty data segments hold live state
	}
	if !opts.IncludeFileBacked {
		return false, "read-only file-backed mapping excluded by filter"
	}
	return true, ""
}

// SelectRegions applies the filter, returning the regions to acquire and the
// regions excluded (with their reasons preserved).
func SelectRegions(regions []MemoryRegion, opts FilterOptions) (acquire, skipped []MemoryRegion) {
	for _, r := range regions {
		if ok, reason := ShouldAcquire(r, opts); ok {
			r.Status = RegionSkipped // upgraded once actually read
			acquire = append(acquire, r)
		} else {
			r.Status = RegionSkipped
			r.Error = reason
			skipped = append(skipped, r)
		}
	}
	return acquire, skipped
}
