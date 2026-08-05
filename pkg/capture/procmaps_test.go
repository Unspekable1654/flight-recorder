package capture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const sampleMaps = `55d4f2a00000-55d4f2a21000 r-xp 00000000 08:01 1052                       /usr/bin/python3.11
55d4f2c20000-55d4f2c21000 r--p 00020000 08:01 1052                       /usr/bin/python3.11
55d4f2c21000-55d4f2c22000 rw-p 00021000 08:01 1052                       /usr/bin/python3.11
55d4f3000000-55d4f3400000 rw-p 00000000 00:00 0                          [heap]
7f9c2a000000-7f9c2a1f5000 r-xp 00000000 08:01 2048                       /usr/lib/x86_64-linux-gnu/libc.so.6
7f9c2a3f5000-7f9c2a3f9000 rw-p 001f5000 08:01 2048                       /usr/lib/x86_64-linux-gnu/libc.so.6
7f9c2a400000-7f9c2a800000 rw-p 00000000 00:00 0
7f9c2b000000-7f9c2b001000 rw-s 00000000 00:05 12345                      /dev/zero (deleted)
7ffd3c1e0000-7ffd3c201000 rw-p 00000000 00:00 0                          [stack]
7ffd3c3f2000-7ffd3c3f6000 r--p 00000000 00:00 0                          [vvar]
7ffd3c3f6000-7ffd3c3f8000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
`

func parse(t *testing.T, content string) ParseResult {
	t.Helper()
	res, err := ParseProcMaps(strings.NewReader(content))
	if err != nil {
		t.Fatalf("ParseProcMaps: %v", err)
	}
	return res
}

func TestParseProcMapsFields(t *testing.T) {
	res := parse(t, sampleMaps)

	if len(res.Regions) != 12 {
		t.Fatalf("parsed %d regions, want 12", len(res.Regions))
	}
	if res.SkippedLines != 0 {
		t.Errorf("skipped %d well-formed lines", res.SkippedLines)
	}

	first := res.Regions[0]
	if first.StartAddr != 0x55d4f2a00000 || first.EndAddr != 0x55d4f2a21000 {
		t.Errorf("address range = %#x-%#x", first.StartAddr, first.EndAddr)
	}
	if first.Perms != "r-xp" {
		t.Errorf("perms = %q, want r-xp", first.Perms)
	}
	if first.Inode != 1052 || first.Device != "08:01" {
		t.Errorf("inode/device = %d/%s", first.Inode, first.Device)
	}
	if first.Pathname != "/usr/bin/python3.11" {
		t.Errorf("pathname = %q", first.Pathname)
	}
	if first.Size() != 0x21000 {
		t.Errorf("size = %d, want %d", first.Size(), 0x21000)
	}
	if !first.Readable() || !first.Executable() || first.Writable() {
		t.Error("permission accessors disagree with r-xp")
	}

	heap := res.Regions[3]
	if heap.Pathname != "[heap]" || !heap.Pseudo() || heap.Anonymous() {
		t.Errorf("heap region misclassified: %+v", heap)
	}
	if heap.Label() != "heap" {
		t.Errorf("heap label = %q", heap.Label())
	}

	anon := res.Regions[6]
	if !anon.Anonymous() || anon.Label() != "anon" {
		t.Errorf("anonymous region misclassified: %+v", anon)
	}
}

func TestParseProcMapsPathWithSpaces(t *testing.T) {
	const line = "55d4f2a00000-55d4f2a21000 r--p 00000000 08:01 1052                       /opt/my app/lib (deleted)\n"

	res := parse(t, line)
	if len(res.Regions) != 1 {
		t.Fatalf("parsed %d regions, want 1", len(res.Regions))
	}
	if got := res.Regions[0].Pathname; got != "/opt/my app/lib (deleted)" {
		t.Errorf("pathname = %q, want the full path including spaces", got)
	}
}

func TestParseProcMapsMalformedLinesAreSkipped(t *testing.T) {
	content := strings.Join([]string{
		"55d4f2a00000-55d4f2a21000 r-xp 00000000 08:01 1052 /usr/bin/ok",
		"garbage",
		"zzzz-yyyy rw-p 00000000 00:00 0",
		"55d4f2a00000 rw-p 00000000 00:00 0",               // no dash
		"55d4f2a21000-55d4f2a00000 rw-p 00000000 00:00 0",  // end before start
		"55d4f3000000-55d4f3400000 rwxp",                   // too few fields
		"55d4f3000000-55d4f3400000 rw 00000000 00:00 0",    // short perms
		"55d4f4000000-55d4f4400000 rw-p zzz 00:00 0",       // bad offset
		"55d4f5000000-55d4f5400000 rw-p 00000000 00:00 xx", // bad inode
		"7ffd3c1e0000-7ffd3c201000 rw-p 00000000 00:00 0 [stack]",
		"",
	}, "\n")

	res := parse(t, content)

	if len(res.Regions) != 2 {
		t.Errorf("parsed %d regions, want 2 (the well-formed ones)", len(res.Regions))
	}
	if res.SkippedLines != 8 {
		t.Errorf("skipped %d lines, want 8", res.SkippedLines)
	}
}

func TestParseProcMapsTruncatesLongPaths(t *testing.T) {
	long := strings.Repeat("a", MaxPathnameLen+500)
	content := "55d4f2a00000-55d4f2a21000 r--p 00000000 08:01 1052 /" + long + "\n"

	res := parse(t, content)
	if len(res.Regions) != 1 {
		t.Fatalf("parsed %d regions, want 1", len(res.Regions))
	}
	if res.TruncatedPaths != 1 {
		t.Errorf("TruncatedPaths = %d, want 1", res.TruncatedPaths)
	}
	if !strings.HasSuffix(res.Regions[0].Pathname, "[truncated]") {
		t.Error("truncation marker missing from the recorded pathname")
	}
}

func TestParseProcMapsEmptyInput(t *testing.T) {
	res := parse(t, "")
	if len(res.Regions) != 0 || res.SkippedLines != 0 {
		t.Errorf("empty input produced %+v", res)
	}
}

func TestShouldAcquire(t *testing.T) {
	res := parse(t, sampleMaps)
	opts := DefaultFilterOptions()

	byPath := make(map[string]MemoryRegion, len(res.Regions))
	for _, r := range res.Regions {
		key := r.Pathname
		if key == "" {
			key = "anon"
		}
		if _, seen := byPath[key]; !seen || r.Writable() {
			byPath[key] = r
		}
	}

	cases := []struct {
		name string
		key  string
		want bool
	}{
		{"heap is always acquired", "[heap]", true},
		{"stack is always acquired", "[stack]", true},
		{"anonymous mappings hold fileless payloads", "anon", true},
		{"vvar is not readable through process_vm_readv", "[vvar]", false},
		{"vsyscall is a kernel page", "[vsyscall]", false},
		{"vdso is excluded by default", "[vdso]", false},
		{"device mappings are excluded", "/dev/zero (deleted)", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			region, ok := byPath[tc.key]
			if !ok {
				t.Fatalf("test fixture has no region for %q", tc.key)
			}
			got, reason := ShouldAcquire(region, opts)
			if got != tc.want {
				t.Errorf("ShouldAcquire = %v (%s), want %v", got, reason, tc.want)
			}
			if !got && reason == "" {
				t.Error("exclusions must carry a reason: it is recorded in the evidence bundle")
			}
		})
	}
}

func TestSelectRegionsFileBackedPolicy(t *testing.T) {
	res := parse(t, sampleMaps)

	// Default: read-only file-backed mappings are excluded, writable ones kept.
	acquire, skipped := SelectRegions(res.Regions, DefaultFilterOptions())

	for _, r := range acquire {
		if !r.Anonymous() && !r.Pseudo() && !r.Writable() {
			t.Errorf("read-only file-backed mapping %q was selected by the default filter", r.Pathname)
		}
	}
	if len(skipped) == 0 {
		t.Error("nothing was skipped; the default filter should exclude libraries and vdso")
	}

	// With IncludeFileBacked the library text segments come along.
	opts := DefaultFilterOptions()
	opts.IncludeFileBacked = true
	acquireAll, _ := SelectRegions(res.Regions, opts)
	if len(acquireAll) <= len(acquire) {
		t.Errorf("IncludeFileBacked acquired %d regions, expected more than the default %d", len(acquireAll), len(acquire))
	}

	foundLibc := false
	for _, r := range acquireAll {
		if strings.Contains(r.Pathname, "libc.so.6") && r.Executable() {
			foundLibc = true
		}
	}
	if !foundLibc {
		t.Error("IncludeFileBacked did not select the libc text segment")
	}
}

func TestSelectRegionsMaxRegionBytes(t *testing.T) {
	res := parse(t, sampleMaps)

	opts := DefaultFilterOptions()
	opts.MaxRegionBytes = 4096

	acquire, skipped := SelectRegions(res.Regions, opts)
	for _, r := range acquire {
		if r.Size() > 4096 {
			t.Errorf("region of %d bytes exceeded the cap but was selected", r.Size())
		}
	}

	capped := 0
	for _, r := range skipped {
		if strings.Contains(r.Error, "max_region_bytes") {
			capped++
		}
	}
	if capped == 0 {
		t.Error("no region was excluded by the size cap")
	}
}

func TestReadProcMapsMissingProcess(t *testing.T) {
	if _, err := ReadProcMaps(t.TempDir(), 999999); err == nil {
		t.Error("expected an error for a nonexistent process")
	}
}

func TestProcPath(t *testing.T) {
	got := ProcPath("/host/proc", 42, "maps")
	want := filepath.Join("/host/proc", "42", "maps")
	if got != want {
		t.Errorf("ProcPath = %q, want %q", got, want)
	}

	if got := ProcPath("", 42, "status"); got != filepath.Join(DefaultProcRoot, "42", "status") {
		t.Errorf("ProcPath with empty root = %q", got)
	}
}

// FuzzParseProcMaps asserts the parser is total.
//
// The maps file of a compromised process is attacker-influenced input: a
// process can create mappings with arbitrary pathnames, and a FUSE mount can
// serve arbitrary bytes. A panic here would take down monitoring for the whole
// node, which is a cheap denial of service against the recorder.
func FuzzParseProcMaps(f *testing.F) {
	f.Add(sampleMaps)
	f.Add("")
	f.Add("55d4f2a00000-55d4f2a21000 r-xp 00000000 08:01 1052 /usr/bin/ok\n")
	f.Add("0-0 ---p 0 0:0 0\n")
	f.Add("ffffffffffffffff-ffffffffffffffff rw-p ffffffffffffffff ff:ff 18446744073709551615 /x\n")
	f.Add("55d4f2a00000-55d4f2a21000 rw-p 00000000 00:00 0 " + strings.Repeat("é", 5000) + "\n")
	f.Add("55d4f2a00000-55d4f2a21000 rw-p 00000000 00:00 0 \x00\x01\x02\n")
	f.Add("-1--2 rw-p -1 -1:-1 -1\n")
	f.Add(strings.Repeat("55d4f2a00000-55d4f2a21000 rw-p 00000000 00:00 0 [heap]\n", 1000))

	// Seed from real /proc/[pid]/maps files captured from different runtimes.
	seeds, err := filepath.Glob(filepath.Join("testdata", "maps", "*.maps"))
	if err == nil {
		for _, path := range seeds {
			if raw, err := os.ReadFile(path); err == nil {
				f.Add(string(raw))
			}
		}
	}

	f.Fuzz(func(t *testing.T, content string) {
		res, err := ParseProcMaps(strings.NewReader(content))
		if err != nil {
			// An error is acceptable; a panic is not.
			return
		}

		opts := DefaultFilterOptions()
		for _, r := range res.Regions {
			// Every derived accessor must also be total.
			_ = r.Size()
			_ = r.Label()
			_, _ = ShouldAcquire(r, opts)

			if r.EndAddr < r.StartAddr {
				t.Fatalf("parser produced an inverted range %#x-%#x", r.StartAddr, r.EndAddr)
			}
			if len(r.Pathname) > MaxPathnameLen+len("...[truncated]") {
				t.Fatalf("parser retained a %d byte pathname", len(r.Pathname))
			}
		}

		SelectRegions(res.Regions, opts)
	})
}

func TestFuzzSeedCorpusIsPresent(t *testing.T) {
	seeds, err := filepath.Glob(filepath.Join("testdata", "maps", "*.maps"))
	if err != nil {
		t.Fatalf("glob: %v", err)
	}
	if len(seeds) < 5 {
		t.Errorf("found %d seed corpus files, want at least 5 real /proc/[pid]/maps samples", len(seeds))
	}

	for _, path := range seeds {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		res, err := ParseProcMaps(strings.NewReader(string(raw)))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if len(res.Regions) == 0 {
			t.Errorf("%s: parsed no regions from a real maps file", path)
		}
		if res.SkippedLines > 0 {
			t.Errorf("%s: %d lines of a real maps file were unparseable", path, res.SkippedLines)
		}
	}
}
