package capture

import (
	"regexp"
	"time"
)

// Outcome classifies how complete an acquisition was.
type Outcome string

const (
	// OutcomeComplete: every selected region was read in full.
	OutcomeComplete Outcome = "complete"
	// OutcomePartial: some regions were short or unreadable.
	OutcomePartial Outcome = "partial"
	// OutcomeTruncated: the configured size cap stopped acquisition early.
	OutcomeTruncated Outcome = "truncated"
	// OutcomeProcessExited: the target died mid-acquisition (ESRCH).
	OutcomeProcessExited Outcome = "process_exited"
	// OutcomeInterrupted: shutdown or context cancellation stopped acquisition.
	OutcomeInterrupted Outcome = "interrupted"
	// OutcomeEmpty: nothing at all could be read.
	OutcomeEmpty Outcome = "empty"
)

// MemoryDump is the result of one freeze-frame acquisition.
//
// Every field that describes *how well* the acquisition went is retained and
// ends up in the signed receipt. An examiner must be able to distinguish
// "the heap was empty" from "we could not read the heap".
type MemoryDump struct {
	PID          int    `json:"pid"`
	NamespacePID int    `json:"namespace_pid"`
	ProcRoot     string `json:"proc_root"`
	Comm         string `json:"comm"`
	CgroupID     uint64 `json:"cgroup_id"`

	CaptureStart time.Time `json:"capture_start"`
	CaptureEnd   time.Time `json:"capture_end"`
	MapsParsedAt time.Time `json:"maps_parsed_at"`

	// MapsToFirstReadMS is the width of the race window: the time between
	// reading the address map and beginning to act on it. Every microsecond
	// here is a microsecond in which the map could have changed. It is
	// reported, not hidden, because the evaluation section of the whitepaper
	// depends on it.
	MapsToFirstReadMS float64 `json:"maps_to_first_read_ms"`

	Regions []MemoryRegion `json:"regions"`
	Skipped []MemoryRegion `json:"skipped_regions"`

	TotalBytes     int64 `json:"total_bytes"`
	PartialRegions int   `json:"partial_regions"`
	FailedRegions  int   `json:"failed_regions"`
	FullRegions    int   `json:"full_regions"`
	SkippedRegions int   `json:"skipped_regions_count"`

	Truncated     bool `json:"truncated"`
	ProcessExited bool `json:"process_exited"`
	Interrupted   bool `json:"interrupted"`

	// ParseSkippedLines counts unparseable lines in /proc/[pid]/maps. Non-zero
	// on a real process is an anomaly worth reporting.
	ParseSkippedLines int `json:"parse_skipped_lines"`

	RedactedMatches int      `json:"redacted_matches"`
	RedactionUsed   []string `json:"redaction_patterns,omitempty"`
}

// Duration returns the wall-clock acquisition time.
func (d *MemoryDump) Duration() time.Duration {
	if d.CaptureEnd.IsZero() {
		return 0
	}
	return d.CaptureEnd.Sub(d.CaptureStart)
}

// Outcome classifies the acquisition.
func (d *MemoryDump) Outcome() Outcome {
	switch {
	case d.TotalBytes == 0:
		return OutcomeEmpty
	case d.Interrupted:
		return OutcomeInterrupted
	case d.ProcessExited:
		return OutcomeProcessExited
	case d.Truncated:
		return OutcomeTruncated
	case d.PartialRegions > 0 || d.FailedRegions > 0:
		return OutcomePartial
	default:
		return OutcomeComplete
	}
}

// Chunks returns the acquired region payloads in address order.
//
// This is the exact byte sequence that gets sealed, compressed and encrypted.
// Region order is address-ascending and stable, which is what makes the Merkle
// root reproducible from the stored dump.
func (d *MemoryDump) Chunks() [][]byte {
	out := make([][]byte, 0, len(d.Regions))
	for i := range d.Regions {
		if len(d.Regions[i].Data) > 0 {
			out = append(out, d.Regions[i].Data)
		}
	}
	return out
}

// Bytes concatenates the acquired regions into a single buffer.
//
// The caller pays for one full copy of the dump here. That is accepted: the
// sealed artefact and the encrypted artefact must be the same contiguous byte
// sequence, otherwise verification could not be performed from the stored file
// alone.
func (d *MemoryDump) Bytes() []byte {
	buf := make([]byte, 0, d.TotalBytes)
	for i := range d.Regions {
		buf = append(buf, d.Regions[i].Data...)
	}
	return buf
}

// Release drops the acquired payloads so the garbage collector can reclaim
// them once the bundle has been written. Metadata is retained.
func (d *MemoryDump) Release() {
	for i := range d.Regions {
		d.Regions[i].Data = nil
	}
}

// redactionFill is the byte pattern written over redacted content. 0xDEAD is
// visually obvious in a hex editor, which matters when an examiner needs to
// see at a glance that a region was modified by policy rather than by an
// attacker.
var redactionFill = []byte{0xDE, 0xAD}

// Redact overwrites every match of the supplied patterns in the acquired data.
//
// This mutates the bytes that will be sealed. That is the correct order of
// operations - the Merkle root must describe the artefact actually stored -
// but it means the sealed hash is NOT a hash of the original process memory.
// The receipt records redaction_applied and the pattern list so this is never
// ambiguous. Redaction is off by default because forensic integrity generally
// outranks privacy in incident response; it exists for GDPR-regulated
// environments that cannot store raw PII at all.
func (d *MemoryDump) Redact(patterns []*regexp.Regexp, names []string) int {
	if len(patterns) == 0 {
		return 0
	}

	total := 0
	for i := range d.Regions {
		data := d.Regions[i].Data
		if len(data) == 0 {
			continue
		}
		for _, re := range patterns {
			locs := re.FindAllIndex(data, -1)
			for _, loc := range locs {
				for p := loc[0]; p < loc[1]; p++ {
					data[p] = redactionFill[(p-loc[0])%len(redactionFill)]
				}
				total++
			}
		}
	}

	d.RedactedMatches = total
	if total > 0 {
		d.RedactionUsed = names
	}
	return total
}
