package evidence

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Retention enforces the storage policy for an evidence directory.
//
// Two independent limits apply. Age-based expiry implements the data
// protection commitment ("we keep captures for 90 days"). Size-based expiry
// protects the node: an attacker who knows the recorder is running can
// deliberately trigger captures to fill the disk, and a full disk on a
// Kubernetes node takes down every workload on it, not just this one.
type Retention struct {
	Root      string
	MaxAge    time.Duration
	MaxBytes  int64
	OnDelete  func(caseID, dir string, size int64, reason string)
	NowFunc   func() time.Time
	MinRetain int // never delete the newest N bundles, whatever the policy says
}

// SweepResult reports what a sweep did.
type SweepResult struct {
	Scanned      int
	DeletedAge   int
	DeletedSpace int
	BytesFreed   int64
	BytesInUse   int64
	Errors       []string
}

type bundleEntry struct {
	caseID  string
	dir     string
	modTime time.Time
	size    int64
}

// Sweep applies the retention policy once.
//
// Age expiry runs first, then size expiry deletes oldest-first until usage is
// under the limit. Deletions are logged through OnDelete so they land in the
// audit trail: silently destroying evidence is exactly the behaviour a defence
// counsel would attack, so the record of what was deleted and why must survive
// the deletion.
func (r *Retention) Sweep() (SweepResult, error) {
	var res SweepResult

	now := time.Now
	if r.NowFunc != nil {
		now = r.NowFunc
	}

	entries, err := r.list()
	if err != nil {
		return res, err
	}
	res.Scanned = len(entries)

	// Oldest first.
	sort.Slice(entries, func(i, j int) bool { return entries[i].modTime.Before(entries[j].modTime) })

	// Bundles are ordered oldest first, so the newest MinRetain entries are the
	// tail of the slice. deletable is the count at the head that policy may
	// remove; when MinRetain exceeds the number of bundles, nothing is.
	deletable := len(entries) - r.MinRetain
	if r.MinRetain <= 0 {
		deletable = len(entries)
	}
	if deletable < 0 {
		deletable = 0
	}

	var remaining []bundleEntry
	for i, e := range entries {
		res.BytesInUse += e.size

		expired := r.MaxAge > 0 && now().Sub(e.modTime) > r.MaxAge
		mayDelete := i < deletable

		if expired && mayDelete {
			if err := r.remove(e, fmt.Sprintf("age exceeded retention of %s", r.MaxAge)); err != nil {
				res.Errors = append(res.Errors, err.Error())
				remaining = append(remaining, e)
				continue
			}
			res.DeletedAge++
			res.BytesFreed += e.size
			res.BytesInUse -= e.size
			continue
		}
		remaining = append(remaining, e)
	}

	if r.MaxBytes <= 0 {
		return res, nil
	}

	for i := 0; i < len(remaining) && res.BytesInUse > r.MaxBytes; i++ {
		if r.MinRetain > 0 && len(remaining)-i <= r.MinRetain {
			break
		}
		e := remaining[i]
		if err := r.remove(e, fmt.Sprintf("evidence directory over %d bytes", r.MaxBytes)); err != nil {
			res.Errors = append(res.Errors, err.Error())
			continue
		}
		res.DeletedSpace++
		res.BytesFreed += e.size
		res.BytesInUse -= e.size
	}

	return res, nil
}

func (r *Retention) remove(e bundleEntry, reason string) error {
	if err := os.RemoveAll(e.dir); err != nil {
		return fmt.Errorf("evidence: delete bundle %s: %w", e.caseID, err)
	}
	if r.OnDelete != nil {
		r.OnDelete(e.caseID, e.dir, e.size, reason)
	}
	return nil
}

func (r *Retention) list() ([]bundleEntry, error) {
	dirEntries, err := os.ReadDir(r.Root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("evidence: read evidence root %s: %w", r.Root, err)
	}

	out := make([]bundleEntry, 0, len(dirEntries))
	for _, de := range dirEntries {
		if !de.IsDir() {
			continue
		}
		dir := filepath.Join(r.Root, de.Name())
		size, modTime, err := dirStats(dir)
		if err != nil {
			continue
		}
		out = append(out, bundleEntry{caseID: de.Name(), dir: dir, modTime: modTime, size: size})
	}
	return out, nil
}

func dirStats(dir string) (size int64, newest time.Time, err error) {
	err = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		size += info.Size()
		if info.ModTime().After(newest) {
			newest = info.ModTime()
		}
		return nil
	})
	return size, newest, err
}

// DiskUsage returns the total bytes occupied by the evidence directory.
func DiskUsage(root string) (int64, error) {
	size, _, err := dirStats(root)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, fmt.Errorf("evidence: measure %s: %w", root, err)
	}
	return size, nil
}

// Run sweeps on an interval until ctx is cancelled. An immediate sweep is
// performed on start so that a recorder restarting after a long outage does
// not wait a full interval before reclaiming space.
func (r *Retention) Run(ctx context.Context, interval time.Duration, onSweep func(SweepResult, error)) {
	if interval <= 0 {
		interval = time.Hour
	}

	sweep := func() {
		res, err := r.Sweep()
		if onSweep != nil {
			onSweep(res, err)
		}
	}
	sweep()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sweep()
			}
		}
	}()
}

// ListBundles returns the case ids present in an evidence directory, newest
// first.
func ListBundles(root string) ([]string, error) {
	r := &Retention{Root: root}
	entries, err := r.list()
	if err != nil {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].modTime.After(entries[j].modTime) })

	ids := make([]string, 0, len(entries))
	for _, e := range entries {
		ids = append(ids, e.caseID)
	}
	return ids, nil
}
