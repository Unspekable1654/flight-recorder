package pipeline

import (
	"sync"
	"time"
)

// RateLimiter enforces a per-minute cap globally and per container.
//
// The threat this addresses is specific. An attacker who discovers that a node
// runs Flight Recorder can deliberately execute the trigger commands in a tight
// loop: each one costs a memory read, a Merkle tree, a compression pass and a
// disk write. Without a cap that is a denial of service against the node, and a
// very effective one, because the tool is doing exactly what it was told to do.
//
// A sliding window is used rather than a token bucket so that the semantics
// match what an operator configures: "no more than 10 captures in any 60
// second period" is checkable after the fact from the audit log, which a
// bucket's refill rate is not.
type RateLimiter struct {
	mu sync.Mutex

	window time.Duration

	globalLimit int
	global      []time.Time

	perKeyLimit int
	perKey      map[string][]time.Time

	nowFunc func() time.Time
}

// NewRateLimiter builds a limiter. A limit of 0 disables that dimension.
func NewRateLimiter(globalPerMinute, perContainerPerMinute int) *RateLimiter {
	return &RateLimiter{
		window:      time.Minute,
		globalLimit: globalPerMinute,
		perKeyLimit: perContainerPerMinute,
		perKey:      make(map[string][]time.Time),
		nowFunc:     time.Now,
	}
}

// SetLimits updates the caps at runtime, used on configuration reload.
func (r *RateLimiter) SetLimits(globalPerMinute, perContainerPerMinute int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.globalLimit = globalPerMinute
	r.perKeyLimit = perContainerPerMinute
}

// Allow reports whether a capture may proceed and, when it may not, why.
//
// The reservation is recorded on success only: a rejected capture must not
// count against the budget, or a burst of rejections would extend the outage
// beyond the window.
func (r *RateLimiter) Allow(key string) (bool, string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.nowFunc()
	cutoff := now.Add(-r.window)

	r.global = prune(r.global, cutoff)
	if r.globalLimit > 0 && len(r.global) >= r.globalLimit {
		return false, "global rate limit"
	}

	if r.perKeyLimit > 0 && key != "" {
		entries := prune(r.perKey[key], cutoff)
		r.perKey[key] = entries
		if len(entries) >= r.perKeyLimit {
			return false, "per-container rate limit"
		}
		r.perKey[key] = append(entries, now)
	}

	r.global = append(r.global, now)
	return true, ""
}

// Counts returns the current window occupancy, for metrics and diagnostics.
func (r *RateLimiter) Counts() (global int, keys int) {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := r.nowFunc().Add(-r.window)
	r.global = prune(r.global, cutoff)
	return len(r.global), len(r.perKey)
}

// Purge drops per-key state for containers that have gone quiet, so that a node
// churning through thousands of short-lived pods does not accumulate a map
// entry per pod forever.
func (r *RateLimiter) Purge() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	cutoff := r.nowFunc().Add(-r.window)
	removed := 0
	for k, v := range r.perKey {
		if pruned := prune(v, cutoff); len(pruned) == 0 {
			delete(r.perKey, k)
			removed++
		} else {
			r.perKey[k] = pruned
		}
	}
	return removed
}

func prune(times []time.Time, cutoff time.Time) []time.Time {
	i := 0
	for ; i < len(times); i++ {
		if times[i].After(cutoff) {
			break
		}
	}
	if i == 0 {
		return times
	}
	return times[i:]
}
