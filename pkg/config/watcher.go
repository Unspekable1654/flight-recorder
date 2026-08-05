package config

import (
	"context"
	"fmt"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Store holds the active configuration and swaps it atomically on reload.
//
// Readers on the event hot path call Get() with no lock contention; reloads
// replace the pointer wholesale. A configuration is never mutated in place,
// so a capture that started under the old ruleset finishes under it.
type Store struct {
	current atomic.Pointer[Config]

	mu        sync.Mutex
	path      string
	onReload  []func(*Config)
	reloadCnt atomic.Uint64
}

// NewStore creates a store seeded with cfg.
func NewStore(cfg *Config) *Store {
	s := &Store{}
	s.current.Store(cfg)
	return s
}

// Get returns the active configuration. Never nil.
func (s *Store) Get() *Config { return s.current.Load() }

// Reloads returns the number of successful hot reloads since start.
func (s *Store) Reloads() uint64 { return s.reloadCnt.Load() }

// OnReload registers a callback invoked after every successful reload, used to
// re-sync the kernel prefilter map and to write an audit record.
func (s *Store) OnReload(fn func(*Config)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onReload = append(s.onReload, fn)
}

// Reload re-reads the configuration file and swaps it in.
//
// A failed reload is non-fatal by design: keeping the last known-good ruleset
// running is strictly safer than falling back to no monitoring because someone
// pushed a malformed ConfigMap.
func (s *Store) Reload() error {
	s.mu.Lock()
	path := s.path
	s.mu.Unlock()

	if path == "" {
		return fmt.Errorf("no configuration file is being watched")
	}

	cfg, err := Load(path)
	if err != nil {
		return err
	}

	s.current.Store(cfg)
	s.reloadCnt.Add(1)

	s.mu.Lock()
	callbacks := append([]func(*Config){}, s.onReload...)
	s.mu.Unlock()

	for _, fn := range callbacks {
		fn(cfg)
	}
	return nil
}

// Watch loads the file at path and keeps the store in sync with it until ctx
// is cancelled.
//
// Kubernetes ConfigMap volumes are updated by atomically swapping a
// "..data" symlink, not by rewriting the file in place, so the parent
// directory is watched rather than the file itself. Events are debounced
// because a single ConfigMap update produces a burst of create/rename/remove
// notifications.
//
// onError, if non-nil, receives reload failures; the previous configuration
// stays active in that case.
func (s *Store) Watch(ctx context.Context, path string, onError func(error)) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve config path %s: %w", path, err)
	}

	cfg, err := Load(abs)
	if err != nil {
		return err
	}
	s.current.Store(cfg)

	s.mu.Lock()
	s.path = abs
	s.mu.Unlock()

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create fsnotify watcher: %w", err)
	}

	dir := filepath.Dir(abs)
	if err := watcher.Add(dir); err != nil {
		_ = watcher.Close()
		return fmt.Errorf("watch config directory %s: %w", dir, err)
	}

	go func() {
		defer func() { _ = watcher.Close() }()

		const debounce = 250 * time.Millisecond
		var timer *time.Timer
		var timerC <-chan time.Time

		for {
			select {
			case <-ctx.Done():
				return

			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				// Ignore unrelated files in the directory, but always accept
				// the ConfigMap data-directory swap.
				name := filepath.Base(event.Name)
				if name != filepath.Base(abs) && name != "..data" {
					continue
				}
				if timer != nil {
					timer.Stop()
				}
				timer = time.NewTimer(debounce)
				timerC = timer.C

			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				if onError != nil {
					onError(fmt.Errorf("config watcher: %w", err))
				}

			case <-timerC:
				timerC = nil
				if err := s.Reload(); err != nil && onError != nil {
					onError(fmt.Errorf("config reload rejected, keeping previous ruleset: %w", err))
				}
			}
		}
	}()

	return nil
}
