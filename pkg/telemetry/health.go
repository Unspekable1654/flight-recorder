package telemetry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Health tracks readiness state for the Kubernetes probes.
//
// Liveness and readiness answer genuinely different questions here, and
// conflating them is how a monitoring gap gets hidden:
//
//	liveness  - is the process functioning? If not, restart it.
//	readiness - are the eBPF programs attached and is the ring buffer being
//	            consumed? If not, this node is NOT being monitored, and that
//	            must be visible even though the process is perfectly healthy.
type Health struct {
	probesAttached atomic.Bool
	ringbufActive  atomic.Bool
	lastEvent      atomic.Int64 // unix nano
	startedAt      time.Time
	shuttingDown   atomic.Bool
	// StaleAfter marks readiness false when no event has been seen for this
	// long. Zero disables the check: on a genuinely idle node, no events is
	// the correct state, so this is off by default.
	StaleAfter time.Duration
}

// NewHealth returns a Health tracker.
func NewHealth() *Health {
	return &Health{startedAt: time.Now()}
}

// SetProbesAttached records eBPF attachment state.
func (h *Health) SetProbesAttached(v bool) { h.probesAttached.Store(v) }

// SetRingbufActive records ring buffer consumption state.
func (h *Health) SetRingbufActive(v bool) { h.ringbufActive.Store(v) }

// RecordEvent notes that an event was consumed.
func (h *Health) RecordEvent() { h.lastEvent.Store(time.Now().UnixNano()) }

// BeginShutdown marks the recorder as draining so that Kubernetes stops
// considering it ready before the process actually exits.
func (h *Health) BeginShutdown() { h.shuttingDown.Store(true) }

// Ready reports readiness and the reason when not ready.
func (h *Health) Ready() (bool, string) {
	if h.shuttingDown.Load() {
		return false, "shutting down"
	}
	if !h.probesAttached.Load() {
		return false, "eBPF programs are not attached"
	}
	if !h.ringbufActive.Load() {
		return false, "ring buffer reader is not running"
	}
	if h.StaleAfter > 0 {
		last := h.lastEvent.Load()
		if last > 0 && time.Since(time.Unix(0, last)) > h.StaleAfter {
			return false, fmt.Sprintf("no events observed for more than %s", h.StaleAfter)
		}
	}
	return true, "ok"
}

type healthResponse struct {
	Status   string  `json:"status"`
	Reason   string  `json:"reason,omitempty"`
	UptimeS  float64 `json:"uptime_seconds"`
	Attached bool    `json:"probes_attached"`
	Ringbuf  bool    `json:"ringbuf_active"`
}

// Server hosts the metrics and health endpoints.
type Server struct {
	metricsSrv *http.Server
	healthSrv  *http.Server
}

// ServerOptions configures the telemetry endpoints.
type ServerOptions struct {
	MetricsAddr string
	HealthAddr  string
	Metrics     *Metrics
	Health      *Health
	// PprofEnabled exposes /debug/pprof on the health listener. Off by default:
	// profiling endpoints on a privileged DaemonSet are an information
	// disclosure risk and are only enabled deliberately, during performance work.
	PprofEnabled bool
}

// NewServer wires the HTTP handlers.
func NewServer(opts ServerOptions) *Server {
	s := &Server{}

	if opts.MetricsAddr != "" && opts.Metrics != nil {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.HandlerFor(opts.Metrics.Registry(), promhttp.HandlerOpts{
			ErrorHandling: promhttp.ContinueOnError,
		}))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "/metrics", http.StatusFound)
		})
		s.metricsSrv = &http.Server{
			Addr:              opts.MetricsAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
	}

	if opts.HealthAddr != "" && opts.Health != nil {
		mux := http.NewServeMux()
		mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, healthResponse{
				Status:   "ok",
				UptimeS:  time.Since(opts.Health.startedAt).Seconds(),
				Attached: opts.Health.probesAttached.Load(),
				Ringbuf:  opts.Health.ringbufActive.Load(),
			})
		})
		mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
			ready, reason := opts.Health.Ready()
			status := http.StatusOK
			body := healthResponse{
				Status:   "ready",
				UptimeS:  time.Since(opts.Health.startedAt).Seconds(),
				Attached: opts.Health.probesAttached.Load(),
				Ringbuf:  opts.Health.ringbufActive.Load(),
			}
			if !ready {
				status = http.StatusServiceUnavailable
				body.Status = "not ready"
				body.Reason = reason
			}
			writeJSON(w, status, body)
		})

		if opts.PprofEnabled {
			registerPprof(mux)
		}

		s.healthSrv = &http.Server{
			Addr:              opts.HealthAddr,
			Handler:           mux,
			ReadHeaderTimeout: 5 * time.Second,
		}
	}

	return s
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// Start launches the listeners. Errors other than server closure are passed to
// onError; a failed telemetry listener must never stop the recorder from
// monitoring - losing metrics is bad, losing evidence is worse.
func (s *Server) Start(onError func(error)) {
	launch := func(name string, srv *http.Server) {
		if srv == nil {
			return
		}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) && onError != nil {
				onError(fmt.Errorf("telemetry: %s listener on %s: %w", name, srv.Addr, err))
			}
		}()
	}
	launch("metrics", s.metricsSrv)
	launch("health", s.healthSrv)
}

// Shutdown stops the listeners.
func (s *Server) Shutdown(ctx context.Context) error {
	var firstErr error
	for _, srv := range []*http.Server{s.metricsSrv, s.healthSrv} {
		if srv == nil {
			continue
		}
		if err := srv.Shutdown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
