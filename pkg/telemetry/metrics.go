// Package telemetry exposes the recorder's own observability surface:
// Prometheus metrics, Kubernetes health probes, and the append-only audit log
// of the tool's actions.
//
// The audit log is not a convenience. A tool that runs with CAP_SYS_PTRACE and
// reads other processes' memory must be able to account for every time it did
// so; "what did the forensic tool touch, and when" is the first question asked
// when the tool itself comes under scrutiny.
package telemetry

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics holds every instrument the recorder publishes.
//
// Label cardinality is bounded deliberately: container_id and pod_name are NOT
// labels on the high-frequency counters. A node running a few thousand
// short-lived pods would otherwise generate a few thousand time series per
// counter and overwhelm the scrape endpoint - a self-inflicted denial of
// service on the monitoring stack. Per-container detail lives in the audit log
// and in the evidence bundle, where it belongs.
type Metrics struct {
	EventsTotal      *prometheus.CounterVec
	EventsDropped    prometheus.Counter
	RingbufLost      prometheus.Counter
	CapturesTotal    *prometheus.CounterVec
	CapturesDropped  *prometheus.CounterVec
	CaptureDuration  prometheus.Histogram
	CaptureBytes     prometheus.Counter
	CapturePartial   prometheus.Counter
	CaptureFailed    prometheus.Counter
	SealDuration     prometheus.Histogram
	ExportTotal      *prometheus.CounterVec
	ExportDuration   *prometheus.HistogramVec
	TriggerLatency   prometheus.Histogram
	QueueDepth       prometheus.Gauge
	WorkersActive    prometheus.Gauge
	EvidenceBytes    prometheus.Gauge
	EvidenceBundles  prometheus.Gauge
	RetentionDeleted *prometheus.CounterVec
	ConfigReloads    *prometheus.CounterVec
	CPUPercent       prometheus.Gauge
	Ready            prometheus.Gauge
	BuildInfo        *prometheus.GaugeVec

	registry *prometheus.Registry
}

// NewMetrics constructs and registers every instrument on a private registry.
//
// A private registry (rather than the default global one) keeps the scrape
// output limited to this tool's own metrics plus the standard Go and process
// collectors, which is what an operator sizing the recorder's overhead needs.
func NewMetrics() *Metrics {
	reg := prometheus.NewRegistry()

	m := &Metrics{
		registry: reg,

		EventsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flight_recorder_events_total",
			Help: "eBPF events received from the ring buffer, by kind.",
		}, []string{"kind"}),

		EventsDropped: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flight_recorder_events_dropped_total",
			Help: "Events discarded in userspace because the processing queue was full.",
		}),

		RingbufLost: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flight_recorder_ringbuf_lost_total",
			Help: "Events the kernel could not place in the ring buffer (buffer full).",
		}),

		CapturesTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flight_recorder_captures_total",
			Help: "Memory captures attempted, by rule and outcome.",
		}, []string{"rule", "outcome"}),

		CapturesDropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flight_recorder_captures_dropped_total",
			Help: "Captures not attempted, by reason (rate limit, queue full, disk guard).",
		}, []string{"reason"}),

		CaptureDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "flight_recorder_capture_duration_ms",
			Help: "End-to-end capture latency in milliseconds (trigger to sealed bundle).",
			// Buckets span the interesting range: sub-100ms is the target for
			// small processes, 10s is where the ephemeral race is already lost.
			Buckets: []float64{10, 25, 50, 100, 200, 400, 800, 1600, 3200, 6400, 12800},
		}),

		CaptureBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flight_recorder_capture_bytes_total",
			Help: "Total bytes of process memory acquired.",
		}),

		CapturePartial: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flight_recorder_capture_partial_total",
			Help: "Captures that completed with at least one partial or failed region.",
		}),

		CaptureFailed: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "flight_recorder_capture_failed_total",
			Help: "Captures that produced no evidence at all.",
		}),

		SealDuration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "flight_recorder_seal_duration_ms",
			Help:    "Merkle tree construction and signing time in milliseconds.",
			Buckets: []float64{1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500},
		}),

		ExportTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flight_recorder_export_total",
			Help: "Evidence notifications sent to external systems, by target and result.",
		}, []string{"target", "result"}),

		ExportDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "flight_recorder_export_duration_ms",
			Help:    "Time to deliver a notification to an external system.",
			Buckets: []float64{5, 10, 25, 50, 100, 250, 500, 1000, 5000},
		}, []string{"target"}),

		TriggerLatency: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "flight_recorder_trigger_latency_ms",
			Help:    "Time from the kernel observing execve to userspace beginning acquisition.",
			Buckets: []float64{0.5, 1, 2, 5, 10, 25, 50, 100, 250, 500},
		}),

		QueueDepth: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flight_recorder_queue_depth",
			Help: "Captures currently queued for a worker.",
		}),

		WorkersActive: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flight_recorder_workers_active",
			Help: "Capture workers currently executing.",
		}),

		EvidenceBytes: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flight_recorder_evidence_bytes",
			Help: "Bytes occupied by the local evidence directory.",
		}),

		EvidenceBundles: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flight_recorder_evidence_bundles",
			Help: "Evidence bundles currently stored locally.",
		}),

		RetentionDeleted: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flight_recorder_retention_deleted_total",
			Help: "Evidence bundles deleted by the retention policy, by reason.",
		}, []string{"reason"}),

		ConfigReloads: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "flight_recorder_config_reloads_total",
			Help: "Trigger configuration reloads, by result.",
		}, []string{"result"}),

		CPUPercent: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flight_recorder_cpu_percent",
			Help: "Self-reported CPU utilisation of the recorder process.",
		}),

		Ready: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "flight_recorder_ready",
			Help: "1 when eBPF programs are attached and the ring buffer is being consumed.",
		}),

		BuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "flight_recorder_build_info",
			Help: "Build identity of the running recorder (always 1).",
		}, []string{"version", "commit", "go_version", "kernel"}),
	}

	reg.MustRegister(
		m.EventsTotal, m.EventsDropped, m.RingbufLost,
		m.CapturesTotal, m.CapturesDropped, m.CaptureDuration, m.CaptureBytes,
		m.CapturePartial, m.CaptureFailed, m.SealDuration,
		m.ExportTotal, m.ExportDuration, m.TriggerLatency,
		m.QueueDepth, m.WorkersActive, m.EvidenceBytes, m.EvidenceBundles,
		m.RetentionDeleted, m.ConfigReloads, m.CPUPercent, m.Ready, m.BuildInfo,
	)

	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	return m
}

// Registry exposes the private registry for the HTTP handler and for tests.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// SetBuildInfo publishes build identity as a labelled gauge.
func (m *Metrics) SetBuildInfo(version, commit, goVersion, kernel string) {
	m.BuildInfo.WithLabelValues(version, commit, goVersion, kernel).Set(1)
}
