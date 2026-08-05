// Package pipeline turns kernel events into sealed, exported evidence.
//
// The shape of this package is dictated by one constraint: the ring buffer
// reader must never block. A container that executes a payload and exits three
// seconds later gives us a window measured in hundreds of milliseconds, and any
// design where a slow capture stalls event consumption loses the next event
// entirely. So events are matched on the reader goroutine (cheap), and
// acquisition, sealing and export happen on a bounded worker pool (expensive).
// When the pool is saturated the pipeline drops explicitly, counts the drop,
// and writes it to the audit log - a recorded drop is recoverable knowledge, a
// silent one is not.
package pipeline

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"

	"github.com/Unspekable1654/flight-recorder/pkg/capture"
	"github.com/Unspekable1654/flight-recorder/pkg/config"
	"github.com/Unspekable1654/flight-recorder/pkg/container"
	"github.com/Unspekable1654/flight-recorder/pkg/evidence"
	"github.com/Unspekable1654/flight-recorder/pkg/export"
	"github.com/Unspekable1654/flight-recorder/pkg/format"
	"github.com/Unspekable1654/flight-recorder/pkg/probe"
	"github.com/Unspekable1654/flight-recorder/pkg/seal"
	"github.com/Unspekable1654/flight-recorder/pkg/telemetry"
)

// Publisher receives completed captures, used by the gRPC stream.
type Publisher interface {
	Publish(export.Notification)
}

// Options configure the pipeline.
type Options struct {
	Config    *config.Store
	Resolver  *container.Resolver
	Signer    *seal.Signer
	Writer    *evidence.Writer
	Exporters *export.Multi
	Metrics   *telemetry.Metrics
	Audit     *telemetry.AuditLog
	Health    *telemetry.Health
	Publisher Publisher
	Logger    zerolog.Logger

	// Workers is the number of concurrent captures. More workers means more
	// simultaneous captures but also more simultaneous memory pressure: each
	// worker can hold up to MaxDumpBytes.
	Workers int
	// QueueSize bounds pending captures.
	QueueSize int
	// CaptureTimeout bounds one end-to-end capture.
	CaptureTimeout time.Duration
	// ShutdownGrace is how long in-flight captures may take to finish sealing
	// after a SIGTERM.
	ShutdownGrace time.Duration

	ProcRoot          string
	EvidenceRoot      string
	EvidenceURIPrefix string
	NodeName          string
	Operator          string
	KernelVersion     string
	MaxDumpBytes      int64
	IncludeFileBacked bool
	IncludeVDSO       bool
	DryRun            bool
	// BootWallClock converts monotonic kernel timestamps to absolute time.
	BootWallClock time.Time
}

// Stats is a snapshot of pipeline counters.
type Stats struct {
	EventsSeen      uint64 `json:"events_seen"`
	EventsMatched   uint64 `json:"events_matched"`
	CapturesQueued  uint64 `json:"captures_queued"`
	CapturesDone    uint64 `json:"captures_completed"`
	CapturesFailed  uint64 `json:"captures_failed"`
	CapturesDropped uint64 `json:"captures_dropped"`
	BytesCaptured   uint64 `json:"bytes_captured"`
	ExitsSeen       uint64 `json:"exits_seen"`
}

// Pipeline is the event-to-evidence engine.
type Pipeline struct {
	opts Options
	log  zerolog.Logger

	limiter *RateLimiter
	jobs    chan job

	redaction     []*regexp.Regexp
	redactionName []string

	stats  Stats
	statMu sync.Mutex

	inFlight atomic.Int64
	queued   atomic.Int64
	stopping atomic.Bool
}

type job struct {
	event    probe.Event
	rule     config.Rule
	observed time.Time
}

// New validates options and builds a pipeline.
func New(opts Options) (*Pipeline, error) {
	if opts.Config == nil {
		return nil, errors.New("pipeline: config store is required")
	}
	if opts.Signer == nil {
		return nil, errors.New("pipeline: signer is required")
	}
	if opts.Writer == nil && !opts.DryRun {
		return nil, errors.New("pipeline: evidence writer is required unless running with --dry-run")
	}
	if opts.Resolver == nil {
		opts.Resolver = container.NewResolver(container.WithProcRoot(opts.ProcRoot), container.WithNodeName(opts.NodeName))
	}
	if opts.Workers <= 0 {
		opts.Workers = 4
	}
	if opts.QueueSize <= 0 {
		opts.QueueSize = 16
	}
	if opts.CaptureTimeout <= 0 {
		opts.CaptureTimeout = 30 * time.Second
	}
	if opts.ShutdownGrace <= 0 {
		opts.ShutdownGrace = 15 * time.Second
	}
	if opts.ProcRoot == "" {
		opts.ProcRoot = capture.DefaultProcRoot
	}
	if opts.Exporters == nil {
		opts.Exporters = export.NewMulti()
	}

	cfg := opts.Config.Get()

	p := &Pipeline{
		opts:    opts,
		log:     opts.Logger,
		limiter: NewRateLimiter(cfg.MaxCapturesPerMinute, cfg.MaxCapturesPerContainerPerMin),
		jobs:    make(chan job, opts.QueueSize),
	}

	if cfg.RedactionEnabled {
		res, names, err := cfg.RedactionRegexes()
		if err != nil {
			return nil, err
		}
		p.redaction, p.redactionName = res, names
	}

	opts.Config.OnReload(func(c *config.Config) {
		p.limiter.SetLimits(c.MaxCapturesPerMinute, c.MaxCapturesPerContainerPerMin)
		if c.RedactionEnabled {
			if res, names, err := c.RedactionRegexes(); err == nil {
				p.redaction, p.redactionName = res, names
			}
		} else {
			p.redaction, p.redactionName = nil, nil
		}
	})

	return p, nil
}

// Run consumes events until the channel closes or ctx is cancelled.
//
// On cancellation the queue is closed and workers are given ShutdownGrace to
// finish. An in-flight capture that cannot finish in time is sealed with
// whatever it has and marked partial_shutdown: partial evidence with an honest
// label beats no evidence.
func (p *Pipeline) Run(ctx context.Context, events <-chan probe.Event) error {
	workerCtx, cancelWorkers := context.WithCancel(context.Background())
	defer cancelWorkers()

	var wg sync.WaitGroup
	for i := 0; i < p.opts.Workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			p.worker(workerCtx, id)
		}(i)
	}

	// Housekeeping: purge caches that would otherwise grow with pod churn.
	housekeep := time.NewTicker(5 * time.Minute)
	defer housekeep.Stop()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-housekeep.C:
				p.limiter.Purge()
				p.opts.Resolver.Purge()
			}
		}
	}()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop

		case event, ok := <-events:
			if !ok {
				break loop
			}
			p.handleEvent(event)
		}
	}

	p.stopping.Store(true)
	close(p.jobs)

	// Wait for workers, bounded by the shutdown grace period.
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(p.opts.ShutdownGrace):
		p.log.Warn().
			Dur("grace", p.opts.ShutdownGrace).
			Int64("in_flight", p.inFlight.Load()).
			Msg("shutdown grace expired; cancelling in-flight captures")
		cancelWorkers()
		<-done
	}

	return nil
}

// handleEvent runs on the reader goroutine and must stay cheap.
func (p *Pipeline) handleEvent(event probe.Event) {
	if p.opts.Health != nil {
		p.opts.Health.RecordEvent()
	}
	if p.opts.Metrics != nil {
		p.opts.Metrics.EventsTotal.WithLabelValues(event.Kind.String()).Inc()
	}

	p.bump(func(s *Stats) { s.EventsSeen++ })

	if event.Kind == probe.KindExit {
		p.bump(func(s *Stats) { s.ExitsSeen++ })
		return
	}

	cfg := p.opts.Config.Get()
	cmdline := event.CommandLine()

	rule, matched := cfg.Match(cmdline, event.Comm)
	if !matched {
		return
	}

	p.bump(func(s *Stats) { s.EventsMatched++ })

	select {
	case p.jobs <- job{event: event, rule: rule, observed: time.Now()}:
		p.queued.Add(1)
		p.bump(func(s *Stats) { s.CapturesQueued++ })
		if p.opts.Metrics != nil {
			p.opts.Metrics.QueueDepth.Set(float64(p.queued.Load()))
		}
	default:
		p.dropCapture(event, rule, "capture queue full")
	}
}

func (p *Pipeline) dropCapture(event probe.Event, rule config.Rule, reason string) {
	p.bump(func(s *Stats) { s.CapturesDropped++ })
	if p.opts.Metrics != nil {
		p.opts.Metrics.CapturesDropped.WithLabelValues(reason).Inc()
	}
	p.log.Warn().
		Str("rule", rule.Name).
		Uint32("pid", event.HostPID).
		Str("comm", event.Comm).
		Str("cmdline", event.CommandLine()).
		Str("reason", reason).
		Msg("capture dropped")

	_ = p.opts.Audit.Write(telemetry.AuditEntry{
		Action:   telemetry.AuditCaptureDropped,
		Rule:     rule.Name,
		Severity: string(rule.Severity),
		HostPID:  int(event.HostPID),
		Comm:     event.Comm,
		Cmdline:  event.CommandLine(),
		Reason:   reason,
	})
}

func (p *Pipeline) worker(ctx context.Context, id int) {
	for j := range p.jobs {
		p.queued.Add(-1)
		p.inFlight.Add(1)
		if p.opts.Metrics != nil {
			p.opts.Metrics.QueueDepth.Set(float64(p.queued.Load()))
			p.opts.Metrics.WorkersActive.Set(float64(p.inFlight.Load()))
		}

		captureCtx, cancel := context.WithTimeout(ctx, p.opts.CaptureTimeout)
		if err := p.process(captureCtx, j); err != nil {
			p.bump(func(s *Stats) { s.CapturesFailed++ })
			if p.opts.Metrics != nil {
				p.opts.Metrics.CaptureFailed.Inc()
				p.opts.Metrics.CapturesTotal.WithLabelValues(j.rule.Name, "failed").Inc()
			}
			p.log.Error().
				Err(err).
				Int("worker", id).
				Str("rule", j.rule.Name).
				Uint32("pid", j.event.HostPID).
				Str("comm", j.event.Comm).
				Msg("capture failed")

			_ = p.opts.Audit.Write(telemetry.AuditEntry{
				Action:   telemetry.AuditCaptureFailed,
				Rule:     j.rule.Name,
				Severity: string(j.rule.Severity),
				HostPID:  int(j.event.HostPID),
				Comm:     j.event.Comm,
				Cmdline:  j.event.CommandLine(),
				Reason:   err.Error(),
			})
		}
		cancel()

		p.inFlight.Add(-1)
		if p.opts.Metrics != nil {
			p.opts.Metrics.WorkersActive.Set(float64(p.inFlight.Load()))
		}
	}
}

// process performs one complete capture: resolve, acquire, seal, format,
// store, export, audit.
func (p *Pipeline) process(ctx context.Context, j job) error {
	cfg := p.opts.Config.Get()
	event := j.event
	start := time.Now()

	// --- pick the PID we can actually act on ---------------------------------
	targetPID := p.targetPID(event)

	// --- resolve the workload ------------------------------------------------
	info, err := p.opts.Resolver.Resolve(event.CgroupID, targetPID)
	if err != nil {
		p.log.Debug().Err(err).Uint32("pid", event.HostPID).Msg("container resolution incomplete")
	}
	if info == nil {
		info = &container.Info{HostPID: targetPID, CgroupID: event.CgroupID, NodeName: p.opts.NodeName}
	}
	if info.NamespacePID == 0 {
		info.NamespacePID = int(event.NamespacePID)
	}

	if !cfg.WatchesNamespace(info.PodNamespace) {
		return nil
	}

	// --- rate limit ----------------------------------------------------------
	limitKey := info.ContainerID
	if limitKey == "" {
		limitKey = fmt.Sprintf("host-%d", event.HostTGID)
	}
	if ok, reason := p.limiter.Allow(limitKey); !ok {
		p.dropCapture(event, j.rule, reason)
		return nil
	}

	// --- disk guard ----------------------------------------------------------
	if p.opts.EvidenceRoot != "" && cfg.MaxDiskUsageMB > 0 {
		used, err := evidence.DiskUsage(p.opts.EvidenceRoot)
		if err == nil {
			if p.opts.Metrics != nil {
				p.opts.Metrics.EvidenceBytes.Set(float64(used))
			}
			if used > int64(cfg.MaxDiskUsageMB)*1024*1024 {
				p.dropCapture(event, j.rule, "evidence disk usage limit reached")
				return nil
			}
		}
	}

	caseID := format.NewCaseID()
	triggerTime := event.ReceivedAt
	if !p.opts.BootWallClock.IsZero() && event.TimestampNS > 0 {
		triggerTime = event.BootTime(p.opts.BootWallClock)
	}

	triggerLatency := float64(time.Since(triggerTime).Microseconds()) / 1000.0
	if p.opts.Metrics != nil && triggerLatency >= 0 {
		p.opts.Metrics.TriggerLatency.Observe(triggerLatency)
	}

	p.log.Info().
		Str("case_id", caseID).
		Str("rule", j.rule.Name).
		Str("severity", string(j.rule.Severity)).
		Uint32("host_pid", event.HostPID).
		Int("target_pid", targetPID).
		Int("ns_pid", info.NamespacePID).
		Str("comm", event.Comm).
		Str("cmdline", event.CommandLine()).
		Str("target", info.Describe()).
		Float64("trigger_latency_ms", triggerLatency).
		Msg("trigger matched")

	_ = p.opts.Audit.Write(telemetry.AuditEntry{
		Action:      telemetry.AuditTriggerMatched,
		CaseID:      caseID,
		Rule:        j.rule.Name,
		Severity:    string(j.rule.Severity),
		HostPID:     int(event.HostPID),
		NSPid:       info.NamespacePID,
		Comm:        event.Comm,
		Cmdline:     event.CommandLine(),
		ContainerID: info.ContainerID,
		PodName:     info.PodName,
		PodNS:       info.PodNamespace,
	})

	if p.opts.DryRun {
		p.log.Info().Str("case_id", caseID).Msg("dry run: memory acquisition skipped")
		return nil
	}

	// --- acquire -------------------------------------------------------------
	filter := capture.DefaultFilterOptions()
	filter.IncludeFileBacked = p.opts.IncludeFileBacked
	filter.IncludeVDSO = p.opts.IncludeVDSO

	maxBytes := p.opts.MaxDumpBytes
	if cfg.MaxDumpSizeMB > 0 {
		maxBytes = int64(cfg.MaxDumpSizeMB) * 1024 * 1024
	}

	dump, err := capture.DumpProcessMemory(ctx, targetPID, capture.Options{
		ProcRoot:         p.opts.ProcRoot,
		Filter:           filter,
		MaxBytes:         maxBytes,
		ExpectedCgroupID: event.CgroupID,
	})
	if err != nil {
		// A process that exited before we reached it is the expected outcome
		// for the fastest containers, and is data rather than an error: it
		// bounds the capture window that the architecture can serve.
		if errors.Is(err, capture.ErrProcessGone) || errors.Is(err, capture.ErrIdentityMismatch) {
			p.log.Warn().
				Str("case_id", caseID).
				Uint32("pid", event.HostPID).
				Dur("since_trigger", time.Since(triggerTime)).
				Err(err).
				Msg("target vanished before acquisition")
			if p.opts.Metrics != nil {
				p.opts.Metrics.CapturesTotal.WithLabelValues(j.rule.Name, "target_gone").Inc()
			}
			return nil
		}
		return fmt.Errorf("acquire memory: %w", err)
	}
	dump.NamespacePID = info.NamespacePID
	dump.CgroupID = event.CgroupID

	if dump.TotalBytes == 0 {
		p.log.Warn().
			Str("case_id", caseID).
			Uint32("pid", event.HostPID).
			Int("skipped_regions", dump.SkippedRegions).
			Msg("acquisition produced no readable memory")
		if p.opts.Metrics != nil {
			p.opts.Metrics.CapturesTotal.WithLabelValues(j.rule.Name, "empty").Inc()
		}
		return nil
	}

	// --- redact (optional, before sealing) -----------------------------------
	if len(p.redaction) > 0 {
		n := dump.Redact(p.redaction, p.redactionName)
		if n > 0 {
			p.log.Info().Str("case_id", caseID).Int("matches", n).Msg("redaction applied before sealing")
		}
	}

	payload := dump.Bytes()
	dump.Release()

	// --- seal, render CASE/UCO, store ----------------------------------------
	result, err := SealAndStore(SealStoreInput{
		CaseID:        caseID,
		Payload:       payload,
		Dump:          dump,
		Rule:          j.rule,
		Event:         event,
		Info:          info,
		TriggerTime:   triggerTime,
		Signer:        p.opts.Signer,
		Writer:        p.opts.Writer,
		NodeName:      p.opts.NodeName,
		Operator:      p.opts.Operator,
		KernelVersion: p.opts.KernelVersion,
		EvidenceRoot:  p.opts.EvidenceRoot,
		Encrypted:     true,
		Compression:   evidence.CompressionZstd,
	})
	if err != nil {
		return err
	}
	receipt := result.Receipt
	written := result.Written

	if p.opts.Metrics != nil {
		p.opts.Metrics.SealDuration.Observe(float64(result.SealDuration.Microseconds()) / 1000.0)
	}

	totalMS := float64(time.Since(start).Microseconds()) / 1000.0

	p.bump(func(s *Stats) {
		s.CapturesDone++
		s.BytesCaptured += uint64(len(payload))
	})

	if p.opts.Metrics != nil {
		p.opts.Metrics.CapturesTotal.WithLabelValues(j.rule.Name, string(dump.Outcome())).Inc()
		p.opts.Metrics.CaptureDuration.Observe(totalMS)
		p.opts.Metrics.CaptureBytes.Add(float64(len(payload)))
		if dump.PartialRegions > 0 || dump.FailedRegions > 0 {
			p.opts.Metrics.CapturePartial.Inc()
		}
	}

	p.log.Info().
		Str("case_id", caseID).
		Str("rule", j.rule.Name).
		Str("target", info.Describe()).
		Int64("bytes", int64(len(payload))).
		Int("regions", len(dump.Regions)).
		Str("status", string(dump.Outcome())).
		Str("merkle_root", receipt.RootHash).
		Float64("total_ms", totalMS).
		Float64("acquire_ms", float64(dump.Duration().Microseconds())/1000.0).
		Str("bundle", written.Dir).
		Msg("evidence sealed")

	_ = p.opts.Audit.Write(telemetry.AuditEntry{
		Action:       telemetry.AuditBundleWritten,
		CaseID:       caseID,
		Rule:         j.rule.Name,
		Severity:     string(j.rule.Severity),
		HostPID:      int(event.HostPID),
		NSPid:        info.NamespacePID,
		Comm:         event.Comm,
		Cmdline:      event.CommandLine(),
		ContainerID:  info.ContainerID,
		PodName:      info.PodName,
		PodNS:        info.PodNamespace,
		Bytes:        int64(len(payload)),
		DurationMS:   totalMS,
		MerkleRoot:   receipt.RootHash,
		EvidencePath: written.Dir,
		Result:       string(dump.Outcome()),
	})

	// --- export --------------------------------------------------------------
	notification := result.Notification
	notification.LatencyMS = totalMS
	notification.EvidenceURI = p.evidenceURI(caseID, written.Dir)

	if p.opts.Publisher != nil {
		p.opts.Publisher.Publish(notification)
	}

	if p.opts.Exporters.Len() > 0 {
		// Export runs on the worker but with its own deadline: a slow SIEM must
		// not extend the capture timeout, and the evidence is already durable.
		exportCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		results := p.opts.Exporters.Send(exportCtx, notification)
		cancel()

		for _, res := range results {
			outcome := "success"
			if res.Err != nil {
				outcome = "failure"
				p.log.Warn().Err(res.Err).Str("target", res.Target).Str("case_id", caseID).Msg("export failed")
			}
			if p.opts.Metrics != nil {
				p.opts.Metrics.ExportTotal.WithLabelValues(res.Target, outcome).Inc()
				p.opts.Metrics.ExportDuration.WithLabelValues(res.Target).Observe(float64(res.Duration.Microseconds()) / 1000.0)
			}
			action := telemetry.AuditExportSent
			reason := ""
			if res.Err != nil {
				action = telemetry.AuditExportFailed
				reason = res.Err.Error()
			}
			_ = p.opts.Audit.Write(telemetry.AuditEntry{
				Action: action,
				CaseID: caseID,
				Target: res.Target,
				Result: outcome,
				Reason: reason,
			})
		}
	}

	return nil
}

// targetPID chooses the PID to acquire from.
//
// eBPF reports PIDs numbered in the host namespace, which is exactly right for
// the supported deployment (a DaemonSet with hostPID: true). When the recorder
// is instead confined to a PID namespace - during development, in a test
// harness, or in a misconfigured deployment - that number is invisible to it,
// and the namespace-local PID is the one that can actually be opened. Falling
// back keeps the tool usable in those environments; the startup warning tells
// the operator that production should not look like this.
func (p *Pipeline) targetPID(event probe.Event) int {
	host := int(event.HostPID)
	if capture.ProcessExists(p.opts.ProcRoot, host) {
		return host
	}

	ns := int(event.NamespacePID)
	if ns != 0 && ns != host && capture.ProcessExists(p.opts.ProcRoot, ns) {
		p.log.Debug().
			Int("host_pid", host).
			Int("ns_pid", ns).
			Msg("host PID is not visible in this PID namespace; acquiring the namespace-local PID instead")
		return ns
	}

	// Neither is visible: return the host PID so the failure is reported
	// against the identifier the kernel gave us.
	return host
}

func (p *Pipeline) evidenceURI(caseID, dir string) string {
	if p.opts.EvidenceURIPrefix != "" {
		return fmt.Sprintf("%s/%s", p.opts.EvidenceURIPrefix, caseID)
	}
	return "file://" + dir
}

// RegionReport is the serialisable memory map stored alongside the payload.
//
// It is what lets an examiner locate a finding: byte offset 4,194,304 in the
// dump means nothing until you know it is offset 0 of the [heap] mapping at
// 0x55d4f2a00000.
type RegionReport struct {
	PID               int                 `json:"pid"`
	NamespacePID      int                 `json:"namespace_pid"`
	Comm              string              `json:"comm"`
	CgroupID          uint64              `json:"cgroup_id"`
	CaptureStart      time.Time           `json:"capture_start"`
	CaptureEnd        time.Time           `json:"capture_end"`
	MapsParsedAt      time.Time           `json:"maps_parsed_at"`
	MapsToFirstReadMS float64             `json:"maps_to_first_read_ms"`
	TotalBytes        int64               `json:"total_bytes"`
	Outcome           string              `json:"outcome"`
	ParseSkippedLines int                 `json:"parse_skipped_lines"`
	Regions           []RegionReportEntry `json:"regions"`
	Skipped           []RegionReportEntry `json:"skipped"`
}

// RegionReportEntry describes one mapping and where it landed in the dump.
type RegionReportEntry struct {
	Start      string  `json:"start_addr"`
	End        string  `json:"end_addr"`
	Perms      string  `json:"perms"`
	Pathname   string  `json:"pathname"`
	Label      string  `json:"label"`
	Status     string  `json:"status"`
	BytesRead  int64   `json:"bytes_read"`
	BytesTotal int64   `json:"bytes_total"`
	DumpOffset int64   `json:"dump_offset"`
	ReadTimeMS float64 `json:"read_time_ms,omitempty"`
	Error      string  `json:"error,omitempty"`
}

func regionReport(d *capture.MemoryDump) RegionReport {
	report := RegionReport{
		PID:               d.PID,
		NamespacePID:      d.NamespacePID,
		Comm:              d.Comm,
		CgroupID:          d.CgroupID,
		CaptureStart:      d.CaptureStart.UTC(),
		CaptureEnd:        d.CaptureEnd.UTC(),
		MapsParsedAt:      d.MapsParsedAt.UTC(),
		MapsToFirstReadMS: d.MapsToFirstReadMS,
		TotalBytes:        d.TotalBytes,
		Outcome:           string(d.Outcome()),
		ParseSkippedLines: d.ParseSkippedLines,
	}

	var offset int64
	for _, r := range d.Regions {
		entry := RegionReportEntry{
			Start:      fmt.Sprintf("%#x", r.StartAddr),
			End:        fmt.Sprintf("%#x", r.EndAddr),
			Perms:      r.Perms,
			Pathname:   r.Pathname,
			Label:      r.Label(),
			Status:     string(r.Status),
			BytesRead:  r.BytesRead,
			BytesTotal: r.BytesTotal,
			DumpOffset: offset,
			ReadTimeMS: r.ReadTimeMS,
			Error:      r.Error,
		}
		offset += r.BytesRead
		report.Regions = append(report.Regions, entry)
	}

	for _, r := range d.Skipped {
		report.Skipped = append(report.Skipped, RegionReportEntry{
			Start:      fmt.Sprintf("%#x", r.StartAddr),
			End:        fmt.Sprintf("%#x", r.EndAddr),
			Perms:      r.Perms,
			Pathname:   r.Pathname,
			Label:      r.Label(),
			Status:     string(r.Status),
			BytesTotal: r.BytesTotal,
			Error:      r.Error,
		})
	}

	return report
}

func outcomeToStatus(o capture.Outcome) seal.Status {
	switch o {
	case capture.OutcomeComplete:
		return seal.StatusComplete
	case capture.OutcomeTruncated:
		return seal.StatusTruncated
	case capture.OutcomeProcessExited:
		return seal.StatusProcessExited
	case capture.OutcomeInterrupted:
		return seal.StatusPartialShutdown
	default:
		return seal.StatusPartial
	}
}

func statusDetail(d *capture.MemoryDump) string {
	if d.PartialRegions == 0 && d.FailedRegions == 0 && !d.Truncated && !d.ProcessExited && !d.Interrupted {
		return ""
	}
	return fmt.Sprintf("%d full, %d partial, %d failed, %d skipped regions",
		d.FullRegions, d.PartialRegions, d.FailedRegions, d.SkippedRegions)
}

// Stats returns a snapshot of the counters.
func (p *Pipeline) Stats() Stats {
	p.statMu.Lock()
	defer p.statMu.Unlock()
	return p.stats
}

func (p *Pipeline) bump(fn func(*Stats)) {
	p.statMu.Lock()
	fn(&p.stats)
	p.statMu.Unlock()
}
