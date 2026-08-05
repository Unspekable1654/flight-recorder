package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/Unspekable1654/flight-recorder/pkg/config"
	"github.com/Unspekable1654/flight-recorder/pkg/container"
	"github.com/Unspekable1654/flight-recorder/pkg/evidence"
	"github.com/Unspekable1654/flight-recorder/pkg/export"
	evidencepb "github.com/Unspekable1654/flight-recorder/pkg/export/grpc"
	"github.com/Unspekable1654/flight-recorder/pkg/pipeline"
	"github.com/Unspekable1654/flight-recorder/pkg/probe"
	"github.com/Unspekable1654/flight-recorder/pkg/seal"
	"github.com/Unspekable1654/flight-recorder/pkg/telemetry"
	"github.com/Unspekable1654/flight-recorder/pkg/version"
)

type startOptions struct {
	configPath string
	triggers   []string
	mode       string

	output       string
	keyPath      string
	auditPath    string
	procRoot     string
	pinPath      string
	noPin        bool
	nodeName     string
	operator     string
	uriPrefix    string
	k8sEnrich    bool
	trackExits   bool
	includeFiles bool
	includeVDSO  bool
	dryRun       bool
	noEncrypt    bool
	noCompress   bool
	redact       bool

	workers        int
	queueSize      int
	captureTimeout time.Duration
	shutdownGrace  time.Duration
	maxPerMinute   int
	maxDumpMB      int
	maxDiskMB      int
	retentionDays  int

	metricsAddr string
	healthAddr  string
	grpcAddr    string
	pprof       bool

	webhookURL     string
	webhookHeaders []string
	splunkURL      string
	splunkToken    string
	splunkIndex    string
	elasticURL     string
	elasticIndex   string
	elasticAPIKey  string
	syslogAddr     string
	syslogNetwork  string
	syslogFormat   string
	notifyFile     string
	insecureTLS    bool
}

func newStartCommand() *cobra.Command {
	opts := &startOptions{}

	cmd := &cobra.Command{
		Use:   "start",
		Short: "Load the eBPF probes and begin preserving evidence",
		Long: `Attach the kernel probes and run the capture pipeline until terminated.

Requires Linux with a kernel providing BTF and BPF ring buffers (5.8+; 6.1+
recommended) and the capabilities CAP_BPF, CAP_PERFMON and CAP_SYS_PTRACE
(or CAP_SYS_ADMIN on kernels before 5.8).

Signals:
  SIGTERM, SIGINT  drain in-flight captures, seal what exists, detach, exit 0
  SIGHUP           reload the trigger ruleset without restarting`,
		Example: `  # Production: rules from a mounted ConfigMap, evidence on a host path
  flight-recorder start \
      --config /etc/flight-recorder/triggers.yaml \
      --output /var/lib/flight-recorder/evidence \
      --siem-webhook https://soar.internal/hooks/flight-recorder

  # Ad hoc: inline triggers, no external systems
  flight-recorder start --trigger "cat /etc/shadow,curl,xmrig" --output ./evidence

  # See what would be captured without touching any process memory
  flight-recorder start --trigger curl --dry-run`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStart(cmd, opts)
		},
	}

	f := cmd.Flags()
	f.StringVarP(&opts.configPath, "config", "c", "", "path to triggers.yaml (hot-reloaded on change)")
	f.StringSliceVar(&opts.triggers, "trigger", nil, "inline trigger substrings, comma separated (alternative to --config)")
	f.StringVar(&opts.mode, "mode", "", `capture mode: "trigger" (default) or "all"`)

	f.StringVarP(&opts.output, "output", "o", "/var/lib/flight-recorder/evidence", "evidence directory")
	f.StringVar(&opts.keyPath, "key", "/etc/flight-recorder/key.pem", "ECDSA signing key (generated on first run)")
	f.StringVar(&opts.auditPath, "audit-log", "/var/log/flight-recorder/audit.jsonl", "append-only audit log (empty to disable)")
	f.StringVar(&opts.procRoot, "proc-root", "/proc", "procfs mount point (/host/proc inside a DaemonSet)")
	f.StringVar(&opts.pinPath, "pin-path", "/sys/fs/bpf/flight-recorder", "bpffs directory for pinned programs and links")
	f.BoolVar(&opts.noPin, "no-pin", false, "do not pin eBPF objects (monitoring gaps on restart)")
	f.StringVar(&opts.nodeName, "node-name", "", "node name recorded in evidence (defaults to $NODE_NAME or hostname)")
	f.StringVar(&opts.operator, "operator", "", "operator identity recorded in the chain of custody")
	f.StringVar(&opts.uriPrefix, "evidence-uri-prefix", "", "URI prefix for evidence references sent to SIEM (e.g. s3://bucket/path)")
	f.BoolVar(&opts.k8sEnrich, "k8s-enrich", true, "resolve pod names from the Kubernetes API when running in-cluster")
	f.BoolVar(&opts.trackExits, "track-exits", true, "also observe process exits (used to characterise the capture race)")
	f.BoolVar(&opts.includeFiles, "include-file-backed", false, "acquire read-only file-backed mappings (large; usually recoverable from the image)")
	f.BoolVar(&opts.includeVDSO, "include-vdso", false, "acquire [vdso] and kernel pseudo-mappings")
	f.BoolVar(&opts.dryRun, "dry-run", false, "match rules and log, but never read process memory")
	f.BoolVar(&opts.noEncrypt, "no-encrypt", false, "store payloads unencrypted (lab use only)")
	f.BoolVar(&opts.noCompress, "no-compress", false, "store payloads uncompressed")
	f.BoolVar(&opts.redact, "redact", false, "redact PII patterns before sealing (changes the sealed bytes; see docs)")

	f.IntVar(&opts.workers, "workers", 4, "concurrent capture workers")
	f.IntVar(&opts.queueSize, "queue-size", 16, "pending capture queue depth")
	f.DurationVar(&opts.captureTimeout, "capture-timeout", 30*time.Second, "per-capture timeout")
	f.DurationVar(&opts.shutdownGrace, "shutdown-grace", 15*time.Second, "time allowed for in-flight captures on shutdown")
	f.IntVar(&opts.maxPerMinute, "max-captures-per-min", 0, "override the configured global capture rate limit")
	f.IntVar(&opts.maxDumpMB, "max-dump-size-mb", 0, "override the configured per-capture size cap")
	f.IntVar(&opts.maxDiskMB, "max-disk-usage-mb", 0, "override the configured evidence directory size cap")
	f.IntVar(&opts.retentionDays, "retention-days", 0, "override the configured evidence retention period")

	f.StringVar(&opts.metricsAddr, "metrics-addr", ":9090", "Prometheus metrics listen address (empty to disable)")
	f.StringVar(&opts.healthAddr, "health-addr", ":8080", "health probe listen address (empty to disable)")
	f.StringVar(&opts.grpcAddr, "grpc-addr", "", "evidence API listen address, e.g. :9091 (empty to disable)")
	f.BoolVar(&opts.pprof, "pprof", false, "expose /debug/pprof on the health listener")

	f.StringVar(&opts.webhookURL, "siem-webhook", "", "POST capture notifications to this URL (SOAR integration)")
	f.StringArrayVar(&opts.webhookHeaders, "webhook-header", nil, "extra webhook header, repeatable: 'Name: value'")
	f.StringVar(&opts.splunkURL, "splunk-hec-url", "", "Splunk HEC endpoint")
	f.StringVar(&opts.splunkToken, "splunk-hec-token", "", "Splunk HEC token")
	f.StringVar(&opts.splunkIndex, "splunk-index", "forensics", "Splunk index")
	f.StringVar(&opts.elasticURL, "elastic-url", "", "Elasticsearch base URL")
	f.StringVar(&opts.elasticIndex, "elastic-index", "flight-recorder", "Elasticsearch index")
	f.StringVar(&opts.elasticAPIKey, "elastic-api-key", "", "Elasticsearch API key")
	f.StringVar(&opts.syslogAddr, "syslog-addr", "", "syslog collector address host:port")
	f.StringVar(&opts.syslogNetwork, "syslog-network", "udp", "syslog transport: udp, tcp or tcp+tls")
	f.StringVar(&opts.syslogFormat, "syslog-format", "rfc5424", "syslog encoding: rfc5424 or cef")
	f.StringVar(&opts.notifyFile, "notify-file", "", "append notifications to a local JSON Lines file")
	f.BoolVar(&opts.insecureTLS, "export-insecure-tls", false, "skip TLS verification for export targets")

	return cmd
}

func runStart(cmd *cobra.Command, opts *startOptions) error {
	log := newLogger()
	info := version.Get()

	log.Info().
		Str("version", info.Version).
		Str("commit", info.Commit).
		Str("platform", info.Platform).
		Str("self_sha256", info.SelfSHA256).
		Msg("flight recorder starting")

	// ---- configuration -----------------------------------------------------
	cfg, err := loadStartConfig(opts)
	if err != nil {
		return err
	}
	store := config.NewStore(cfg)

	rootCtx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	if opts.configPath != "" {
		if err := store.Watch(rootCtx, opts.configPath, func(err error) {
			log.Error().Err(err).Msg("configuration reload failed")
		}); err != nil {
			return err
		}
		log.Info().Str("path", opts.configPath).Int("rules", len(store.Get().Rules)).Msg("trigger ruleset loaded")
	}

	nodeName := resolveNodeName(opts.nodeName)

	// ---- signing key --------------------------------------------------------
	signer, generated, err := seal.LoadOrCreateSigner(opts.keyPath)
	if err != nil {
		return err
	}
	if generated {
		log.Warn().
			Str("path", opts.keyPath).
			Str("key_id", signer.KeyIDString()).
			Msg("generated a new signing key; back it up, evidence signed with it cannot be verified without it")
	}

	// ---- telemetry -----------------------------------------------------------
	metrics := telemetry.NewMetrics()
	health := telemetry.NewHealth()
	kernel := probe.KernelVersion()
	metrics.SetBuildInfo(info.Version, info.Commit, info.GoVersion, kernel)

	audit, err := telemetry.NewAuditLog(telemetry.AuditOptions{
		Path:        opts.auditPath,
		NodeName:    nodeName,
		ToolVersion: info.Version,
		Operator:    opts.operator,
	})
	if err != nil {
		// The audit log is important but not worth refusing to monitor over;
		// a loud warning is the right trade.
		log.Warn().Err(err).Msg("audit log unavailable; continuing without it")
		audit, _ = telemetry.NewAuditLog(telemetry.AuditOptions{})
	}
	defer func() { _ = audit.Close() }()

	_ = audit.Write(telemetry.AuditEntry{Action: telemetry.AuditStart, Reason: strings.Join(os.Args, " ")})
	if generated {
		_ = audit.Write(telemetry.AuditEntry{Action: telemetry.AuditKeyGenerated, Reason: signer.KeyIDString()})
	}

	telemetrySrv := telemetry.NewServer(telemetry.ServerOptions{
		MetricsAddr:  opts.metricsAddr,
		HealthAddr:   opts.healthAddr,
		Metrics:      metrics,
		Health:       health,
		PprofEnabled: opts.pprof,
	})
	telemetrySrv.Start(func(err error) { log.Error().Err(err).Msg("telemetry listener failed") })
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = telemetrySrv.Shutdown(shutdownCtx)
	}()

	// ---- PID namespace sanity check ---------------------------------------------
	// eBPF reports host-namespace PIDs. If this process cannot see them, every
	// capture will fail with "process does not exist" - a failure mode that is
	// almost impossible to diagnose from the symptom, so it is called out here.
	if inHost, err := container.InHostPIDNamespace(opts.procRoot); err != nil {
		log.Debug().Err(err).Msg("could not determine PID namespace membership")
	} else if !inHost {
		log.Warn().
			Str("proc_root", opts.procRoot).
			Msg("running inside a PID namespace: host PIDs reported by eBPF are not resolvable here. " +
				"Set hostPID: true on the DaemonSet and mount the host procfs at /host/proc (--proc-root). " +
				"Captures will fall back to namespace-local PIDs, which is correct only for processes in this namespace")
	}

	// ---- container resolution -------------------------------------------------
	resolverOpts := []container.ResolverOption{
		container.WithProcRoot(opts.procRoot),
		container.WithNodeName(nodeName),
	}
	if opts.k8sEnrich {
		enricher, err := container.NewKubeEnricher(container.KubeConfig{NodeName: nodeName})
		if err != nil {
			log.Info().Err(err).Msg("kubernetes enrichment unavailable; evidence will carry container ids only")
		} else {
			enricher.Start(rootCtx, 30*time.Second)
			resolverOpts = append(resolverOpts, container.WithEnricher(enricher))
			log.Info().Str("node", nodeName).Msg("kubernetes pod enrichment enabled")
		}
	}
	resolver := container.NewResolver(resolverOpts...)

	// ---- evidence storage ------------------------------------------------------
	writerOpts := evidence.DefaultWriterOptions(opts.output, signer)
	writerOpts.Encrypt = !opts.noEncrypt
	writerOpts.Compress = !opts.noCompress
	writer, err := evidence.NewWriter(writerOpts)
	if err != nil {
		return err
	}
	if opts.noEncrypt {
		log.Warn().Msg("payload encryption is disabled; memory dumps will be stored in the clear")
	}

	retention := &evidence.Retention{
		Root:      opts.output,
		MaxAge:    time.Duration(store.Get().RetentionDays) * 24 * time.Hour,
		MaxBytes:  int64(store.Get().MaxDiskUsageMB) * 1024 * 1024,
		MinRetain: 1,
		OnDelete: func(caseID, dir string, size int64, reason string) {
			log.Info().Str("case_id", caseID).Int64("bytes", size).Str("reason", reason).Msg("evidence bundle deleted by retention policy")
			_ = audit.Write(telemetry.AuditEntry{
				Action: telemetry.AuditBundleDeleted, CaseID: caseID, EvidencePath: dir, Bytes: size, Reason: reason,
			})
			metrics.RetentionDeleted.WithLabelValues(reason).Inc()
		},
	}
	retention.Run(rootCtx, time.Hour, func(res evidence.SweepResult, err error) {
		if err != nil {
			log.Error().Err(err).Msg("retention sweep failed")
			return
		}
		metrics.EvidenceBytes.Set(float64(res.BytesInUse))
		metrics.EvidenceBundles.Set(float64(res.Scanned - res.DeletedAge - res.DeletedSpace))
	})

	// ---- exporters --------------------------------------------------------------
	exporters, err := buildExporters(opts)
	if err != nil {
		return err
	}
	defer func() { _ = exporters.Close() }()
	if exporters.Len() > 0 {
		log.Info().Strs("targets", exporters.Names()).Msg("export targets configured")
	}

	// ---- evidence API -------------------------------------------------------------
	var publisher pipeline.Publisher
	if opts.grpcAddr != "" {
		apiServer, err := evidencepb.NewServer(evidencepb.ServerConfig{
			EvidenceRoot: opts.output,
			Signer:       signer,
			PublicKey:    signer.Public(),
		})
		if err != nil {
			return err
		}
		go func() {
			log.Info().Str("addr", opts.grpcAddr).Msg("evidence API listening")
			if err := apiServer.ListenAndServe(opts.grpcAddr); err != nil {
				log.Error().Err(err).Msg("evidence API stopped")
			}
		}()
		defer apiServer.Stop()
		publisher = apiServer
	}

	// ---- kernel probes ---------------------------------------------------------------
	pinPath := opts.pinPath
	if opts.noPin {
		pinPath = ""
	}

	activeCfg := store.Get()
	loadOpts := probe.LoadOptions{
		PinPath:      pinPath,
		TrackExits:   opts.trackExits,
		SelfTGID:     uint32(os.Getpid()),
		TriggerComms: activeCfg.PrefilterComms(),
	}
	loadOpts.Prefilter = len(loadOpts.TriggerComms) > 0

	kernelProbe, err := probe.Load(loadOpts)
	if err != nil {
		return err
	}
	defer func() { _ = kernelProbe.Close() }()

	health.SetProbesAttached(true)
	health.SetRingbufActive(true)
	metrics.Ready.Set(1)

	log.Info().
		Str("kernel", kernel).
		Bool("reused_pinned_links", kernelProbe.Reused()).
		Str("mode", string(activeCfg.Mode)).
		Int("rules", len(activeCfg.Rules)).
		Msg("eBPF probes attached")

	_ = audit.Write(telemetry.AuditEntry{Action: telemetry.AuditProbeAttached, Reason: kernel})

	store.OnReload(func(c *config.Config) {
		comms := c.PrefilterComms()
		if err := kernelProbe.SetTriggerComms(comms); err != nil {
			log.Error().Err(err).Msg("failed to update kernel prefilter")
			metrics.ConfigReloads.WithLabelValues("failure").Inc()
			return
		}
		if err := kernelProbe.SetPrefilterEnabled(len(comms) > 0, uint32(os.Getpid()), 0, opts.trackExits); err != nil {
			log.Error().Err(err).Msg("failed to update kernel config map")
			metrics.ConfigReloads.WithLabelValues("failure").Inc()
			return
		}
		metrics.ConfigReloads.WithLabelValues("success").Inc()
		log.Info().Int("rules", len(c.Rules)).Str("mode", string(c.Mode)).Msg("trigger ruleset reloaded")
		_ = audit.Write(telemetry.AuditEntry{Action: telemetry.AuditConfigReloaded, Reason: fmt.Sprintf("%d rules", len(c.Rules))})
	})

	bootClock, err := probe.BootWallClock()
	if err != nil {
		log.Warn().Err(err).Msg("boot clock unavailable; event timestamps will use receive time")
		bootClock = time.Time{}
	}

	// ---- pipeline -----------------------------------------------------------------------
	pipe, err := pipeline.New(pipeline.Options{
		Config:            store,
		Resolver:          resolver,
		Signer:            signer,
		Writer:            writer,
		Exporters:         exporters,
		Metrics:           metrics,
		Audit:             audit,
		Health:            health,
		Publisher:         publisher,
		Logger:            log,
		Workers:           opts.workers,
		QueueSize:         opts.queueSize,
		CaptureTimeout:    opts.captureTimeout,
		ShutdownGrace:     opts.shutdownGrace,
		ProcRoot:          opts.procRoot,
		EvidenceRoot:      opts.output,
		EvidenceURIPrefix: opts.uriPrefix,
		NodeName:          nodeName,
		Operator:          opts.operator,
		KernelVersion:     kernel,
		IncludeFileBacked: opts.includeFiles,
		IncludeVDSO:       opts.includeVDSO,
		DryRun:            opts.dryRun,
		BootWallClock:     bootClock,
	})
	if err != nil {
		return err
	}

	// ---- signals -------------------------------------------------------------------------
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(signals)

	go func() {
		for sig := range signals {
			switch sig {
			case syscall.SIGHUP:
				if opts.configPath == "" {
					log.Warn().Msg("SIGHUP received but no --config file is in use")
					continue
				}
				if err := store.Reload(); err != nil {
					log.Error().Err(err).Msg("SIGHUP reload rejected; previous ruleset remains active")
					metrics.ConfigReloads.WithLabelValues("failure").Inc()
					_ = audit.Write(telemetry.AuditEntry{Action: telemetry.AuditConfigRejected, Reason: err.Error()})
					continue
				}
			default:
				log.Info().Str("signal", sig.String()).Msg("shutdown requested; draining in-flight captures")
				health.BeginShutdown()
				metrics.Ready.Set(0)
				cancel()
				return
			}
		}
	}()

	// ---- kernel stats sampler ----------------------------------------------------------------
	go sampleKernelStats(rootCtx, kernelProbe, metrics, log)

	// ---- run ---------------------------------------------------------------------------------
	events := kernelProbe.Events(rootCtx, 4096)
	runErr := pipe.Run(rootCtx, events)

	stats := pipe.Stats()
	log.Info().
		Uint64("events", stats.EventsSeen).
		Uint64("matched", stats.EventsMatched).
		Uint64("captures", stats.CapturesDone).
		Uint64("failed", stats.CapturesFailed).
		Uint64("dropped", stats.CapturesDropped).
		Uint64("bytes", stats.BytesCaptured).
		Msg("pipeline stopped")

	_ = audit.Write(telemetry.AuditEntry{
		Action: telemetry.AuditStop,
		Reason: fmt.Sprintf("events=%d captures=%d failed=%d dropped=%d", stats.EventsSeen, stats.CapturesDone, stats.CapturesFailed, stats.CapturesDropped),
	})

	if pinPath != "" {
		log.Info().Str("pin_path", pinPath).Msg("leaving eBPF objects pinned for gapless restart")
	}

	return runErr
}

// sampleKernelStats copies kernel-side counters into Prometheus.
//
// Ring buffer drops are only visible from inside the kernel, and they are the
// single most important signal that the node is losing evidence.
func sampleKernelStats(ctx context.Context, p *probe.Probe, m *telemetry.Metrics, log zerolog.Logger) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	var lastDropped uint64
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			stats, err := p.Stats()
			if err != nil {
				continue
			}
			if stats.RingbufDropped > lastDropped {
				delta := stats.RingbufDropped - lastDropped
				m.RingbufLost.Add(float64(delta))
				log.Warn().
					Uint64("dropped", delta).
					Uint64("total", stats.RingbufDropped).
					Msg("kernel could not enqueue events: ring buffer full, events lost")
				lastDropped = stats.RingbufDropped
			}
		}
	}
}

func loadStartConfig(opts *startOptions) (*config.Config, error) {
	var cfg *config.Config

	switch {
	case opts.configPath != "":
		loaded, err := config.Load(opts.configPath)
		if err != nil {
			return nil, err
		}
		cfg = loaded

	case len(opts.triggers) > 0:
		cfg = config.Default()
		cfg.Rules = nil
		for _, t := range opts.triggers {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			cfg.Rules = append(cfg.Rules, config.Rule{
				Name:        "inline_" + sanitiseRuleName(t),
				Match:       t,
				Severity:    config.SeverityHigh,
				Description: "Inline trigger supplied on the command line",
			})
		}

	default:
		cfg = config.Default()
	}

	if opts.mode != "" {
		cfg.Mode = config.Mode(opts.mode)
	}
	if opts.maxPerMinute > 0 {
		cfg.MaxCapturesPerMinute = opts.maxPerMinute
	}
	if opts.maxDumpMB > 0 {
		cfg.MaxDumpSizeMB = opts.maxDumpMB
	}
	if opts.maxDiskMB > 0 {
		cfg.MaxDiskUsageMB = opts.maxDiskMB
	}
	if opts.retentionDays > 0 {
		cfg.RetentionDays = opts.retentionDays
	}
	if opts.redact {
		cfg.RedactionEnabled = true
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func sanitiseRuleName(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.Trim(b.String(), "_")
	if len(out) > 32 {
		out = out[:32]
	}
	if out == "" {
		out = "trigger"
	}
	return out
}

func resolveNodeName(flag string) string {
	if flag != "" {
		return flag
	}
	if env := os.Getenv("NODE_NAME"); env != "" {
		return env
	}
	host, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return host
}

func buildExporters(opts *startOptions) (*export.Multi, error) {
	multi := export.NewMulti()

	if opts.webhookURL != "" {
		headers, err := parseHeaders(opts.webhookHeaders)
		if err != nil {
			return nil, err
		}
		w, err := export.NewWebhook(export.WebhookConfig{
			URL:      opts.webhookURL,
			Headers:  headers,
			Insecure: opts.insecureTLS,
		})
		if err != nil {
			return nil, err
		}
		multi.Add(w)
	}

	if opts.splunkURL != "" {
		s, err := export.NewSplunk(export.SplunkConfig{
			URL:      opts.splunkURL,
			Token:    opts.splunkToken,
			Index:    opts.splunkIndex,
			Insecure: opts.insecureTLS,
		})
		if err != nil {
			return nil, err
		}
		multi.Add(s)
	}

	if opts.elasticURL != "" {
		e, err := export.NewElastic(export.ElasticConfig{
			URL:      opts.elasticURL,
			Index:    opts.elasticIndex,
			APIKey:   opts.elasticAPIKey,
			Insecure: opts.insecureTLS,
		})
		if err != nil {
			return nil, err
		}
		multi.Add(e)
	}

	if opts.syslogAddr != "" {
		s, err := export.NewSyslog(export.SyslogConfig{
			Address:  opts.syslogAddr,
			Network:  opts.syslogNetwork,
			Format:   export.SyslogFormat(opts.syslogFormat),
			Insecure: opts.insecureTLS,
		})
		if err != nil {
			return nil, err
		}
		multi.Add(s)
	}

	if opts.notifyFile != "" {
		f, err := export.NewFileExporter(opts.notifyFile)
		if err != nil {
			return nil, err
		}
		multi.Add(f)
	}

	return multi, nil
}

func parseHeaders(raw []string) (map[string]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make(map[string]string, len(raw))
	for _, h := range raw {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return nil, errors.New("webhook header must be in 'Name: value' form, got " + h)
		}
		out[strings.TrimSpace(name)] = strings.TrimSpace(value)
	}
	return out, nil
}
