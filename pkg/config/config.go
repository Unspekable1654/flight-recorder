// Package config defines the Flight Recorder trigger ruleset: the schema, its
// validation rules, and the matcher that decides whether an observed process
// execution warrants a forensic capture.
//
// The configuration is deliberately data-driven rather than compiled in. In an
// incident the operator must be able to add a trigger ("we now know the
// attacker runs `xmrig`") without redeploying the DaemonSet, so the ruleset is
// mounted from a ConfigMap and hot-reloaded (see watcher.go).
package config

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Mode selects how aggressively the recorder captures.
type Mode string

const (
	// ModeTrigger captures only executions matching a rule. This is the
	// production default: low volume, low CPU, low disk.
	ModeTrigger Mode = "trigger"
	// ModeAll captures every observed execve in monitored namespaces. Used
	// during active incident response, where a missed capture costs more
	// than the CPU. Roughly 5% CPU on a busy node versus <2% for trigger.
	ModeAll Mode = "all"
)

// Severity ranks a rule for downstream SIEM/SOAR routing.
type Severity string

// Recognised severities, ordered low to critical.
const (
	SeverityLow      Severity = "low"
	SeverityMedium   Severity = "medium"
	SeverityHigh     Severity = "high"
	SeverityCritical Severity = "critical"
)

var validSeverities = map[Severity]int{
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

// Rank returns a numeric ordering for the severity (higher is worse).
func (s Severity) Rank() int { return validSeverities[s] }

// FilterMode selects include- or exclude-semantics for the namespace filter.
type FilterMode string

const (
	// FilterExclude watches everything except the listed namespaces.
	FilterExclude FilterMode = "exclude"
	// FilterInclude watches only the listed namespaces.
	FilterInclude FilterMode = "include"
)

// Rule is a single trigger definition.
//
// Exactly one of Match (literal substring) or MatchRegex must be set. Literal
// matching exists because it is far cheaper and covers the common case; the
// regex form covers shell pipelines such as `curl ... | sh`.
type Rule struct {
	Name       string   `yaml:"name" json:"name"`
	Match      string   `yaml:"match,omitempty" json:"match,omitempty"`
	MatchRegex string   `yaml:"match_regex,omitempty" json:"match_regex,omitempty"`
	Severity   Severity `yaml:"severity" json:"severity"`
	// Comm optionally restricts the rule to a specific process name. When set
	// it is also pushed into the kernel-side prefilter map.
	Comm string `yaml:"comm,omitempty" json:"comm,omitempty"`
	// MITRE is an optional ATT&CK technique id recorded in the evidence bundle.
	MITRE string `yaml:"mitre,omitempty" json:"mitre,omitempty"`
	// Description is free text carried into the SIEM event.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	re *regexp.Regexp
}

// NamespaceFilter restricts which Kubernetes namespaces are monitored.
type NamespaceFilter struct {
	Mode       FilterMode `yaml:"mode" json:"mode"`
	Namespaces []string   `yaml:"namespaces" json:"namespaces"`
}

// Config is the complete runtime ruleset.
type Config struct {
	Version string `yaml:"version" json:"version"`
	Mode    Mode   `yaml:"mode" json:"mode"`

	MaxCapturesPerMinute          int `yaml:"max_captures_per_minute" json:"max_captures_per_minute"`
	MaxCapturesPerContainerPerMin int `yaml:"max_captures_per_container_per_minute" json:"max_captures_per_container_per_minute"`
	MaxDumpSizeMB                 int `yaml:"max_dump_size_mb" json:"max_dump_size_mb"`
	MaxDiskUsageMB                int `yaml:"max_disk_usage_mb" json:"max_disk_usage_mb"`
	RetentionDays                 int `yaml:"retention_days" json:"retention_days"`

	RedactionEnabled  bool     `yaml:"redaction_enabled" json:"redaction_enabled"`
	RedactionPatterns []string `yaml:"redaction_patterns,omitempty" json:"redaction_patterns,omitempty"`

	// KernelPrefilter pushes rule comms into a BPF hash map so that
	// non-matching execs are dropped in kernel space. Reduces ring buffer
	// pressure on busy nodes at the cost of losing full-cmdline matching for
	// processes whose comm is not listed.
	KernelPrefilter bool `yaml:"kernel_prefilter" json:"kernel_prefilter"`

	Rules           []Rule          `yaml:"rules" json:"rules"`
	NamespaceFilter NamespaceFilter `yaml:"namespace_filter" json:"namespace_filter"`
}

// Default returns a production-safe configuration with the baseline ruleset.
//
// The returned configuration is validated, which is what compiles the rules'
// regexes. A caller that skipped validation would get a Config whose regex
// rules silently never match - the worst possible failure for a forensic
// trigger, because it looks exactly like "no attack happened".
func Default() *Config {
	cfg := defaultUnvalidated()
	if err := cfg.Validate(); err != nil {
		// The built-in ruleset is a compile-time constant. If it fails to
		// validate the binary is broken, and continuing would mean monitoring
		// with a ruleset nobody has checked.
		panic("config: the built-in ruleset is invalid: " + err.Error())
	}
	return cfg
}

func defaultUnvalidated() *Config {
	return &Config{
		Version:                       "1",
		Mode:                          ModeTrigger,
		MaxCapturesPerMinute:          10,
		MaxCapturesPerContainerPerMin: 3,
		MaxDumpSizeMB:                 512,
		MaxDiskUsageMB:                1024,
		RetentionDays:                 90,
		RedactionEnabled:              false,
		KernelPrefilter:               false,
		Rules: []Rule{
			{Name: "shadow_access", Match: "/etc/shadow", Severity: SeverityCritical, MITRE: "T1003.008",
				Description: "Read of the local password hash database"},
			{Name: "curl_pipe_sh", MatchRegex: `(curl|wget)[^|]*\|\s*(ba)?sh`, Severity: SeverityCritical, MITRE: "T1059.004",
				Description: "Fileless download-and-execute pipeline"},
			{Name: "reverse_shell", MatchRegex: `/dev/tcp/|nc\s+-e|ncat\s+-e|socat.*exec`, Severity: SeverityCritical, MITRE: "T1071",
				Description: "Interactive reverse shell establishment"},
			{Name: "crypto_miner", MatchRegex: `(?i)(xmrig|minerd|cpuminer|stratum\+tcp)`, Severity: SeverityHigh, MITRE: "T1496",
				Description: "Cryptomining payload execution"},
			{Name: "dns_exfil", MatchRegex: `(?i)(dnscat|iodine|dig\s+.*\s+txt\s)`, Severity: SeverityHigh, MITRE: "T1048.003",
				Description: "DNS tunnelling or exfiltration tooling"},
			{Name: "container_breakout", MatchRegex: `(?i)(nsenter|unshare\s+.*--mount|mount\s+/dev/(sd|nvme|vd))`, Severity: SeverityCritical, MITRE: "T1611",
				Description: "Container escape or host filesystem mount"},
			{Name: "credential_harvest", MatchRegex: `(?i)(/var/run/secrets/kubernetes\.io|\.aws/credentials|\.kube/config)`, Severity: SeverityHigh, MITRE: "T1552.001",
				Description: "Access to mounted service-account or cloud credentials"},
		},
		NamespaceFilter: NamespaceFilter{
			Mode:       FilterExclude,
			Namespaces: []string{"kube-system", "flight-recorder"},
		},
	}
}

// Load reads and validates a ruleset from a YAML file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	cfg, err := Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return cfg, nil
}

// Parse decodes and validates a ruleset from YAML bytes.
//
// Unknown fields are rejected: a typo in a production trigger file must fail
// loudly at load time, not silently disable a rule.
func Parse(raw []byte) (*Config, error) {
	cfg := defaultUnvalidated()
	cfg.Rules = nil
	cfg.NamespaceFilter = NamespaceFilter{}

	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("decode yaml: %w", err)
	}

	if cfg.NamespaceFilter.Mode == "" {
		cfg.NamespaceFilter.Mode = FilterExclude
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks the ruleset for internal consistency and compiles regexes.
//
// Compilation happens here, once, so that a malformed pattern is reported at
// config load rather than at the moment an attack is in progress.
func (c *Config) Validate() error {
	switch c.Mode {
	case ModeTrigger, ModeAll:
	case "":
		c.Mode = ModeTrigger
	default:
		return fmt.Errorf("invalid mode %q: want %q or %q", c.Mode, ModeTrigger, ModeAll)
	}

	if c.MaxCapturesPerMinute < 0 {
		return fmt.Errorf("max_captures_per_minute must be >= 0, got %d", c.MaxCapturesPerMinute)
	}
	if c.MaxCapturesPerContainerPerMin < 0 {
		return fmt.Errorf("max_captures_per_container_per_minute must be >= 0, got %d", c.MaxCapturesPerContainerPerMin)
	}
	if c.MaxDumpSizeMB <= 0 {
		return fmt.Errorf("max_dump_size_mb must be > 0, got %d", c.MaxDumpSizeMB)
	}
	if c.MaxDiskUsageMB <= 0 {
		return fmt.Errorf("max_disk_usage_mb must be > 0, got %d", c.MaxDiskUsageMB)
	}
	if c.RetentionDays <= 0 {
		return fmt.Errorf("retention_days must be > 0, got %d", c.RetentionDays)
	}

	switch c.NamespaceFilter.Mode {
	case FilterInclude, FilterExclude:
	case "":
		c.NamespaceFilter.Mode = FilterExclude
	default:
		return fmt.Errorf("invalid namespace_filter.mode %q", c.NamespaceFilter.Mode)
	}

	if c.Mode == ModeTrigger && len(c.Rules) == 0 {
		return fmt.Errorf("mode %q requires at least one rule", ModeTrigger)
	}

	seen := make(map[string]struct{}, len(c.Rules))
	for i := range c.Rules {
		r := &c.Rules[i]
		if r.Name == "" {
			return fmt.Errorf("rule[%d]: name is required", i)
		}
		if _, dup := seen[r.Name]; dup {
			return fmt.Errorf("rule[%d]: duplicate rule name %q", i, r.Name)
		}
		seen[r.Name] = struct{}{}

		if r.Match == "" && r.MatchRegex == "" && r.Comm == "" {
			return fmt.Errorf("rule %q: one of match, match_regex or comm is required", r.Name)
		}
		if r.Match != "" && r.MatchRegex != "" {
			return fmt.Errorf("rule %q: match and match_regex are mutually exclusive", r.Name)
		}
		if r.Severity == "" {
			r.Severity = SeverityMedium
		}
		if _, ok := validSeverities[r.Severity]; !ok {
			return fmt.Errorf("rule %q: invalid severity %q", r.Name, r.Severity)
		}
		if r.MatchRegex != "" {
			re, err := regexp.Compile(r.MatchRegex)
			if err != nil {
				return fmt.Errorf("rule %q: compile match_regex: %w", r.Name, err)
			}
			r.re = re
		}
		if len(r.Comm) > 15 {
			// Kernel comm is TASK_COMM_LEN (16) including the NUL.
			return fmt.Errorf("rule %q: comm %q exceeds 15 characters", r.Name, r.Comm)
		}
	}

	for i, p := range c.RedactionPatterns {
		if _, err := regexp.Compile(p); err != nil {
			return fmt.Errorf("redaction_patterns[%d]: %w", i, err)
		}
	}

	return nil
}

// Match evaluates the ruleset against an observed execution.
//
// cmdline is the reconstructed command line (filename plus argv). comm is the
// kernel's 15-character process name. In ModeAll every execution matches and a
// synthetic rule is returned so downstream code has uniform metadata.
//
// When multiple rules match, the highest-severity one wins; ties are broken by
// declaration order, which makes the outcome deterministic and therefore
// reproducible for evidentiary purposes.
func (c *Config) Match(cmdline, comm string) (Rule, bool) {
	if c.Mode == ModeAll {
		return Rule{
			Name:        "capture_all",
			Severity:    SeverityMedium,
			Description: "Capture-all mode: every observed execution is preserved",
		}, true
	}

	var best Rule
	found := false
	for _, r := range c.Rules {
		if !r.matches(cmdline, comm) {
			continue
		}
		if !found || r.Severity.Rank() > best.Severity.Rank() {
			best, found = r, true
		}
	}
	return best, found
}

func (r Rule) matches(cmdline, comm string) bool {
	if r.Comm != "" && r.Comm != comm {
		return false
	}
	switch {
	case r.Match != "":
		return strings.Contains(cmdline, r.Match)
	case r.MatchRegex != "":
		re := r.re
		if re == nil {
			// The rule reached the matcher without having been validated.
			// Compiling here (from a process-wide cache) is far better than
			// returning false, which would silently disable the trigger.
			var err error
			re, err = cachedRegexp(r.MatchRegex)
			if err != nil {
				return false
			}
		}
		return re.MatchString(cmdline)
	default:
		// Comm-only rule, and the comm already matched above.
		return r.Comm != ""
	}
}

var (
	regexCacheMu sync.RWMutex
	regexCache   = map[string]*regexp.Regexp{}
)

// cachedRegexp compiles a pattern once per process.
func cachedRegexp(pattern string) (*regexp.Regexp, error) {
	regexCacheMu.RLock()
	re, ok := regexCache[pattern]
	regexCacheMu.RUnlock()
	if ok {
		return re, nil
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	regexCacheMu.Lock()
	regexCache[pattern] = re
	regexCacheMu.Unlock()
	return re, nil
}

// WatchesNamespace reports whether events from a Kubernetes namespace should
// be processed. An empty namespace (non-Kubernetes workload, or unresolved
// container) is always watched: dropping unattributed events would create a
// blind spot an attacker could hide in.
func (c *Config) WatchesNamespace(ns string) bool {
	if ns == "" {
		return true
	}
	listed := false
	for _, n := range c.NamespaceFilter.Namespaces {
		if n == ns {
			listed = true
			break
		}
	}
	if c.NamespaceFilter.Mode == FilterInclude {
		return listed
	}
	return !listed
}

// PrefilterComms returns the process names to install in the kernel-side
// prefilter map. It returns nil when prefiltering is disabled or when any rule
// lacks a comm (in which case a kernel prefilter would silently drop events
// that rule needs to see).
func (c *Config) PrefilterComms() []string {
	if !c.KernelPrefilter || c.Mode == ModeAll {
		return nil
	}
	comms := make([]string, 0, len(c.Rules))
	for _, r := range c.Rules {
		if r.Comm == "" {
			return nil
		}
		comms = append(comms, r.Comm)
	}
	return comms
}

// RedactionRegexes compiles the configured redaction patterns, falling back to
// the built-in defaults when the operator enabled redaction without supplying
// patterns.
func (c *Config) RedactionRegexes() ([]*regexp.Regexp, []string, error) {
	patterns := c.RedactionPatterns
	if len(patterns) == 0 {
		patterns = DefaultRedactionPatterns()
	}
	out := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, nil, fmt.Errorf("compile redaction pattern %q: %w", p, err)
		}
		out = append(out, re)
	}
	return out, patterns, nil
}

// DefaultRedactionPatterns are the byte patterns removed from memory dumps
// when --redact is enabled. They are intentionally conservative: over-redaction
// destroys evidence, and redaction is off by default for that reason.
func DefaultRedactionPatterns() []string {
	return []string{
		`\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b`, // payment card numbers
		`\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b`,                                 // US SSN
		`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`,           // email addresses
		`\bAKIA[0-9A-Z]{16}\b`,                                           // AWS access key id
		`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b`,                    // GitHub tokens
	}
}

// Marshal renders the configuration back to YAML, used by `flight-recorder
// rules dump` and by the audit trail that records config changes.
func (c *Config) Marshal() ([]byte, error) {
	out, err := yaml.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("marshal config: %w", err)
	}
	return out, nil
}
