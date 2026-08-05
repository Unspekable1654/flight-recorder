// Package format renders a capture as a CASE/UCO JSON-LD bundle.
//
// CASE (Cyber-investigation Analysis Standard Expression) and its base
// ontology UCO are the interchange format endorsed by INTERPOL, Europol EC3
// and NIST for digital evidence. Emitting it directly - rather than a
// proprietary schema with a converter bolted on - is what allows evidence
// produced here to enter an existing forensic workflow without re-collection.
//
// A note on namespaces. The Flight Recorder design documents refer to
// "case-core:InvestigativeAction" and "case-core:ProvenanceRecord". In the
// published ontology (CASE 1.3.0) both classes live in the
// case-investigation namespace, not case-core. This package follows the
// published ontology, because output that a CASE validator rejects is not
// interoperable no matter what an internal document says. Both prefixes are
// declared in @context.
//
// Fields with no home in the published ontology (container identity, Merkle
// parameters, capture completeness accounting) are emitted under the "fr"
// extension namespace. Extending via a documented namespace is the mechanism
// CASE itself prescribes; inventing terms inside case-* prefixes is not.
package format

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Ontology namespace IRIs.
const (
	NSCaseCore          = "https://ontology.caseontology.org/case/core/"
	NSCaseInvestigation = "https://ontology.caseontology.org/case/investigation/"
	NSUCOCore           = "https://ontology.unifiedcyberontology.org/uco/core/"
	NSUCOObservable     = "https://ontology.unifiedcyberontology.org/uco/observable/"
	NSUCOAction         = "https://ontology.unifiedcyberontology.org/uco/action/"
	NSUCOTool           = "https://ontology.unifiedcyberontology.org/uco/tool/"
	NSUCOTypes          = "https://ontology.unifiedcyberontology.org/uco/types/"
	NSUCOIdentity       = "https://ontology.unifiedcyberontology.org/uco/identity/"
	NSUCOVocabulary     = "https://ontology.unifiedcyberontology.org/uco/vocabulary/"
	NSXSD               = "http://www.w3.org/2001/XMLSchema#"
	// NSFlightRecorder is this tool's documented extension namespace.
	NSFlightRecorder = "https://flightrecorder.dev/ontology/2026/01#"
	// NSKB is the local knowledge base namespace for instance identifiers.
	NSKB = "http://example.org/kb/"
)

// SpecVersion is the CASE version this output targets.
const SpecVersion = "1.3.0"

// Classification marks the sensitivity of a bundle.
//
// Memory dumps routinely contain credentials, tokens and personal data. The
// classification travels with the metadata so that downstream systems can
// apply handling rules without opening the payload.
type Classification string

// Classification values.
const (
	// ClassificationConfidential is the default for any raw memory capture.
	ClassificationConfidential Classification = "CONFIDENTIAL"
	// ClassificationRestricted is applied when the source workload is marked
	// PII-sensitive via the flight-recorder.io/classification annotation.
	ClassificationRestricted Classification = "RESTRICTED"
)

// CaptureMetadata is everything the exporter needs to describe one capture.
//
// It is a plain data structure with no behaviour so that the CASE mapping can
// be tested in isolation from the capture and sealing machinery.
type CaptureMetadata struct {
	CaseID string

	// Trigger.
	TriggerRule     string
	TriggerSeverity string
	TriggerMITRE    string
	TriggerCmdline  string
	TriggerTime     time.Time

	// Process identity.
	HostPID      int
	NamespacePID int
	ParentPID    int
	UID          uint32
	Comm         string
	BinaryPath   string
	Arguments    []string

	// Workload identity.
	ContainerID   string
	PodName       string
	PodNamespace  string
	PodUID        string
	ContainerRT   string
	CgroupID      uint64
	CgroupPath    string
	NodeName      string
	KernelVersion string

	// Acquisition.
	CaptureStart   time.Time
	CaptureEnd     time.Time
	DumpFileName   string
	DumpFilePath   string
	DumpSizeBytes  int64
	DumpSHA256     string
	RegionCount    int
	FullRegions    int
	PartialRegions int
	FailedRegions  int
	SkippedRegions int
	CaptureStatus  string
	Encrypted      bool
	Compression    string

	// Sealing.
	MerkleRoot     string
	MerkleLeaves   int
	MerkleDepth    int
	MerkleChunk    int
	OddLeafPolicy  string
	Signature      string
	SignerKeyID    string
	SignatureAlg   string
	SealTime       time.Time
	SealDurationMS float64

	// Provenance.
	ToolName       string
	ToolVersion    string
	ToolCommit     string
	ToolSelfSHA256 string
	Operator       string

	// Handling.
	Classification    Classification
	RedactionApplied  bool
	RedactionPatterns []string
}

// Bundle is a CASE/UCO JSON-LD document.
type Bundle struct {
	Context     map[string]string `json:"@context"`
	ID          string            `json:"@id"`
	Type        string            `json:"@type"`
	Name        string            `json:"uco-core:name"`
	Description string            `json:"uco-core:description"`
	CreatedTime typedLiteral      `json:"uco-core:createdTime"`
	SpecVersion string            `json:"case-core:specVersion"`
	Graph       []map[string]any  `json:"@graph"`
}

type typedLiteral struct {
	Type  string `json:"@type"`
	Value string `json:"@value"`
}

func xsdDateTime(t time.Time) typedLiteral {
	return typedLiteral{Type: "xsd:dateTime", Value: t.UTC().Format(time.RFC3339Nano)}
}

func xsdInteger(v int64) typedLiteral {
	return typedLiteral{Type: "xsd:integer", Value: fmt.Sprintf("%d", v)}
}

func xsdDecimal(v float64) typedLiteral {
	return typedLiteral{Type: "xsd:decimal", Value: fmt.Sprintf("%.3f", v)}
}

func xsdBoolean(v bool) typedLiteral {
	return typedLiteral{Type: "xsd:boolean", Value: fmt.Sprintf("%t", v)}
}

func ref(id string) map[string]any { return map[string]any{"@id": id} }

// context returns the @context every bundle declares.
func context() map[string]string {
	return map[string]string{
		"case-core":          NSCaseCore,
		"case-investigation": NSCaseInvestigation,
		"uco-core":           NSUCOCore,
		"uco-observable":     NSUCOObservable,
		"uco-action":         NSUCOAction,
		"uco-tool":           NSUCOTool,
		"uco-types":          NSUCOTypes,
		"uco-identity":       NSUCOIdentity,
		"uco-vocabulary":     NSUCOVocabulary,
		"fr":                 NSFlightRecorder,
		"kb":                 NSKB,
		"xsd":                NSXSD,
	}
}

// ExportToCASE renders a capture as a validated CASE/UCO JSON-LD bundle.
//
// The returned bytes are indented JSON: forensic output is read by humans
// under time pressure at least as often as it is parsed by machines.
//
// The bundle is validated before it is returned. An invalid bundle is an
// error, never a warning - silently emitting malformed evidence would be worse
// than emitting none, because the defect would only surface when the evidence
// was needed.
func ExportToCASE(meta CaptureMetadata) ([]byte, error) {
	bundle, err := BuildBundle(meta)
	if err != nil {
		return nil, err
	}
	if err := Validate(bundle); err != nil {
		return nil, fmt.Errorf("format: generated bundle failed validation: %w", err)
	}

	out, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("format: marshal CASE bundle: %w", err)
	}
	return append(out, '\n'), nil
}

// BuildBundle assembles the object graph for a capture.
func BuildBundle(meta CaptureMetadata) (*Bundle, error) {
	if meta.CaseID == "" {
		return nil, fmt.Errorf("format: CaseID is required")
	}
	if meta.MerkleRoot == "" {
		return nil, fmt.Errorf("format: MerkleRoot is required (evidence must be sealed before export)")
	}
	if meta.DumpSHA256 == "" {
		return nil, fmt.Errorf("format: DumpSHA256 is required")
	}
	if meta.Classification == "" {
		meta.Classification = ClassificationConfidential
	}

	id := func(kind string) string {
		return fmt.Sprintf("kb:%s-%s", kind, meta.CaseID)
	}

	var (
		bundleID     = id("bundle")
		dumpID       = id("memory-dump")
		processID    = id("process")
		containerID  = id("container")
		actionID     = id("investigative-action")
		provenanceID = id("provenance-record")
		toolID       = id("tool")
		identityID   = id("performer")
		triggerID    = id("trigger-event")
	)

	graph := make([]map[string]any, 0, 12)

	// ---- The acquired artefact -------------------------------------------
	contentFacet := map[string]any{
		"@id":   dumpID + "-content-facet",
		"@type": "uco-observable:ContentDataFacet",
		"uco-observable:hash": []map[string]any{{
			"@id":                  dumpID + "-hash",
			"@type":                "uco-types:Hash",
			"uco-types:hashMethod": map[string]any{"@type": "uco-vocabulary:HashNameVocab", "@value": "SHA256"},
			"uco-types:hashValue":  map[string]any{"@type": "xsd:hexBinary", "@value": strings.ToUpper(meta.DumpSHA256)},
		}},
		"uco-observable:sizeInBytes": xsdInteger(meta.DumpSizeBytes),
		"uco-observable:mimeType":    "application/octet-stream",
		"uco-observable:isEncrypted": xsdBoolean(meta.Encrypted),
	}
	if meta.Compression != "" {
		contentFacet["fr:compression"] = meta.Compression
	}

	fileFacet := map[string]any{
		"@id":                                  dumpID + "-file-facet",
		"@type":                                "uco-observable:FileFacet",
		"uco-observable:fileName":              meta.DumpFileName,
		"uco-observable:filePath":              meta.DumpFilePath,
		"uco-observable:sizeInBytes":           xsdInteger(meta.DumpSizeBytes),
		"uco-observable:observableCreatedTime": xsdDateTime(meta.CaptureEnd),
	}

	acquisitionFacet := map[string]any{
		"@id":                     dumpID + "-acquisition-facet",
		"@type":                   "fr:MemoryAcquisitionFacet",
		"fr:regionCount":          xsdInteger(int64(meta.RegionCount)),
		"fr:fullRegions":          xsdInteger(int64(meta.FullRegions)),
		"fr:partialRegions":       xsdInteger(int64(meta.PartialRegions)),
		"fr:failedRegions":        xsdInteger(int64(meta.FailedRegions)),
		"fr:skippedRegions":       xsdInteger(int64(meta.SkippedRegions)),
		"fr:captureStatus":        meta.CaptureStatus,
		"fr:acquisitionMethod":    "process_vm_readv(2)",
		"fr:targetProcessStopped": xsdBoolean(false),
		"fr:redactionApplied":     xsdBoolean(meta.RedactionApplied),
	}
	if len(meta.RedactionPatterns) > 0 {
		acquisitionFacet["fr:redactionPatterns"] = meta.RedactionPatterns
	}

	graph = append(graph, map[string]any{
		"@id":                  dumpID,
		"@type":                "uco-observable:ObservableObject",
		"uco-core:name":        fmt.Sprintf("Process memory dump (pid %d)", meta.HostPID),
		"uco-core:description": fmt.Sprintf("Volatile memory acquired from %s via process_vm_readv without suspending the target", describeTarget(meta)),
		"uco-core:tag":         []string{string(meta.Classification)},
		"fr:classification":    string(meta.Classification),
		"uco-core:hasFacet":    []map[string]any{contentFacet, fileFacet, acquisitionFacet},
	})

	// ---- The process it came from ----------------------------------------
	processFacet := map[string]any{
		"@id":                                  processID + "-facet",
		"@type":                                "uco-observable:ProcessFacet",
		"uco-observable:pid":                   xsdInteger(int64(meta.HostPID)),
		"uco-observable:observableCreatedTime": xsdDateTime(meta.TriggerTime),
	}
	if len(meta.Arguments) > 0 {
		processFacet["uco-observable:arguments"] = meta.Arguments
	}
	if meta.BinaryPath != "" {
		// The executed image is its own observable. Referencing it without
		// defining it would leave a dangling @id, which Validate rejects.
		binaryID := id("binary")
		graph = append(graph, map[string]any{
			"@id":                  binaryID,
			"@type":                "uco-observable:File",
			"uco-core:name":        path.Base(meta.BinaryPath),
			"uco-core:description": "Binary image passed to execve",
			"uco-core:hasFacet": []map[string]any{{
				"@id":                     binaryID + "-facet",
				"@type":                   "uco-observable:FileFacet",
				"uco-observable:fileName": path.Base(meta.BinaryPath),
				// Recorded as the kernel saw it: resolved inside the
				// container's mount namespace, not the host's.
				"uco-observable:filePath": meta.BinaryPath,
			}},
		})
		processFacet["uco-observable:binary"] = ref(binaryID)
	}

	nsFacet := map[string]any{
		"@id":             processID + "-namespace-facet",
		"@type":           "fr:ProcessNamespaceFacet",
		"fr:hostPID":      xsdInteger(int64(meta.HostPID)),
		"fr:namespacePID": xsdInteger(int64(meta.NamespacePID)),
		"fr:uid":          xsdInteger(int64(meta.UID)),
		"fr:comm":         meta.Comm,
		"fr:commandLine":  meta.TriggerCmdline,
		"fr:cgroupID":     xsdInteger(int64(meta.CgroupID)),
	}
	if meta.ParentPID > 0 {
		nsFacet["fr:parentHostPID"] = xsdInteger(int64(meta.ParentPID))
	}

	graph = append(graph, map[string]any{
		"@id":                  processID,
		"@type":                "uco-observable:Process",
		"uco-core:name":        meta.Comm,
		"uco-core:description": fmt.Sprintf("Process observed executing %q", meta.TriggerCmdline),
		"uco-core:hasFacet":    []map[string]any{processFacet, nsFacet},
	})

	// ---- The workload ----------------------------------------------------
	if meta.ContainerID != "" || meta.PodName != "" {
		containerFacet := map[string]any{
			"@id":             containerID + "-facet",
			"@type":           "fr:ContainerFacet",
			"fr:containerID":  meta.ContainerID,
			"fr:runtime":      meta.ContainerRT,
			"fr:cgroupPath":   meta.CgroupPath,
			"fr:podName":      meta.PodName,
			"fr:podNamespace": meta.PodNamespace,
			"fr:podUID":       meta.PodUID,
			"fr:nodeName":     meta.NodeName,
		}
		graph = append(graph, map[string]any{
			"@id":                  containerID,
			"@type":                "uco-observable:ObservableObject",
			"uco-core:name":        containerDisplayName(meta),
			"uco-core:description": "Container that hosted the observed process",
			"uco-core:hasFacet":    []map[string]any{containerFacet},
		})
	}

	// ---- The kernel event that triggered acquisition ----------------------
	graph = append(graph, map[string]any{
		"@id":                  triggerID,
		"@type":                "uco-observable:ObservableObject",
		"uco-core:name":        "eBPF trigger event",
		"uco-core:description": fmt.Sprintf("execve observed by tracepoint/syscalls/sys_enter_execve matched rule %q", meta.TriggerRule),
		"uco-core:hasFacet": []map[string]any{{
			"@id":               triggerID + "-facet",
			"@type":             "fr:TriggerFacet",
			"fr:ruleName":       meta.TriggerRule,
			"fr:severity":       meta.TriggerSeverity,
			"fr:mitreTechnique": meta.TriggerMITRE,
			"fr:commandLine":    meta.TriggerCmdline,
			"fr:observedTime":   xsdDateTime(meta.TriggerTime),
			"fr:probe":          "tracepoint/syscalls/sys_enter_execve",
			"fr:clockSource":    "CLOCK_BOOTTIME (bpf_ktime_get_boot_ns)",
		}},
	})

	// ---- The tool --------------------------------------------------------
	graph = append(graph, map[string]any{
		"@id":                  toolID,
		"@type":                "uco-tool:Tool",
		"uco-core:name":        meta.ToolName,
		"uco-tool:toolType":    "Forensic Capture Tool",
		"uco-tool:version":     meta.ToolVersion,
		"uco-core:description": "eBPF-triggered volatile memory preservation for ephemeral compute",
		"uco-core:hasFacet": []map[string]any{{
			"@id":              toolID + "-build-facet",
			"@type":            "fr:BuildFacet",
			"fr:commit":        meta.ToolCommit,
			"fr:binarySHA256":  meta.ToolSelfSHA256,
			"fr:kernelVersion": meta.KernelVersion,
			"fr:nodeName":      meta.NodeName,
		}},
	})

	// ---- Who performed the acquisition ------------------------------------
	operator := meta.Operator
	if operator == "" {
		operator = "automated:flight-recorder"
	}
	graph = append(graph, map[string]any{
		"@id":                  identityID,
		"@type":                "uco-identity:Identity",
		"uco-core:name":        operator,
		"uco-core:description": "Identity responsible for the acquisition (service account when automated)",
	})

	// ---- The acquisition itself -------------------------------------------
	graph = append(graph, map[string]any{
		"@id":                            actionID,
		"@type":                          "case-investigation:InvestigativeAction",
		"uco-core:name":                  "Volatile memory acquisition",
		"uco-core:description":           fmt.Sprintf("Triggered acquisition of process memory following rule %q", meta.TriggerRule),
		"uco-action:startTime":           xsdDateTime(meta.CaptureStart),
		"uco-action:endTime":             xsdDateTime(meta.CaptureEnd),
		"case-investigation:startedTime": xsdDateTime(meta.CaptureStart),
		"case-investigation:endedTime":   xsdDateTime(meta.CaptureEnd),
		"uco-action:instrument":          ref(toolID),
		"uco-action:performer":           ref(identityID),
		"uco-action:object":              []map[string]any{ref(processID), ref(triggerID)},
		"uco-action:result":              []map[string]any{ref(dumpID)},
		"fr:acquisitionLatencyMS":        xsdDecimal(float64(meta.CaptureEnd.Sub(meta.TriggerTime).Microseconds()) / 1000.0),
	})

	// ---- The chain of custody ---------------------------------------------
	graph = append(graph, map[string]any{
		"@id":                              provenanceID,
		"@type":                            "case-investigation:ProvenanceRecord",
		"uco-core:name":                    "Cryptographic seal",
		"uco-core:description":             "Merkle tree over 4 KiB chunks of the acquired memory, root signed with ECDSA P-256",
		"case-investigation:exhibitNumber": meta.CaseID,
		"uco-core:object":                  []map[string]any{ref(dumpID)},
		"uco-core:hasFacet": []map[string]any{{
			"@id":                   provenanceID + "-facet",
			"@type":                 "fr:SealFacet",
			"fr:merkleRoot":         meta.MerkleRoot,
			"fr:merkleLeafCount":    xsdInteger(int64(meta.MerkleLeaves)),
			"fr:merkleTreeDepth":    xsdInteger(int64(meta.MerkleDepth)),
			"fr:merkleChunkBytes":   xsdInteger(int64(meta.MerkleChunk)),
			"fr:merkleHashFunction": "SHA-256",
			"fr:oddLeafPolicy":      meta.OddLeafPolicy,
			"fr:signature":          meta.Signature,
			"fr:signatureAlgorithm": meta.SignatureAlg,
			"fr:signerKeyID":        meta.SignerKeyID,
			"fr:sealTime":           xsdDateTime(meta.SealTime),
			"fr:sealDurationMS":     xsdDecimal(meta.SealDurationMS),
		}},
	})

	// ---- Relationships ----------------------------------------------------
	graph = append(graph,
		relationship(id("rel-produced"), actionID, dumpID, "Produced"),
		relationship(id("rel-used-tool"), actionID, toolID, "Used"),
		relationship(id("rel-authenticates"), provenanceID, dumpID, "Authenticates"),
		relationship(id("rel-extracted-from"), dumpID, processID, "Extracted_From"),
	)
	if meta.ContainerID != "" || meta.PodName != "" {
		graph = append(graph, relationship(id("rel-contained-within"), processID, containerID, "Contained_Within"))
	}

	return &Bundle{
		Context:     context(),
		ID:          bundleID,
		Type:        "uco-core:Bundle",
		Name:        fmt.Sprintf("Flight Recorder capture %s", meta.CaseID),
		Description: fmt.Sprintf("Volatile memory preserved from %s after trigger %q", describeTarget(meta), meta.TriggerRule),
		CreatedTime: xsdDateTime(meta.SealTime),
		SpecVersion: SpecVersion,
		Graph:       graph,
	}, nil
}

func relationship(id, source, target, kind string) map[string]any {
	return map[string]any{
		"@id":                         id,
		"@type":                       "uco-core:Relationship",
		"uco-core:source":             ref(source),
		"uco-core:target":             ref(target),
		"uco-core:kindOfRelationship": kind,
		"uco-core:isDirectional":      xsdBoolean(true),
	}
}

func describeTarget(meta CaptureMetadata) string {
	switch {
	case meta.PodName != "":
		return fmt.Sprintf("pod %s/%s (container %s)", meta.PodNamespace, meta.PodName, shortID(meta.ContainerID))
	case meta.ContainerID != "":
		return fmt.Sprintf("container %s", shortID(meta.ContainerID))
	default:
		return fmt.Sprintf("host process %d", meta.HostPID)
	}
}

func containerDisplayName(meta CaptureMetadata) string {
	if meta.PodName != "" {
		return fmt.Sprintf("%s/%s", meta.PodNamespace, meta.PodName)
	}
	return shortID(meta.ContainerID)
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	if id == "" {
		return "unknown"
	}
	return id
}

// NewCaseID returns a fresh UUID v4 case identifier.
func NewCaseID() string { return uuid.NewString() }

// -----------------------------------------------------------------------------
// Validation
// -----------------------------------------------------------------------------

var (
	hexHashRe = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	prefixRe  = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9-]*):`)
)

// requiredTypes are the classes a Flight Recorder bundle must always contain.
var requiredTypes = []string{
	"uco-observable:ObservableObject",
	"uco-observable:Process",
	"case-investigation:InvestigativeAction",
	"case-investigation:ProvenanceRecord",
	"uco-tool:Tool",
	"uco-core:Relationship",
}

// Validate performs structural conformance checks on a bundle.
//
// This is not a full JSON-LD/SHACL validation - that requires the CASE
// validator and a Python runtime, and is wired into CI rather than into the
// capture hot path (see .github/workflows/build.yaml). What it does check is
// everything that can go wrong in this program: missing classes, dangling
// references, duplicate identifiers, unbound prefixes and malformed hashes.
func Validate(b *Bundle) error {
	if b == nil {
		return fmt.Errorf("format: nil bundle")
	}
	if b.Type != "uco-core:Bundle" {
		return fmt.Errorf("format: bundle @type is %q, want uco-core:Bundle", b.Type)
	}
	if b.ID == "" {
		return fmt.Errorf("format: bundle has no @id")
	}
	if len(b.Graph) == 0 {
		return fmt.Errorf("format: bundle @graph is empty")
	}

	for _, prefix := range []string{"uco-core", "uco-observable", "case-investigation", "uco-tool", "fr", "kb", "xsd"} {
		if _, ok := b.Context[prefix]; !ok {
			return fmt.Errorf("format: @context is missing required prefix %q", prefix)
		}
	}

	ids := make(map[string]struct{}, len(b.Graph)*3)
	types := make(map[string]int, len(b.Graph))
	var refs []string

	var walk func(node map[string]any, path string) error
	walk = func(node map[string]any, path string) error {
		nodeID, hasID := node["@id"].(string)
		if hasID {
			if _, dup := ids[nodeID]; dup {
				return fmt.Errorf("format: duplicate @id %q at %s", nodeID, path)
			}
			ids[nodeID] = struct{}{}
			if err := checkPrefix(nodeID, b.Context); err != nil {
				return fmt.Errorf("format: %s: %w", path, err)
			}
		}

		if t, ok := node["@type"].(string); ok {
			types[t]++
			if err := checkPrefix(t, b.Context); err != nil {
				return fmt.Errorf("format: %s: %w", path, err)
			}
		}

		for key, value := range node {
			if strings.HasPrefix(key, "@") {
				continue
			}
			if err := checkPrefix(key, b.Context); err != nil {
				return fmt.Errorf("format: %s: %w", path, err)
			}
			if err := walkValue(value, path+"/"+key, &refs, walk); err != nil {
				return err
			}
		}
		return nil
	}

	for i, node := range b.Graph {
		if err := walk(node, fmt.Sprintf("@graph[%d]", i)); err != nil {
			return err
		}
	}

	for _, want := range requiredTypes {
		if types[want] == 0 {
			return fmt.Errorf("format: bundle is missing a required object of type %q", want)
		}
	}

	for _, r := range refs {
		if _, ok := ids[r]; !ok {
			return fmt.Errorf("format: dangling reference to @id %q", r)
		}
	}

	if err := validateHashes(b); err != nil {
		return err
	}

	return nil
}

func walkValue(value any, path string, refs *[]string, walk func(map[string]any, string) error) error {
	switch v := value.(type) {
	case map[string]any:
		// A single-key {"@id": ...} object is a reference, not a definition.
		if id, ok := v["@id"].(string); ok && len(v) == 1 {
			*refs = append(*refs, id)
			return nil
		}
		return walk(v, path)

	case []map[string]any:
		for i, item := range v {
			if err := walkValue(item, fmt.Sprintf("%s[%d]", path, i), refs, walk); err != nil {
				return err
			}
		}

	case []any:
		for i, item := range v {
			if err := walkValue(item, fmt.Sprintf("%s[%d]", path, i), refs, walk); err != nil {
				return err
			}
		}

	case typedLiteral, string, []string, nil:
		// Literals need no further inspection.

	default:
		// Unknown Go types would serialise unpredictably; reject them.
		return fmt.Errorf("format: %s: unsupported value type %T in graph", path, value)
	}
	return nil
}

func checkPrefix(term string, ctx map[string]string) error {
	m := prefixRe.FindStringSubmatch(term)
	if m == nil {
		// Unprefixed terms (plain strings used as relationship kinds) are fine.
		return nil
	}
	prefix := m[1]
	if strings.HasPrefix(term, "http://") || strings.HasPrefix(term, "https://") {
		return nil
	}
	if _, ok := ctx[prefix]; !ok {
		return fmt.Errorf("term %q uses prefix %q which is not bound in @context", term, prefix)
	}
	return nil
}

func validateHashes(b *Bundle) error {
	raw, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("format: re-marshal for validation: %w", err)
	}
	var probe map[string]any
	if err := json.Unmarshal(raw, &probe); err != nil {
		return fmt.Errorf("format: bundle is not valid JSON: %w", err)
	}

	var check func(any) error
	check = func(v any) error {
		switch node := v.(type) {
		case map[string]any:
			for key, val := range node {
				switch key {
				case "uco-types:hashValue":
					if lit, ok := val.(map[string]any); ok {
						if s, ok := lit["@value"].(string); ok && !hexHashRe.MatchString(s) {
							return fmt.Errorf("format: hashValue %q is not a 64-character hex digest", s)
						}
					}
				case "fr:merkleRoot", "fr:binarySHA256":
					if s, ok := val.(string); ok && s != "" && !hexHashRe.MatchString(s) {
						return fmt.Errorf("format: %s %q is not a 64-character hex digest", key, s)
					}
				}
				if err := check(val); err != nil {
					return err
				}
			}
		case []any:
			for _, item := range node {
				if err := check(item); err != nil {
					return err
				}
			}
		}
		return nil
	}

	return check(probe)
}

// BundleDigest returns the SHA-256 of the serialised bundle, recorded in the
// evidence manifest so that the metadata document is itself tamper evident.
func BundleDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// ParseBundle decodes a bundle, used by `flight-recorder inspect` and by the
// verification path.
func ParseBundle(raw []byte) (*Bundle, error) {
	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		return nil, fmt.Errorf("format: parse CASE bundle: %w", err)
	}
	return &b, nil
}

// FindFacetValue searches the graph for a facet field, used by inspection
// tooling that needs one datum without re-implementing the schema.
func (b *Bundle) FindFacetValue(facetType, field string) (any, bool) {
	for _, node := range b.Graph {
		facets, ok := node["uco-core:hasFacet"].([]any)
		if !ok {
			continue
		}
		for _, f := range facets {
			facet, ok := f.(map[string]any)
			if !ok {
				continue
			}
			if facet["@type"] == facetType {
				if v, ok := facet[field]; ok {
					return v, true
				}
			}
		}
	}
	return nil, false
}
