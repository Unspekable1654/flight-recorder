package pipeline

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"github.com/Unspekable1654/flight-recorder/pkg/capture"
	"github.com/Unspekable1654/flight-recorder/pkg/config"
	"github.com/Unspekable1654/flight-recorder/pkg/container"
	"github.com/Unspekable1654/flight-recorder/pkg/evidence"
	"github.com/Unspekable1654/flight-recorder/pkg/export"
	"github.com/Unspekable1654/flight-recorder/pkg/format"
	"github.com/Unspekable1654/flight-recorder/pkg/probe"
	"github.com/Unspekable1654/flight-recorder/pkg/seal"
	"github.com/Unspekable1654/flight-recorder/pkg/version"
)

// SealStoreInput is one acquisition ready to be sealed and stored.
//
// Factoring this out of the streaming pipeline means the daemon, the one-shot
// `capture` command and the `demo` command all produce byte-identical bundle
// structures. A verification path that only ever sees output from one of three
// code paths is a verification path that has not been tested.
type SealStoreInput struct {
	CaseID      string
	Payload     []byte
	Dump        *capture.MemoryDump
	Rule        config.Rule
	Event       probe.Event
	Info        *container.Info
	TriggerTime time.Time

	Signer *seal.Signer
	Writer *evidence.Writer

	NodeName      string
	Operator      string
	KernelVersion string
	EvidenceRoot  string
	Encrypted     bool
	Compression   string
}

// SealStoreResult is what was produced.
type SealStoreResult struct {
	Receipt      *seal.SealReceipt
	CASEBundle   []byte
	Written      *evidence.Written
	SealDuration time.Duration
	Notification export.Notification
}

// SealAndStore seals a payload, renders CASE/UCO, and writes the bundle.
//
// Order is fixed and load-bearing: seal first so the receipt describes exactly
// the bytes acquired, then render metadata that references the seal, then write
// both alongside the payload. Rendering metadata before sealing would leave the
// Merkle root absent from the document that is supposed to authenticate it.
func SealAndStore(in SealStoreInput) (*SealStoreResult, error) {
	if in.Signer == nil {
		return nil, fmt.Errorf("pipeline: signer is required")
	}
	if in.Writer == nil {
		return nil, fmt.Errorf("pipeline: evidence writer is required")
	}
	if len(in.Payload) == 0 {
		return nil, fmt.Errorf("pipeline: refusing to seal an empty payload")
	}
	if in.Dump == nil {
		return nil, fmt.Errorf("pipeline: dump metadata is required")
	}
	if in.Info == nil {
		in.Info = &container.Info{HostPID: in.Dump.PID, NodeName: in.NodeName}
	}

	buildInfo := version.Get()

	sealStart := time.Now()
	receipt, _, err := seal.Seal(in.Payload, in.Signer, seal.SealOptions{
		CaseID:            in.CaseID,
		CaptureStartTime:  in.Dump.CaptureStart,
		CaptureEndTime:    in.Dump.CaptureEnd,
		Status:            outcomeToStatus(in.Dump.Outcome()),
		StatusDetail:      statusDetail(in.Dump),
		ToolName:          version.Name,
		ToolVersion:       buildInfo.Version,
		ToolCommit:        buildInfo.Commit,
		ToolSelfSHA256:    buildInfo.SelfSHA256,
		KernelVersion:     in.KernelVersion,
		NodeName:          in.NodeName,
		Operator:          in.Operator,
		RedactionApplied:  in.Dump.RedactedMatches > 0,
		RedactionPatterns: in.Dump.RedactionUsed,
		SampleProofs:      8,
	})
	if err != nil {
		return nil, fmt.Errorf("seal evidence: %w", err)
	}
	sealDuration := time.Since(sealStart)

	payloadName := evidence.FileDumpEnc
	if !in.Encrypted {
		payloadName = evidence.FileDumpPlain
	}

	meta := format.CaptureMetadata{
		CaseID:          in.CaseID,
		TriggerRule:     in.Rule.Name,
		TriggerSeverity: string(in.Rule.Severity),
		TriggerMITRE:    in.Rule.MITRE,
		TriggerCmdline:  in.Event.CommandLine(),
		TriggerTime:     in.TriggerTime,

		HostPID:      in.Dump.PID,
		NamespacePID: in.Info.NamespacePID,
		UID:          in.Event.UID,
		Comm:         nonEmptyString(in.Event.Comm, in.Dump.Comm),
		BinaryPath:   in.Event.Filename,
		Arguments:    in.Event.Args,

		ContainerID:   in.Info.ContainerID,
		PodName:       in.Info.PodName,
		PodNamespace:  in.Info.PodNamespace,
		PodUID:        in.Info.PodUID,
		ContainerRT:   string(in.Info.Runtime),
		CgroupID:      in.Dump.CgroupID,
		CgroupPath:    in.Info.CgroupPath,
		NodeName:      in.NodeName,
		KernelVersion: in.KernelVersion,

		CaptureStart: in.Dump.CaptureStart,
		CaptureEnd:   in.Dump.CaptureEnd,
		DumpFileName: payloadName,
		// filepath.Join, not a "%s/%s/%s" format: the evidence root is a
		// native path, so concatenating with forward slashes produced a
		// mixed-separator filePath in the CASE/UCO output off Linux.
		DumpFilePath:   filepath.Join(in.EvidenceRoot, in.CaseID, payloadName),
		DumpSizeBytes:  int64(len(in.Payload)),
		DumpSHA256:     receipt.DumpSHA256,
		RegionCount:    len(in.Dump.Regions),
		FullRegions:    in.Dump.FullRegions,
		PartialRegions: in.Dump.PartialRegions,
		FailedRegions:  in.Dump.FailedRegions,
		SkippedRegions: in.Dump.SkippedRegions,
		CaptureStatus:  string(in.Dump.Outcome()),
		Encrypted:      in.Encrypted,
		Compression:    in.Compression,

		MerkleRoot:     receipt.RootHash,
		MerkleLeaves:   receipt.LeafCount,
		MerkleDepth:    receipt.TreeDepth,
		MerkleChunk:    receipt.ChunkSizeBytes,
		OddLeafPolicy:  receipt.OddLeafPolicy,
		Signature:      receipt.Signature,
		SignerKeyID:    receipt.SignerKeyID,
		SignatureAlg:   receipt.SignatureAlgorithm,
		SealTime:       receipt.SealTime,
		SealDurationMS: receipt.SealDurationMS,

		ToolName:       version.Name,
		ToolVersion:    buildInfo.Version,
		ToolCommit:     buildInfo.Commit,
		ToolSelfSHA256: buildInfo.SelfSHA256,
		Operator:       in.Operator,

		Classification:    format.ClassificationConfidential,
		RedactionApplied:  in.Dump.RedactedMatches > 0,
		RedactionPatterns: in.Dump.RedactionUsed,
	}

	caseBundle, err := format.ExportToCASE(meta)
	if err != nil {
		return nil, fmt.Errorf("build CASE bundle: %w", err)
	}

	written, err := in.Writer.Write(evidence.Input{
		CaseID:         in.CaseID,
		Dump:           in.Payload,
		Receipt:        receipt,
		CASEBundle:     caseBundle,
		Regions:        regionReport(in.Dump),
		Classification: string(format.ClassificationConfidential),
		ToolName:       version.Name,
		ToolVersion:    buildInfo.Version,
		NodeName:       in.NodeName,
	})
	if err != nil {
		return nil, fmt.Errorf("write evidence bundle: %w", err)
	}

	notification := export.Notification{
		CaseID:         in.CaseID,
		Timestamp:      time.Now().UTC(),
		Rule:           in.Rule.Name,
		Severity:       string(in.Rule.Severity),
		MITRE:          in.Rule.MITRE,
		Comm:           meta.Comm,
		Cmdline:        meta.TriggerCmdline,
		Args:           in.Event.Args,
		HostPID:        in.Dump.PID,
		NamespacePID:   in.Info.NamespacePID,
		UID:            in.Event.UID,
		ContainerID:    in.Info.ContainerID,
		PodName:        in.Info.PodName,
		PodNamespace:   in.Info.PodNamespace,
		NodeName:       in.NodeName,
		Runtime:        string(in.Info.Runtime),
		CaptureStart:   in.Dump.CaptureStart,
		CaptureEnd:     in.Dump.CaptureEnd,
		DumpSizeBytes:  int64(len(in.Payload)),
		DumpSHA256:     receipt.DumpSHA256,
		RegionCount:    len(in.Dump.Regions),
		CaptureStatus:  string(in.Dump.Outcome()),
		PartialRegions: in.Dump.PartialRegions,
		MerkleRoot:     receipt.RootHash,
		SignerKeyID:    receipt.SignerKeyID,
		EvidenceURI:    "file://" + written.Dir,
		Classification: string(format.ClassificationConfidential),
		ToolName:       version.Name,
		ToolVersion:    buildInfo.Version,
		KernelVersion:  in.KernelVersion,
	}

	return &SealStoreResult{
		Receipt:      receipt,
		CASEBundle:   caseBundle,
		Written:      written,
		SealDuration: sealDuration,
		Notification: notification,
	}, nil
}

// OneShotOptions configure a single manual capture.
type OneShotOptions struct {
	PID           int
	RuleName      string
	Signer        *seal.Signer
	Writer        *evidence.Writer
	Resolver      *container.Resolver
	ProcRoot      string
	EvidenceRoot  string
	NodeName      string
	Operator      string
	KernelVersion string
	MaxBytes      int64
	Filter        capture.FilterOptions
	Encrypted     bool
	Compression   string
}

// CaptureOnce acquires, seals and stores the memory of a single process.
//
// This is the manual counterpart to the daemon: an incident responder who
// already knows which process matters does not need to wait for it to execute
// something that trips a rule.
func CaptureOnce(ctx context.Context, opts OneShotOptions) (*SealStoreResult, error) {
	if opts.RuleName == "" {
		opts.RuleName = "manual_capture"
	}

	dump, err := capture.DumpProcessMemory(ctx, opts.PID, capture.Options{
		ProcRoot: opts.ProcRoot,
		Filter:   opts.Filter,
		MaxBytes: opts.MaxBytes,
	})
	if err != nil {
		return nil, err
	}
	if dump.TotalBytes == 0 {
		return nil, fmt.Errorf("pipeline: no readable memory in pid %d (%d regions skipped)", opts.PID, dump.SkippedRegions)
	}

	info := &container.Info{HostPID: opts.PID, NodeName: opts.NodeName}
	if opts.Resolver != nil {
		if resolved, err := opts.Resolver.Resolve(0, opts.PID); err == nil && resolved != nil {
			info = resolved
		}
	}
	dump.NamespacePID = info.NamespacePID

	cmdline, _ := capture.ProcessCmdline(opts.ProcRoot, opts.PID)

	payload := dump.Bytes()
	dump.Release()

	return SealAndStore(SealStoreInput{
		CaseID:  format.NewCaseID(),
		Payload: payload,
		Dump:    dump,
		Rule: config.Rule{
			Name:        opts.RuleName,
			Severity:    config.SeverityMedium,
			Description: "Operator-initiated acquisition",
		},
		Event: probe.Event{
			HostPID: uint32(opts.PID),
			Comm:    dump.Comm,
			Args:    splitCmdline(cmdline),
		},
		Info:          info,
		TriggerTime:   dump.CaptureStart,
		Signer:        opts.Signer,
		Writer:        opts.Writer,
		NodeName:      opts.NodeName,
		Operator:      opts.Operator,
		KernelVersion: opts.KernelVersion,
		EvidenceRoot:  opts.EvidenceRoot,
		Encrypted:     opts.Encrypted,
		Compression:   opts.Compression,
	})
}

func splitCmdline(s string) []string {
	if s == "" {
		return nil
	}
	out := make([]string, 0, 4)
	for _, f := range splitFields(s) {
		out = append(out, f)
		if len(out) == 4 {
			break
		}
	}
	return out
}

func splitFields(s string) []string {
	var out []string
	start := -1
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' {
			if start >= 0 {
				out = append(out, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
	}
	if start >= 0 {
		out = append(out, s[start:])
	}
	return out
}

func nonEmptyString(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
