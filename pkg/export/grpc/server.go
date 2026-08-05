// Package evidencepb implements the Flight Recorder gRPC evidence API.
//
// The API exists so that SOAR playbooks can pull evidence programmatically:
// list what was captured, fetch the metadata and receipt, verify the seal, and
// subscribe to captures as they happen. It is read-only by design. Nothing
// exposed here can delete, modify or re-seal evidence, because an API that
// could do those things would be the easiest way to attack the chain of
// custody.
package evidencepb

import (
	"context"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/Unspekable1654/flight-recorder/pkg/evidence"
	"github.com/Unspekable1654/flight-recorder/pkg/export"
	"github.com/Unspekable1654/flight-recorder/pkg/seal"
)

// defaultListLimit bounds an unbounded ListEvidence call.
const defaultListLimit = 100

// ServerConfig configures the evidence API server.
type ServerConfig struct {
	// EvidenceRoot is the directory holding bundles.
	EvidenceRoot string
	// Signer, when set, allows the server to decrypt payloads during
	// verification. Without it, VerifyEvidence still checks the manifest and
	// the receipt signature.
	Signer *seal.Signer
	// PublicKey verifies receipt signatures.
	PublicKey *ecdsa.PublicKey
	// TLSCertFile and TLSKeyFile enable transport security. Strongly
	// recommended: the API discloses which workloads were captured and why.
	TLSCertFile string
	TLSKeyFile  string
	// StreamBuffer is the per-subscriber queue depth.
	StreamBuffer int
}

// Server implements EvidenceServiceServer.
type Server struct {
	UnimplementedEvidenceServiceServer

	cfg ServerConfig

	mu     sync.RWMutex
	nextID uint64
	subs   map[uint64]*subscriber

	grpcServer *grpc.Server
}

type subscriber struct {
	ch          chan *EventNotification
	minSeverity int
	namespaces  map[string]struct{}
	dropped     uint64
}

// NewServer builds an evidence API server.
func NewServer(cfg ServerConfig) (*Server, error) {
	if cfg.EvidenceRoot == "" {
		return nil, fmt.Errorf("grpc: evidence root is required")
	}
	if cfg.StreamBuffer <= 0 {
		cfg.StreamBuffer = 64
	}
	return &Server{cfg: cfg, subs: make(map[uint64]*subscriber)}, nil
}

// ListenAndServe starts the gRPC server on addr and blocks until Stop.
func (s *Server) ListenAndServe(addr string) error {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("grpc: listen on %s: %w", addr, err)
	}
	return s.Serve(lis)
}

// Serve starts the gRPC server on an existing listener.
func (s *Server) Serve(lis net.Listener) error {
	var opts []grpc.ServerOption

	if s.cfg.TLSCertFile != "" && s.cfg.TLSKeyFile != "" {
		creds, err := credentials.NewServerTLSFromFile(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
		if err != nil {
			return fmt.Errorf("grpc: load TLS credentials: %w", err)
		}
		opts = append(opts, grpc.Creds(creds))
	}

	srv := grpc.NewServer(opts...)
	RegisterEvidenceServiceServer(srv, s)

	s.mu.Lock()
	s.grpcServer = srv
	s.mu.Unlock()

	if err := srv.Serve(lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("grpc: serve: %w", err)
	}
	return nil
}

// Stop gracefully stops the server and disconnects subscribers.
func (s *Server) Stop() {
	s.mu.Lock()
	srv := s.grpcServer
	for id, sub := range s.subs {
		close(sub.ch)
		delete(s.subs, id)
	}
	s.mu.Unlock()

	if srv != nil {
		srv.GracefulStop()
	}
}

// Publish fans a completed capture out to stream subscribers.
//
// Publishing never blocks the capture pipeline: a subscriber that cannot keep
// up loses events and its drop counter increments. Evidence is already durable
// on disk before this is called, so a dropped notification costs visibility,
// not evidence.
func (s *Server) Publish(n export.Notification) {
	msg := notificationToProto(n)
	sev := severityRank(n.Severity)

	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sub := range s.subs {
		if sev < sub.minSeverity {
			continue
		}
		if len(sub.namespaces) > 0 {
			if _, ok := sub.namespaces[n.PodNamespace]; !ok {
				continue
			}
		}
		select {
		case sub.ch <- msg:
		default:
			sub.dropped++
		}
	}
}

// ListEvidence implements EvidenceServiceServer.
func (s *Server) ListEvidence(ctx context.Context, req *ListEvidenceRequest) (*ListEvidenceResponse, error) {
	ids, err := evidence.ListBundles(s.cfg.EvidenceRoot)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list evidence: %v", err)
	}

	limit := int(req.GetLimit())
	if limit <= 0 || limit > defaultListLimit {
		limit = defaultListLimit
	}

	resp := &ListEvidenceResponse{Total: uint32(len(ids))}
	for _, id := range ids {
		if len(resp.Bundles) >= limit {
			break
		}
		summary, err := s.summarise(id)
		if err != nil {
			continue // a partially written bundle is skipped, not fatal
		}
		if req.GetSinceUnix() > 0 && summary.CreatedAtUnix < req.GetSinceUnix() {
			continue
		}
		resp.Bundles = append(resp.Bundles, summary)
	}
	return resp, nil
}

// GetEvidence implements EvidenceServiceServer.
func (s *Server) GetEvidence(ctx context.Context, req *EvidenceRequest) (*EvidenceResponse, error) {
	dir, err := s.bundleDir(req.GetCaseId())
	if err != nil {
		return nil, err
	}

	summary, err := s.summarise(req.GetCaseId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "case %s: %v", req.GetCaseId(), err)
	}

	resp := &EvidenceResponse{Summary: summary, BundlePath: dir}

	manifest, err := evidence.LoadManifest(dir)
	if err == nil {
		for _, f := range manifest.Files {
			resp.Files = append(resp.Files, &BundleFile{
				Name:        f.Name,
				SizeBytes:   f.Size,
				Sha256:      f.SHA256,
				Encrypted:   f.Encrypted,
				Compression: f.Compression,
			})
		}
	}

	if req.GetIncludeCaseBundle() {
		if raw, err := os.ReadFile(filepath.Join(dir, evidence.FileMetadata)); err == nil {
			resp.CaseBundle = raw
		}
	}
	if req.GetIncludeReceipt() {
		if raw, err := os.ReadFile(filepath.Join(dir, evidence.FileReceipt)); err == nil {
			resp.Receipt = raw
		}
	}

	return resp, nil
}

// VerifyEvidence implements EvidenceServiceServer.
func (s *Server) VerifyEvidence(ctx context.Context, req *VerifyRequest) (*VerifyResponse, error) {
	dir, err := s.bundleDir(req.GetCaseId())
	if err != nil {
		return nil, err
	}

	report, err := evidence.VerifyBundle(dir, s.cfg.PublicKey, s.cfg.Signer)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "verify %s: %v", req.GetCaseId(), err)
	}

	manifestIntact := true
	for _, c := range report.FileChecks {
		if !c.OK {
			manifestIntact = false
		}
	}

	return &VerifyResponse{
		Ok:             report.OK(),
		RootMatches:    report.Seal.RootMatches,
		SignatureValid: report.Seal.SignatureValid,
		ManifestIntact: manifestIntact,
		RecomputedRoot: report.Seal.RecomputedRoot,
		Errors:         report.Errors,
	}, nil
}

// StreamEvents implements EvidenceServiceServer.
func (s *Server) StreamEvents(req *StreamRequest, stream EvidenceService_StreamEventsServer) error {
	sub := &subscriber{
		ch:          make(chan *EventNotification, s.cfg.StreamBuffer),
		minSeverity: severityRank(req.GetMinSeverity()),
	}
	if ns := req.GetNamespaces(); len(ns) > 0 {
		sub.namespaces = make(map[string]struct{}, len(ns))
		for _, n := range ns {
			sub.namespaces[n] = struct{}{}
		}
	}

	s.mu.Lock()
	s.nextID++
	id := s.nextID
	s.subs[id] = sub
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		if existing, ok := s.subs[id]; ok && existing == sub {
			delete(s.subs, id)
			close(sub.ch)
		}
		s.mu.Unlock()
	}()

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return nil
		case msg, ok := <-sub.ch:
			if !ok {
				return nil
			}
			if err := stream.Send(msg); err != nil {
				return err
			}
		}
	}
}

// bundleDir resolves and validates a case id to a directory.
//
// The case id is attacker-influencable only in the sense that it comes from an
// API caller, but path traversal is checked regardless: this process runs
// privileged, and "..%2f..%2fetc" is the first thing anyone tries.
func (s *Server) bundleDir(caseID string) (string, error) {
	if caseID == "" {
		return "", status.Error(codes.InvalidArgument, "case_id is required")
	}
	if strings.ContainsAny(caseID, `/\`) || strings.Contains(caseID, "..") {
		return "", status.Errorf(codes.InvalidArgument, "invalid case_id %q", caseID)
	}

	dir := filepath.Join(s.cfg.EvidenceRoot, caseID)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return "", status.Errorf(codes.NotFound, "no evidence bundle for case %s", caseID)
	}
	return dir, nil
}

func (s *Server) summarise(caseID string) (*EvidenceSummary, error) {
	dir := filepath.Join(s.cfg.EvidenceRoot, caseID)

	manifest, err := evidence.LoadManifest(dir)
	if err != nil {
		return nil, err
	}
	receipt, err := seal.LoadReceipt(filepath.Join(dir, evidence.FileReceipt))
	if err != nil {
		return nil, err
	}

	summary := &EvidenceSummary{
		CaseId:         caseID,
		CreatedAtUnix:  manifest.CreatedAt.Unix(),
		DumpSizeBytes:  receipt.DumpSizeBytes,
		MerkleRoot:     receipt.RootHash,
		CaptureStatus:  string(receipt.Status),
		Classification: manifest.Classification,
	}

	// Pod, container and rule live in the CASE bundle rather than the receipt,
	// so read them from there when it is present.
	if raw, err := os.ReadFile(filepath.Join(dir, evidence.FileMetadata)); err == nil {
		if bundle, perr := parseCASESummary(raw); perr == nil {
			summary.Rule = bundle.rule
			summary.Severity = bundle.severity
			summary.PodName = bundle.podName
			summary.PodNamespace = bundle.podNamespace
			summary.ContainerId = bundle.containerID
		}
	}

	return summary, nil
}

func notificationToProto(n export.Notification) *EventNotification {
	ts := n.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}
	return &EventNotification{
		CaseId:            n.CaseID,
		TimestampUnixNano: ts.UnixNano(),
		Rule:              n.Rule,
		Severity:          n.Severity,
		MitreTechnique:    n.MITRE,
		Comm:              n.Comm,
		Cmdline:           n.Cmdline,
		HostPid:           int32(n.HostPID),
		NamespacePid:      int32(n.NamespacePID),
		ContainerId:       n.ContainerID,
		PodName:           n.PodName,
		PodNamespace:      n.PodNamespace,
		NodeName:          n.NodeName,
		DumpSizeBytes:     n.DumpSizeBytes,
		DumpSha256:        n.DumpSHA256,
		MerkleRoot:        n.MerkleRoot,
		EvidenceUri:       n.EvidenceURI,
		CaptureStatus:     n.CaptureStatus,
		LatencyMs:         n.LatencyMS,
		Classification:    n.Classification,
	}
}

func severityRank(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 4
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}
