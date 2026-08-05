package seal

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// ReceiptSchemaVersion identifies the receipt layout. It is bumped whenever a
// field changes meaning, so that a verifier reading a five-year-old bundle
// knows which rules to apply.
const ReceiptSchemaVersion = "1.0"

// Status describes how complete the underlying capture was.
//
// Partial evidence is still evidence. What is unacceptable is partial evidence
// that presents itself as complete, so the reason for incompleteness is
// recorded in the signed receipt rather than in a log line nobody keeps.
type Status string

const (
	// StatusComplete means every requested region was read in full.
	StatusComplete Status = "complete"
	// StatusPartial means some regions were unreadable (EFAULT on
	// non-resident pages is the usual cause) and the rest was preserved.
	StatusPartial Status = "partial"
	// StatusTruncated means the capture hit the configured size cap.
	StatusTruncated Status = "truncated"
	// StatusPartialShutdown means SIGTERM arrived mid-capture and what had
	// been read was sealed rather than discarded.
	StatusPartialShutdown Status = "partial_shutdown"
	// StatusProcessExited means the target died during acquisition (ESRCH).
	StatusProcessExited Status = "process_exited"
)

// SealReceipt is the signed, self-describing chain-of-custody record for one
// capture. It is written to receipt.json inside the evidence bundle and is the
// document an examiner reads first.
type SealReceipt struct {
	SchemaVersion string `json:"schema_version"`
	CaseID        string `json:"case_id"`

	// Merkle tree parameters. All five are required to reproduce the root.
	RootHash       string `json:"root_hash"`
	LeafCount      int    `json:"leaf_count"`
	TreeDepth      int    `json:"tree_depth"`
	ChunkSizeBytes int    `json:"chunk_size_bytes"`
	OddLeafPolicy  string `json:"odd_leaf_policy"`

	// Flat digest of the same bytes, so a verifier with no Merkle
	// implementation can still perform a basic integrity check.
	DumpSHA256    string `json:"dump_sha256"`
	DumpSizeBytes int64  `json:"dump_size_bytes"`

	CaptureStartTime time.Time `json:"capture_start_time"`
	CaptureEndTime   time.Time `json:"capture_end_time"`
	SealTime         time.Time `json:"seal_time"`
	SealDurationMS   float64   `json:"seal_duration_ms"`

	Signature          string `json:"signature"`
	SignerKeyID        string `json:"signer_key_id"`
	SignatureAlgorithm string `json:"signature_algorithm"`

	ToolName       string `json:"tool_name"`
	ToolVersion    string `json:"tool_version"`
	ToolCommit     string `json:"tool_commit"`
	ToolSelfSHA256 string `json:"tool_self_sha256"`

	KernelVersion string `json:"kernel_version"`
	NodeName      string `json:"node_name"`
	Operator      string `json:"operator"`

	Status            Status   `json:"status"`
	StatusDetail      string   `json:"status_detail,omitempty"`
	RedactionApplied  bool     `json:"redaction_applied"`
	RedactionPatterns []string `json:"redaction_patterns,omitempty"`

	// Proofs are inclusion proofs for a sample of leaves. They are excluded
	// from the default JSON encoding because a 512 MB dump has 131,072 leaves
	// and embedding every proof would dwarf the evidence itself. Use
	// WithProofs to serialise them deliberately.
	Proofs map[int]MerkleProof `json:"-"`
}

// SealOptions carry the provenance metadata that cannot be derived from the
// data being sealed.
type SealOptions struct {
	CaseID            string
	ChunkSize         int
	CaptureStartTime  time.Time
	CaptureEndTime    time.Time
	Status            Status
	StatusDetail      string
	ToolName          string
	ToolVersion       string
	ToolCommit        string
	ToolSelfSHA256    string
	KernelVersion     string
	NodeName          string
	Operator          string
	RedactionApplied  bool
	RedactionPatterns []string
	// SampleProofs is how many leaf inclusion proofs to attach (0 = none).
	SampleProofs int
}

// Seal builds the Merkle tree over data, signs the root, and returns the
// receipt plus the tree (retained by the caller for on-demand proofs).
func Seal(data []byte, signer *Signer, opts SealOptions) (*SealReceipt, *Tree, error) {
	if signer == nil {
		return nil, nil, errors.New("seal: a signer is required")
	}

	start := time.Now()

	tree, err := BuildTree(data, opts.ChunkSize)
	if err != nil {
		return nil, nil, err
	}

	root := tree.RootBytes()
	signature, err := signer.Sign(root)
	if err != nil {
		return nil, nil, err
	}

	flat := sha256.Sum256(data)

	status := opts.Status
	if status == "" {
		status = StatusComplete
	}

	receipt := &SealReceipt{
		SchemaVersion:      ReceiptSchemaVersion,
		CaseID:             opts.CaseID,
		RootHash:           tree.Root(),
		LeafCount:          tree.LeafCount(),
		TreeDepth:          tree.Depth(),
		ChunkSizeBytes:     tree.ChunkSize(),
		OddLeafPolicy:      OddLeafPolicyDuplicateLast,
		DumpSHA256:         hex.EncodeToString(flat[:]),
		DumpSizeBytes:      int64(len(data)),
		CaptureStartTime:   opts.CaptureStartTime.UTC(),
		CaptureEndTime:     opts.CaptureEndTime.UTC(),
		SealTime:           start.UTC(),
		Signature:          signature,
		SignerKeyID:        signer.KeyIDString(),
		SignatureAlgorithm: "ecdsa-p256-sha256-asn1",
		ToolName:           opts.ToolName,
		ToolVersion:        opts.ToolVersion,
		ToolCommit:         opts.ToolCommit,
		ToolSelfSHA256:     opts.ToolSelfSHA256,
		KernelVersion:      opts.KernelVersion,
		NodeName:           opts.NodeName,
		Operator:           opts.Operator,
		Status:             status,
		StatusDetail:       opts.StatusDetail,
		RedactionApplied:   opts.RedactionApplied,
		RedactionPatterns:  opts.RedactionPatterns,
	}

	if opts.SampleProofs > 0 {
		n := opts.SampleProofs
		if n > tree.LeafCount() {
			n = tree.LeafCount()
		}
		receipt.Proofs = make(map[int]MerkleProof, n)
		for i := 0; i < n; i++ {
			p, err := tree.GenerateProof(i)
			if err != nil {
				return nil, nil, err
			}
			receipt.Proofs[i] = p
		}
	}

	receipt.SealDurationMS = float64(time.Since(start).Microseconds()) / 1000.0
	return receipt, tree, nil
}

// VerificationResult reports the outcome of each independent check.
type VerificationResult struct {
	RootMatches      bool   `json:"root_matches"`
	FlatHashMatches  bool   `json:"flat_hash_matches"`
	SignatureValid   bool   `json:"signature_valid"`
	LeafCountMatches bool   `json:"leaf_count_matches"`
	SizeMatches      bool   `json:"size_matches"`
	KeyIDMatches     bool   `json:"key_id_matches"`
	RecomputedRoot   string `json:"recomputed_root"`
	RecomputedSHA256 string `json:"recomputed_sha256"`
}

// OK reports whether every check passed.
func (r VerificationResult) OK() bool {
	return r.RootMatches && r.FlatHashMatches && r.SignatureValid &&
		r.LeafCountMatches && r.SizeMatches && r.KeyIDMatches
}

// Verify re-derives every sealed property of data and checks the signature.
//
// Each check is reported separately rather than collapsed into a boolean: when
// verification fails, "which check failed" is the difference between "the file
// was truncated in transit" and "someone edited the evidence".
func (r *SealReceipt) Verify(data []byte, pub *ecdsa.PublicKey) (VerificationResult, error) {
	var res VerificationResult

	tree, err := BuildTree(data, r.ChunkSizeBytes)
	if err != nil {
		return res, err
	}

	res.RecomputedRoot = tree.Root()
	res.RootMatches = tree.Root() == r.RootHash
	res.LeafCountMatches = tree.LeafCount() == r.LeafCount
	res.SizeMatches = int64(len(data)) == r.DumpSizeBytes

	flat := sha256.Sum256(data)
	res.RecomputedSHA256 = hex.EncodeToString(flat[:])
	res.FlatHashMatches = res.RecomputedSHA256 == r.DumpSHA256

	if pub == nil {
		return res, errors.New("seal: a public key is required to verify the signature")
	}

	keyID, err := KeyID(pub)
	if err != nil {
		return res, err
	}
	res.KeyIDMatches = keyID == r.SignerKeyID

	// The signature covers the root recorded in the receipt. Verifying against
	// the recomputed root instead would make a tampered dump with a rewritten
	// receipt verify successfully.
	rootBytes, err := hex.DecodeString(r.RootHash)
	if err != nil || len(rootBytes) != sha256.Size {
		return res, fmt.Errorf("seal: receipt root_hash is not a SHA-256 digest: %q", r.RootHash)
	}
	var root [32]byte
	copy(root[:], rootBytes)

	if err := VerifySignature(pub, root, r.Signature); err == nil {
		res.SignatureValid = true
	}

	return res, nil
}

// MarshalIndent renders the receipt with stable, human-readable formatting.
func (r *SealReceipt) MarshalIndent() ([]byte, error) {
	out, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("seal: marshal receipt: %w", err)
	}
	return append(out, '\n'), nil
}

// WriteFile writes the receipt as indented JSON.
func (r *SealReceipt) WriteFile(path string) error {
	out, err := r.MarshalIndent()
	if err != nil {
		return err
	}
	// The receipt contains hashes and metadata, never captured content. Group
	// read is deliberate: triage must not require the decryption key.
	// #nosec G306
	if err := os.WriteFile(path, out, 0o640); err != nil {
		return fmt.Errorf("seal: write receipt %s: %w", path, err)
	}
	return nil
}

// LoadReceipt reads a receipt from disk.
func LoadReceipt(path string) (*SealReceipt, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seal: read receipt %s: %w", path, err)
	}
	var r SealReceipt
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("seal: parse receipt %s: %w", path, err)
	}
	if r.RootHash == "" {
		return nil, fmt.Errorf("seal: receipt %s has no root_hash", path)
	}
	return &r, nil
}
