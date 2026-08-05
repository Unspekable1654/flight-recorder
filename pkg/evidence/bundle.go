package evidence

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"

	"github.com/Unspekable1654/flight-recorder/pkg/seal"
)

// Canonical file names inside a bundle.
const (
	FileManifest    = "manifest.json"
	FileMetadata    = "metadata.jsonld"
	FileReceipt     = "receipt.json"
	FileRegions     = "regions.json"
	FileDumpEnc     = "dump.bin.zst.enc"
	FileDumpPlain   = "dump.bin.zst"
	FileDumpRaw     = "dump.bin"
	FileDumpSHA256  = "dump.bin.sha256"
	ManifestVersion = "1.0"
)

// CompressionZstd is the only compression algorithm currently emitted.
// Level 3 is used: memory dumps compress 5-10x, and higher levels cost capture
// latency for a few percent of size.
const CompressionZstd = "zstd-3"

// Role identifies what a bundle file is, independently of its name.
//
// Selecting files by name prefix is a trap: "dump.bin.sha256" and
// "dump.bin.zst.enc" share a prefix, and picking the wrong one means
// "verifying" a bundle by hashing its own digest sidecar. The role is
// explicit so that cannot happen.
type Role string

// File roles.
const (
	RolePayload  Role = "payload"
	RoleReceipt  Role = "receipt"
	RoleMetadata Role = "metadata"
	RoleRegions  Role = "regions"
	RoleDigest   Role = "digest"
)

// ManifestFile describes one file in a bundle.
type ManifestFile struct {
	Name string `json:"name"`
	Role Role   `json:"role"`
	Size int64  `json:"size_bytes"`
	// SHA256 is the digest of the file AS STORED.
	SHA256 string `json:"sha256"`
	// PlaintextSHA256 is the digest of the content before compression and
	// encryption. It is what the Merkle tree and receipt describe.
	PlaintextSHA256 string `json:"plaintext_sha256,omitempty"`
	PlaintextSize   int64  `json:"plaintext_size_bytes,omitempty"`
	Encrypted       bool   `json:"encrypted"`
	Compression     string `json:"compression,omitempty"`
	Description     string `json:"description"`
}

// Manifest is the bundle inventory.
type Manifest struct {
	Version   string    `json:"version"`
	CaseID    string    `json:"case_id"`
	CreatedAt time.Time `json:"created_at"`

	ToolName    string `json:"tool_name"`
	ToolVersion string `json:"tool_version"`
	NodeName    string `json:"node_name"`

	Classification string `json:"classification"`

	// Encryption parameters. The salt is stored in the clear by design: it is
	// not secret, and without it the bundle could never be decrypted even with
	// the correct signing key.
	Encryption struct {
		Algorithm      string `json:"algorithm"`
		KeyDerivation  string `json:"key_derivation"`
		SaltHex        string `json:"salt_hex"`
		FrameSizeBytes int    `json:"frame_size_bytes"`
		SignerKeyID    string `json:"signer_key_id"`
	} `json:"encryption"`

	Files []ManifestFile `json:"files"`
}

// Payload returns the manifest entry for the memory dump itself.
//
// Entries written before the role field existed are matched on the presence of
// a plaintext digest, which only the payload carries.
func (m *Manifest) Payload() (ManifestFile, bool) {
	for _, f := range m.Files {
		if f.Role == RolePayload {
			return f, true
		}
	}
	for _, f := range m.Files {
		if f.Role == "" && f.PlaintextSHA256 != "" {
			return f, true
		}
	}
	return ManifestFile{}, false
}

// FileByName returns a manifest entry.
func (m *Manifest) FileByName(name string) (ManifestFile, bool) {
	for _, f := range m.Files {
		if f.Name == name {
			return f, true
		}
	}
	return ManifestFile{}, false
}

// WriterOptions configure bundle creation.
type WriterOptions struct {
	// Root is the evidence directory.
	Root string
	// Signer provides both the receipt signature and (via HKDF) the payload
	// encryption key.
	Signer *seal.Signer
	// Encrypt controls payload encryption. Enabled by default; disabling it is
	// only appropriate in a lab and is recorded in the manifest.
	Encrypt bool
	// Compress controls zstd compression of the payload.
	Compress bool
	// FrameSize overrides the AEAD frame size.
	FrameSize int
	// DirMode and FileMode control permissions on created artefacts.
	DirMode  os.FileMode
	FileMode os.FileMode
}

// DefaultWriterOptions returns production defaults.
func DefaultWriterOptions(root string, signer *seal.Signer) WriterOptions {
	return WriterOptions{
		Root:      root,
		Signer:    signer,
		Encrypt:   true,
		Compress:  true,
		FrameSize: DefaultFrameSize,
		DirMode:   0o750,
		FileMode:  0o640,
	}
}

// Writer creates evidence bundles.
type Writer struct {
	opts WriterOptions
}

// NewWriter validates options and returns a Writer.
func NewWriter(opts WriterOptions) (*Writer, error) {
	if opts.Root == "" {
		return nil, fmt.Errorf("evidence: root directory is required")
	}
	if opts.Encrypt && opts.Signer == nil {
		return nil, fmt.Errorf("evidence: encryption requires a signer (the payload key is derived from it)")
	}
	if opts.FrameSize <= 0 {
		opts.FrameSize = DefaultFrameSize
	}
	if opts.DirMode == 0 {
		opts.DirMode = 0o750
	}
	if opts.FileMode == 0 {
		opts.FileMode = 0o640
	}
	if err := os.MkdirAll(opts.Root, opts.DirMode); err != nil {
		return nil, fmt.Errorf("evidence: create root %s: %w", opts.Root, err)
	}
	return &Writer{opts: opts}, nil
}

// Input is everything written into one bundle.
type Input struct {
	CaseID         string
	Dump           []byte
	Receipt        *seal.SealReceipt
	CASEBundle     []byte
	Regions        any // serialised as regions.json
	Classification string
	ToolName       string
	ToolVersion    string
	NodeName       string
}

// Written describes a completed bundle.
type Written struct {
	CaseID        string
	Dir           string
	Manifest      Manifest
	PayloadBytes  int64 // bytes as stored
	PlaintextSize int64
	Compression   string
	Encrypted     bool
	Duration      time.Duration
}

// Write creates the bundle directory and all of its artefacts.
//
// Ordering matters: the payload is written first so that a crash mid-write
// leaves a bundle whose manifest is absent rather than one whose manifest
// describes files that do not exist. A bundle without a manifest is
// recognisably incomplete; a manifest that lies is not.
func (w *Writer) Write(in Input) (*Written, error) {
	if in.CaseID == "" {
		return nil, fmt.Errorf("evidence: CaseID is required")
	}
	if in.Receipt == nil {
		return nil, fmt.Errorf("evidence: receipt is required")
	}
	if strings.ContainsAny(in.CaseID, `/\..`) {
		return nil, fmt.Errorf("evidence: unsafe case id %q", in.CaseID)
	}

	start := time.Now()
	dir := filepath.Join(w.opts.Root, in.CaseID)
	if err := os.MkdirAll(dir, w.opts.DirMode); err != nil {
		return nil, fmt.Errorf("evidence: create bundle directory: %w", err)
	}

	manifest := Manifest{
		Version:        ManifestVersion,
		CaseID:         in.CaseID,
		CreatedAt:      time.Now().UTC(),
		ToolName:       in.ToolName,
		ToolVersion:    in.ToolVersion,
		NodeName:       in.NodeName,
		Classification: in.Classification,
	}

	// ---- payload ----------------------------------------------------------
	payloadName := FileDumpRaw
	switch {
	case w.opts.Compress && w.opts.Encrypt:
		payloadName = FileDumpEnc
	case w.opts.Compress:
		payloadName = FileDumpPlain
	case w.opts.Encrypt:
		payloadName = FileDumpRaw + ".enc"
	}

	stored, plainDigest, err := w.writePayload(filepath.Join(dir, payloadName), in.Dump, &manifest)
	if err != nil {
		return nil, err
	}

	compression := ""
	if w.opts.Compress {
		compression = CompressionZstd
	}
	manifest.Files = append(manifest.Files, ManifestFile{
		Name:            payloadName,
		Role:            RolePayload,
		Size:            stored,
		SHA256:          fileDigest(filepath.Join(dir, payloadName)),
		PlaintextSHA256: plainDigest,
		PlaintextSize:   int64(len(in.Dump)),
		Encrypted:       w.opts.Encrypt,
		Compression:     compression,
		Description:     "Acquired process memory",
	})

	// ---- plaintext digest sidecar -----------------------------------------
	digestLine := fmt.Sprintf("%s  %s\n", plainDigest, FileDumpRaw)
	if err := w.writeFile(filepath.Join(dir, FileDumpSHA256), []byte(digestLine), &manifest,
		RoleDigest, "SHA-256 of the decrypted, decompressed payload"); err != nil {
		return nil, err
	}

	// ---- receipt ----------------------------------------------------------
	receiptBytes, err := in.Receipt.MarshalIndent()
	if err != nil {
		return nil, err
	}
	if err := w.writeFile(filepath.Join(dir, FileReceipt), receiptBytes, &manifest,
		RoleReceipt, "Signed Merkle seal receipt"); err != nil {
		return nil, err
	}

	// ---- CASE/UCO metadata -------------------------------------------------
	if len(in.CASEBundle) > 0 {
		if err := w.writeFile(filepath.Join(dir, FileMetadata), in.CASEBundle, &manifest,
			RoleMetadata, "CASE/UCO JSON-LD evidence bundle"); err != nil {
			return nil, err
		}
	}

	// ---- region map --------------------------------------------------------
	if in.Regions != nil {
		regionBytes, err := json.MarshalIndent(in.Regions, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("evidence: marshal regions: %w", err)
		}
		if err := w.writeFile(filepath.Join(dir, FileRegions), append(regionBytes, '\n'), &manifest,
			RoleRegions, "Memory map and per-region acquisition outcome"); err != nil {
			return nil, err
		}
	}

	// ---- manifest last -----------------------------------------------------
	sort.Slice(manifest.Files, func(i, j int) bool { return manifest.Files[i].Name < manifest.Files[j].Name })
	manifestBytes, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("evidence: marshal manifest: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, FileManifest), append(manifestBytes, '\n'), w.opts.FileMode); err != nil {
		return nil, fmt.Errorf("evidence: write manifest: %w", err)
	}

	return &Written{
		CaseID:        in.CaseID,
		Dir:           dir,
		Manifest:      manifest,
		PayloadBytes:  stored,
		PlaintextSize: int64(len(in.Dump)),
		Compression:   compression,
		Encrypted:     w.opts.Encrypt,
		Duration:      time.Since(start),
	}, nil
}

// writePayload streams the dump through compression and encryption to disk.
//
// The plaintext digest is computed on the way through, so the dump is never
// buffered a second time.
func (w *Writer) writePayload(path string, dump []byte, manifest *Manifest) (stored int64, plaintextDigest string, err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, w.opts.FileMode)
	if err != nil {
		return 0, "", fmt.Errorf("evidence: create payload %s: %w", path, err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("evidence: close payload: %w", cerr)
		}
	}()

	var sink io.Writer = f
	var closers []io.Closer

	if w.opts.Encrypt {
		salt := make([]byte, 32)
		if _, rerr := rand.Read(salt); rerr != nil {
			return 0, "", fmt.Errorf("evidence: generate key salt: %w", rerr)
		}
		key, kerr := w.opts.Signer.DeriveEvidenceKey(salt)
		if kerr != nil {
			return 0, "", kerr
		}

		fw, _, ferr := newFrameWriter(sink, key, w.opts.FrameSize)
		if ferr != nil {
			return 0, "", ferr
		}
		closers = append(closers, fw)
		sink = fw

		manifest.Encryption.Algorithm = "AES-256-GCM (framed)"
		manifest.Encryption.KeyDerivation = "HKDF-SHA256(signing key, salt, \"flight-recorder/evidence/aes-256-gcm/v1\")"
		manifest.Encryption.SaltHex = hex.EncodeToString(salt)
		manifest.Encryption.FrameSizeBytes = w.opts.FrameSize
		manifest.Encryption.SignerKeyID = w.opts.Signer.KeyIDString()
	}

	if w.opts.Compress {
		zw, zerr := zstd.NewWriter(sink, zstd.WithEncoderLevel(zstd.SpeedDefault))
		if zerr != nil {
			return 0, "", fmt.Errorf("evidence: create zstd writer: %w", zerr)
		}
		// Compression must be closed before the encryption layer beneath it.
		closers = append([]io.Closer{zw}, closers...)
		sink = zw
	}

	hasher := sha256.New()
	// bytes.NewReader, not strings.NewReader(string(dump)): converting a
	// half-gigabyte dump to a string would copy the whole thing.
	if _, err := io.Copy(io.MultiWriter(sink, hasher), bytes.NewReader(dump)); err != nil {
		return 0, "", fmt.Errorf("evidence: write payload: %w", err)
	}

	for _, c := range closers {
		if cerr := c.Close(); cerr != nil {
			return 0, "", fmt.Errorf("evidence: finalise payload: %w", cerr)
		}
	}

	info, err := f.Stat()
	if err != nil {
		return 0, "", fmt.Errorf("evidence: stat payload: %w", err)
	}

	return info.Size(), hex.EncodeToString(hasher.Sum(nil)), nil
}

func (w *Writer) writeFile(path string, content []byte, manifest *Manifest, role Role, description string) error {
	if err := os.WriteFile(path, content, w.opts.FileMode); err != nil {
		return fmt.Errorf("evidence: write %s: %w", filepath.Base(path), err)
	}
	sum := sha256.Sum256(content)
	manifest.Files = append(manifest.Files, ManifestFile{
		Name:        filepath.Base(path),
		Role:        role,
		Size:        int64(len(content)),
		SHA256:      hex.EncodeToString(sum[:]),
		Description: description,
	})
	return nil
}

func fileDigest(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// LoadManifest reads a bundle manifest.
func LoadManifest(dir string) (*Manifest, error) {
	raw, err := os.ReadFile(filepath.Join(dir, FileManifest))
	if err != nil {
		return nil, fmt.Errorf("evidence: read manifest: %w", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("evidence: parse manifest: %w", err)
	}
	return &m, nil
}

// OpenPayload returns a reader over the decrypted, decompressed dump.
//
// signer may be nil for an unencrypted bundle. The caller must Close the
// returned ReadCloser.
func OpenPayload(dir string, signer *seal.Signer) (io.ReadCloser, error) {
	manifest, err := LoadManifest(dir)
	if err != nil {
		return nil, err
	}

	entry, found := manifest.Payload()
	if !found {
		return nil, fmt.Errorf("evidence: bundle %s contains no payload file", dir)
	}

	f, err := os.Open(filepath.Join(dir, entry.Name))
	if err != nil {
		return nil, fmt.Errorf("evidence: open payload: %w", err)
	}

	var src io.Reader = f
	closers := []io.Closer{f}

	if entry.Encrypted {
		if signer == nil {
			f.Close()
			return nil, fmt.Errorf("evidence: bundle %s is encrypted; a signing key is required to read it", dir)
		}
		salt, derr := hex.DecodeString(manifest.Encryption.SaltHex)
		if derr != nil {
			f.Close()
			return nil, fmt.Errorf("evidence: manifest salt is not valid hex: %w", derr)
		}
		key, kerr := signer.DeriveEvidenceKey(salt)
		if kerr != nil {
			f.Close()
			return nil, kerr
		}
		fr, ferr := newFrameReader(src, key)
		if ferr != nil {
			f.Close()
			return nil, ferr
		}
		src = fr
	}

	if entry.Compression != "" {
		zr, zerr := zstd.NewReader(src)
		if zerr != nil {
			f.Close()
			return nil, fmt.Errorf("evidence: create zstd reader: %w", zerr)
		}
		closers = append([]io.Closer{zstdCloser{zr}}, closers...)
		src = zr
	}

	return &multiCloser{Reader: src, closers: closers}, nil
}

type zstdCloser struct{ r *zstd.Decoder }

func (z zstdCloser) Close() error { z.r.Close(); return nil }

type multiCloser struct {
	io.Reader
	closers []io.Closer
}

func (m *multiCloser) Close() error {
	var firstErr error
	for _, c := range m.closers {
		if err := c.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// ReadPayload reads the entire decrypted payload into memory.
func ReadPayload(dir string, signer *seal.Signer) ([]byte, error) {
	rc, err := OpenPayload(dir, signer)
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("evidence: read payload: %w", err)
	}
	return data, nil
}
