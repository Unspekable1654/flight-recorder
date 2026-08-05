package evidence

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Unspekable1654/flight-recorder/pkg/seal"
)

func testSigner(t *testing.T) *seal.Signer {
	t.Helper()
	s, err := seal.GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	return s
}

// payload builds a dump-like buffer: mostly compressible, with a plaintext
// marker whose survival proves the round trip preserved content exactly.
func payload(size int) []byte {
	buf := make([]byte, size)
	for i := range buf {
		buf[i] = byte(i % 64)
	}
	copy(buf[size/2:], "FLIGHT_RECORDER_ROUND_TRIP_MARKER")
	return buf
}

func sealFor(t *testing.T, data []byte, signer *seal.Signer, caseID string) *seal.SealReceipt {
	t.Helper()
	receipt, _, err := seal.Seal(data, signer, seal.SealOptions{
		CaseID:      caseID,
		ToolName:    "flight-recorder",
		ToolVersion: "test",
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	return receipt
}

func TestWriteAndReadBackPayload(t *testing.T) {
	root := t.TempDir()
	signer := testSigner(t)
	data := payload(512 * 1024)

	writer, err := NewWriter(DefaultWriterOptions(root, signer))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	caseID := "11111111-2222-3333-4444-555555555555"
	written, err := writer.Write(Input{
		CaseID:         caseID,
		Dump:           data,
		Receipt:        sealFor(t, data, signer, caseID),
		CASEBundle:     []byte(`{"@context":{},"@graph":[]}`),
		Regions:        map[string]any{"regions": []string{"[heap]"}},
		Classification: "CONFIDENTIAL",
		ToolName:       "flight-recorder",
		ToolVersion:    "test",
		NodeName:       "node-1",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	for _, name := range []string{FileManifest, FileReceipt, FileMetadata, FileRegions, FileDumpEnc, FileDumpSHA256} {
		if _, err := os.Stat(filepath.Join(written.Dir, name)); err != nil {
			t.Errorf("bundle is missing %s: %v", name, err)
		}
	}

	// Compression must actually have happened for this highly regular payload.
	if written.PayloadBytes >= int64(len(data)) {
		t.Errorf("stored %d bytes for a %d byte payload; compression did not engage", written.PayloadBytes, len(data))
	}

	// The stored payload must not contain the plaintext marker.
	stored, err := os.ReadFile(filepath.Join(written.Dir, FileDumpEnc))
	if err != nil {
		t.Fatalf("read stored payload: %v", err)
	}
	if bytes.Contains(stored, []byte("FLIGHT_RECORDER_ROUND_TRIP_MARKER")) {
		t.Fatal("plaintext marker found in the stored payload: it was not encrypted")
	}
	if !bytes.HasPrefix(stored, []byte(EncMagic)) {
		t.Error("stored payload does not carry the container magic")
	}

	// Round trip.
	got, err := ReadPayload(written.Dir, signer)
	if err != nil {
		t.Fatalf("ReadPayload: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("round-tripped payload differs from the original")
	}
}

func TestReadPayloadWrongKeyFails(t *testing.T) {
	root := t.TempDir()
	signer := testSigner(t)
	data := payload(64 * 1024)

	writer, err := NewWriter(DefaultWriterOptions(root, signer))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	caseID := "aaaa1111-2222-3333-4444-555555555555"
	written, err := writer.Write(Input{CaseID: caseID, Dump: data, Receipt: sealFor(t, data, signer, caseID)})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	stranger := testSigner(t)
	if _, err := ReadPayload(written.Dir, stranger); err == nil {
		t.Fatal("payload decrypted with the wrong key")
	}
}

func TestTamperedPayloadFailsAuthentication(t *testing.T) {
	root := t.TempDir()
	signer := testSigner(t)
	data := payload(256 * 1024)

	writer, err := NewWriter(DefaultWriterOptions(root, signer))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	caseID := "bbbb1111-2222-3333-4444-555555555555"
	written, err := writer.Write(Input{CaseID: caseID, Dump: data, Receipt: sealFor(t, data, signer, caseID)})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	path := filepath.Join(written.Dir, FileDumpEnc)
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	stored[len(stored)/2] ^= 0x01
	if err := os.WriteFile(path, stored, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	if _, err := ReadPayload(written.Dir, signer); err == nil {
		t.Fatal("a modified ciphertext decrypted successfully; GCM authentication is not working")
	}
}

func TestVerifyBundleDetectsEveryTamperClass(t *testing.T) {
	newBundle := func(t *testing.T) (string, *seal.Signer, []byte) {
		t.Helper()
		root := t.TempDir()
		signer := testSigner(t)
		data := payload(128 * 1024)

		writer, err := NewWriter(DefaultWriterOptions(root, signer))
		if err != nil {
			t.Fatalf("NewWriter: %v", err)
		}

		caseID := "cccc1111-2222-3333-4444-555555555555"
		receipt := sealFor(t, data, signer, caseID)
		written, err := writer.Write(Input{
			CaseID:     caseID,
			Dump:       data,
			Receipt:    receipt,
			CASEBundle: nil,
		})
		if err != nil {
			t.Fatalf("Write: %v", err)
		}
		return written.Dir, signer, data
	}

	t.Run("pristine bundle verifies", func(t *testing.T) {
		dir, signer, _ := newBundle(t)
		report, err := VerifyBundle(dir, signer.Public(), signer)
		if err != nil {
			t.Fatalf("VerifyBundle: %v", err)
		}
		if !report.OK() {
			t.Fatalf("pristine bundle failed verification: %+v", report)
		}
		if !strings.HasPrefix(report.Summary(), "VERIFIED") {
			t.Errorf("summary = %q", report.Summary())
		}
	})

	t.Run("modified payload", func(t *testing.T) {
		dir, signer, _ := newBundle(t)
		path := filepath.Join(dir, FileDumpEnc)
		raw, _ := os.ReadFile(path)
		raw[len(raw)-20] ^= 0xFF
		_ = os.WriteFile(path, raw, 0o600)

		report, _ := VerifyBundle(dir, signer.Public(), signer)
		if report.OK() {
			t.Fatal("verification passed on a modified payload")
		}
	})

	t.Run("edited receipt", func(t *testing.T) {
		dir, signer, _ := newBundle(t)
		path := filepath.Join(dir, FileReceipt)

		raw, _ := os.ReadFile(path)
		var receipt map[string]any
		_ = json.Unmarshal(raw, &receipt)
		receipt["root_hash"] = strings.Repeat("ab", 32)
		edited, _ := json.MarshalIndent(receipt, "", "  ")
		_ = os.WriteFile(path, edited, 0o600)

		report, _ := VerifyBundle(dir, signer.Public(), signer)
		if report.OK() {
			t.Fatal("verification passed on an edited receipt")
		}
		if report.Seal.SignatureValid {
			t.Error("signature validated over a substituted root")
		}
	})

	t.Run("deleted file", func(t *testing.T) {
		dir, signer, _ := newBundle(t)
		_ = os.Remove(filepath.Join(dir, FileDumpSHA256))

		report, _ := VerifyBundle(dir, signer.Public(), signer)
		if report.OK() {
			t.Fatal("verification passed with a manifest file missing")
		}
	})

	t.Run("wrong verification key", func(t *testing.T) {
		dir, signer, _ := newBundle(t)
		stranger := testSigner(t)

		report, _ := VerifyBundle(dir, stranger.Public(), signer)
		if report.OK() {
			t.Fatal("verification passed against an unrelated public key")
		}
		if report.Seal.KeyIDMatches {
			t.Error("key id matched an unrelated key")
		}
	})

	t.Run("public key only, encrypted payload", func(t *testing.T) {
		dir, signer, _ := newBundle(t)

		// Without the private key the payload cannot be read, but the
		// signature over the receipt still has to check out.
		report, err := VerifyBundle(dir, signer.Public(), nil)
		if err != nil {
			t.Fatalf("VerifyBundle: %v", err)
		}
		if report.OK() {
			t.Error("report claims full verification without access to the payload")
		}
		if !report.Seal.SignatureValid {
			t.Error("receipt signature should still verify with the public key alone")
		}
	})
}

func TestWriteRejectsUnsafeCaseID(t *testing.T) {
	root := t.TempDir()
	signer := testSigner(t)
	writer, err := NewWriter(DefaultWriterOptions(root, signer))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	data := payload(1024)
	for _, id := range []string{"../escape", "sub/dir", `..\windows`, ".."} {
		_, err := writer.Write(Input{CaseID: id, Dump: data, Receipt: sealFor(t, data, signer, "x")})
		if err == nil {
			t.Errorf("case id %q was accepted; path traversal is possible", id)
		}
	}
}

func TestWriteRequiresReceipt(t *testing.T) {
	root := t.TempDir()
	signer := testSigner(t)
	writer, err := NewWriter(DefaultWriterOptions(root, signer))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	if _, err := writer.Write(Input{CaseID: "no-receipt", Dump: payload(16)}); err == nil {
		t.Error("a bundle was written without a receipt: unsealed evidence must not be storable")
	}
}

func TestUnencryptedBundleRoundTrip(t *testing.T) {
	root := t.TempDir()
	signer := testSigner(t)
	data := payload(32 * 1024)

	opts := DefaultWriterOptions(root, signer)
	opts.Encrypt = false
	writer, err := NewWriter(opts)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	caseID := "dddd1111-2222-3333-4444-555555555555"
	written, err := writer.Write(Input{CaseID: caseID, Dump: data, Receipt: sealFor(t, data, signer, caseID)})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	// No key needed to read an unencrypted bundle.
	got, err := ReadPayload(written.Dir, nil)
	if err != nil {
		t.Fatalf("ReadPayload: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Error("unencrypted round trip changed the payload")
	}

	report, err := VerifyBundle(written.Dir, signer.Public(), nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if !report.OK() {
		t.Errorf("unencrypted bundle failed verification: %+v", report.Errors)
	}
}

func TestManifestRecordsEncryptionParameters(t *testing.T) {
	root := t.TempDir()
	signer := testSigner(t)
	data := payload(8192)

	writer, err := NewWriter(DefaultWriterOptions(root, signer))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	caseID := "eeee1111-2222-3333-4444-555555555555"
	written, err := writer.Write(Input{CaseID: caseID, Dump: data, Receipt: sealFor(t, data, signer, caseID)})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	manifest, err := LoadManifest(written.Dir)
	if err != nil {
		t.Fatalf("LoadManifest: %v", err)
	}

	if manifest.Encryption.SaltHex == "" {
		t.Error("manifest records no salt; the bundle would be undecryptable")
	}
	if !strings.Contains(manifest.Encryption.Algorithm, "AES-256-GCM") {
		t.Errorf("algorithm = %q", manifest.Encryption.Algorithm)
	}
	if manifest.Encryption.SignerKeyID != signer.KeyIDString() {
		t.Error("manifest does not record which key the bundle was sealed with")
	}

	entry, ok := manifest.FileByName(FileDumpEnc)
	if !ok {
		t.Fatal("payload is not listed in the manifest")
	}
	if !entry.Encrypted || entry.Compression == "" {
		t.Errorf("payload entry does not describe its own processing: %+v", entry)
	}
	if entry.PlaintextSHA256 == "" || entry.PlaintextSize != int64(len(data)) {
		t.Error("manifest does not record the plaintext digest and size")
	}
}

func TestFramedEncryptionHandlesMultipleFrames(t *testing.T) {
	root := t.TempDir()
	signer := testSigner(t)

	// Random data so compression cannot collapse it below the frame size.
	data := make([]byte, 3*DefaultFrameSize+1234)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("rand: %v", err)
	}

	opts := DefaultWriterOptions(root, signer)
	opts.FrameSize = 64 * 1024
	writer, err := NewWriter(opts)
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	caseID := "ffff1111-2222-3333-4444-555555555555"
	written, err := writer.Write(Input{CaseID: caseID, Dump: data, Receipt: sealFor(t, data, signer, caseID)})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	got, err := ReadPayload(written.Dir, signer)
	if err != nil {
		t.Fatalf("ReadPayload: %v", err)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("multi-frame round trip failed: got %d bytes, want %d", len(got), len(data))
	}
}

func TestRetentionByAge(t *testing.T) {
	root := t.TempDir()

	makeBundle := func(name string, age time.Duration) {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		path := filepath.Join(dir, "data")
		if err := os.WriteFile(path, make([]byte, 1024), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		when := time.Now().Add(-age)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}
	}

	makeBundle("old-1", 100*24*time.Hour)
	makeBundle("old-2", 95*24*time.Hour)
	makeBundle("recent", 2*time.Hour)

	var deleted []string
	r := &Retention{
		Root:     root,
		MaxAge:   90 * 24 * time.Hour,
		OnDelete: func(caseID, dir string, size int64, reason string) { deleted = append(deleted, caseID) },
	}

	res, err := r.Sweep()
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.DeletedAge != 2 {
		t.Errorf("deleted %d bundles by age, want 2", res.DeletedAge)
	}
	if len(deleted) != 2 {
		t.Errorf("OnDelete fired %d times, want 2: deletions must be auditable", len(deleted))
	}
	if _, err := os.Stat(filepath.Join(root, "recent")); err != nil {
		t.Error("a recent bundle was deleted")
	}
}

func TestRetentionBySize(t *testing.T) {
	root := t.TempDir()

	for i, name := range []string{"a", "b", "c", "d"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		path := filepath.Join(dir, "data")
		if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		when := time.Now().Add(-time.Duration(10-i) * time.Hour)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}
	}

	r := &Retention{Root: root, MaxBytes: 9000, MinRetain: 1}
	res, err := r.Sweep()
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if res.DeletedSpace == 0 {
		t.Fatal("nothing was deleted despite exceeding the size cap")
	}
	if res.BytesInUse > 9000 {
		t.Errorf("usage still %d bytes, above the %d cap", res.BytesInUse, 9000)
	}

	// The newest bundle must survive: it is the one most likely to matter.
	if _, err := os.Stat(filepath.Join(root, "d")); err != nil {
		t.Error("the newest bundle was deleted")
	}
}

func TestListBundlesNewestFirst(t *testing.T) {
	root := t.TempDir()

	for i, name := range []string{"oldest", "middle", "newest"} {
		dir := filepath.Join(root, name)
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatalf("MkdirAll: %v", err)
		}
		path := filepath.Join(dir, "data")
		if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
		when := time.Now().Add(-time.Duration(10-i*4) * time.Hour)
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatalf("Chtimes: %v", err)
		}
	}

	ids, err := ListBundles(root)
	if err != nil {
		t.Fatalf("ListBundles: %v", err)
	}
	if len(ids) != 3 || ids[0] != "newest" || ids[2] != "oldest" {
		t.Errorf("ListBundles = %v, want newest first", ids)
	}
}

func TestDiskUsage(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "case")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "data"), make([]byte, 5000), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	used, err := DiskUsage(root)
	if err != nil {
		t.Fatalf("DiskUsage: %v", err)
	}
	if used < 5000 {
		t.Errorf("DiskUsage = %d, want at least 5000", used)
	}

	if used, err := DiskUsage(filepath.Join(root, "missing")); err != nil || used != 0 {
		t.Errorf("DiskUsage on a missing directory = %d, %v; want 0, nil", used, err)
	}
}
