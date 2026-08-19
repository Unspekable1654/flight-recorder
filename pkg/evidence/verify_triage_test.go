package evidence

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/Unspekable1654/flight-recorder/pkg/seal"
)

// writeTriageBundle produces an ordinary encrypted bundle to verify against.
func writeTriageBundle(t *testing.T, signer *seal.Signer) string {
	t.Helper()

	root := t.TempDir()
	writer, err := NewWriter(DefaultWriterOptions(root, signer))
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}

	caseID := "9a8b7c6d-5e4f-3a2b-1c0d-9e8f7a6b5c4d"
	data := payload(128 * 1024)

	written, err := writer.Write(Input{
		CaseID:      caseID,
		Dump:        data,
		Receipt:     sealFor(t, data, signer, caseID),
		CASEBundle:  nil,
		Regions:     map[string]any{"regions": []string{"[heap]"}},
		ToolName:    "flight-recorder",
		ToolVersion: "test",
		NodeName:    "node-1",
	})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	return written.Dir
}

// An examiner given the bundle and the public key alone can prove the
// signature, the manifest digests and the CASE/UCO document. The content
// checks cannot run without the decryption key, and reporting those as
// failures would tell the examiner that pristine evidence is broken.
func TestVerifyWithPublicKeyOnlyReportsSkippedNotFailed(t *testing.T) {
	signer := testSigner(t)
	dir := writeTriageBundle(t, signer)

	report, err := VerifyBundle(dir, signer.Public(), nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}

	if len(report.Errors) != 0 {
		t.Errorf("public-key triage reported errors: %v", report.Errors)
	}
	if len(report.Skipped) == 0 {
		t.Error("the skipped content checks were not recorded as skipped")
	}
	if !report.SealVerified() {
		t.Error("SealVerified is false for a pristine bundle checked with the public key")
	}
	if report.OK() {
		t.Error("OK must stay strict: the payload was never examined")
	}
	if !report.Seal.SignatureValid {
		t.Error("the receipt signature should still verify without the payload")
	}
	if !report.Seal.KeyIDMatches {
		t.Error("the signer key id should still match without the payload")
	}
}

// With no key of either kind nothing cryptographic is checked, so the result
// must not be mistaken for a partial success.
func TestVerifyWithNoKeyFails(t *testing.T) {
	signer := testSigner(t)
	dir := writeTriageBundle(t, signer)

	report, err := VerifyBundle(dir, nil, nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}

	if report.SealVerified() {
		t.Error("SealVerified is true although no key was supplied")
	}
	if len(report.Errors) == 0 {
		t.Error("verifying with no key produced no error")
	}
}

// Skipping the content checks must not blind the manifest digest check.
func TestPublicKeyTriageStillCatchesTamperedPayload(t *testing.T) {
	signer := testSigner(t)
	dir := writeTriageBundle(t, signer)

	path := filepath.Join(dir, FileDumpEnc)
	stored, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read payload: %v", err)
	}
	stored[len(stored)-1] ^= 0xff
	if err := os.WriteFile(path, stored, 0o600); err != nil {
		t.Fatalf("write payload: %v", err)
	}

	report, err := VerifyBundle(dir, signer.Public(), nil)
	if err != nil {
		t.Fatalf("VerifyBundle: %v", err)
	}
	if report.SealVerified() {
		t.Error("a tampered payload passed public-key triage")
	}
}
