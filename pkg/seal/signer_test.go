package seal

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}

	digest := sha256.Sum256([]byte("merkle root stand-in"))
	sig, err := signer.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if err := VerifySignature(signer.Public(), digest, sig); err != nil {
		t.Errorf("VerifySignature on a valid signature: %v", err)
	}

	other := sha256.Sum256([]byte("a different root"))
	if err := VerifySignature(signer.Public(), other, sig); err == nil {
		t.Error("signature verified against the wrong digest")
	}

	stranger, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	if err := VerifySignature(stranger.Public(), digest, sig); err == nil {
		t.Error("signature verified against an unrelated key")
	}
}

func TestKeyPersistenceRoundTrip(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	original, created, err := LoadOrCreateSigner(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateSigner: %v", err)
	}
	if !created {
		t.Error("first call should have created a key")
	}

	reloaded, created, err := LoadOrCreateSigner(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateSigner (reload): %v", err)
	}
	if created {
		t.Error("second call created a new key instead of loading the existing one")
	}
	if reloaded.KeyIDString() != original.KeyIDString() {
		t.Errorf("key id changed on reload: %s != %s", reloaded.KeyIDString(), original.KeyIDString())
	}

	// A signature made by the original must verify under the reloaded key.
	digest := sha256.Sum256([]byte("persisted"))
	sig, err := original.Sign(digest)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := VerifySignature(reloaded.Public(), digest, sig); err != nil {
		t.Errorf("reloaded key failed to verify: %v", err)
	}
}

func TestSaveRefusesToClobber(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	first, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	if err := first.Save(keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}

	second, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	if err := second.Save(keyPath); err == nil {
		t.Fatal("Save overwrote an existing key; every receipt signed with the old key would become unverifiable")
	}
}

func TestLoadRejectsWorldReadableKey(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not meaningful on Windows")
	}

	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")

	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	if err := signer.Save(keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("Chmod: %v", err)
	}

	_, _, err = LoadOrCreateSigner(keyPath)
	if err == nil {
		t.Fatal("loaded a group/world-readable signing key")
	}
	if !strings.Contains(err.Error(), "permissions") {
		t.Errorf("error should explain the permission problem, got: %v", err)
	}
}

func TestPublicKeyPEMRoundTrip(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}

	pemBytes, err := signer.PublicKeyPEM()
	if err != nil {
		t.Fatalf("PublicKeyPEM: %v", err)
	}

	pub, err := ParsePublicKeyPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePublicKeyPEM: %v", err)
	}

	id, err := KeyID(pub)
	if err != nil {
		t.Fatalf("KeyID: %v", err)
	}
	if id != signer.KeyIDString() {
		t.Errorf("key id mismatch after PEM round trip: %s != %s", id, signer.KeyIDString())
	}

	// The private key file must also be accepted where a public key is
	// expected, so `verify --key key.pem` works with either half.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "key.pem")
	if err := signer.Save(keyPath); err != nil {
		t.Fatalf("Save: %v", err)
	}
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if _, err := ParsePublicKeyPEM(raw); err != nil {
		t.Errorf("ParsePublicKeyPEM on a private key file: %v", err)
	}
}

func TestParsePublicKeyPEMRejectsGarbage(t *testing.T) {
	cases := map[string][]byte{
		"empty":       {},
		"not pem":     []byte("just some bytes"),
		"wrong block": []byte("-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"),
	}

	for name, raw := range cases {
		if _, err := ParsePublicKeyPEM(raw); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestDeriveEvidenceKey(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}

	salt := make([]byte, 32)
	for i := range salt {
		salt[i] = byte(i)
	}

	key1, err := signer.DeriveEvidenceKey(salt)
	if err != nil {
		t.Fatalf("DeriveEvidenceKey: %v", err)
	}
	if len(key1) != 32 {
		t.Fatalf("key length = %d, want 32", len(key1))
	}

	// Same salt, same key: this is what makes a stored bundle decryptable.
	key2, err := signer.DeriveEvidenceKey(salt)
	if err != nil {
		t.Fatalf("DeriveEvidenceKey: %v", err)
	}
	if string(key1) != string(key2) {
		t.Error("derivation is not deterministic; stored bundles would be undecryptable")
	}

	// Different salt, different key: this is what stops key reuse across
	// bundles.
	salt[0] ^= 0xFF
	key3, err := signer.DeriveEvidenceKey(salt)
	if err != nil {
		t.Fatalf("DeriveEvidenceKey: %v", err)
	}
	if string(key1) == string(key3) {
		t.Error("different salts produced the same content-encryption key")
	}

	// A different signing key must produce a different content key.
	other, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}
	key4, err := other.DeriveEvidenceKey(salt)
	if err != nil {
		t.Fatalf("DeriveEvidenceKey: %v", err)
	}
	if string(key3) == string(key4) {
		t.Error("different signing keys produced the same content-encryption key")
	}

	if _, err := signer.DeriveEvidenceKey([]byte("short")); err == nil {
		t.Error("accepted a salt below the minimum length")
	}
}

func TestSealAndVerifyReceipt(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}

	data := chunks(12, 4096)
	start := time.Now().Add(-time.Second)

	receipt, tree, err := Seal(data, signer, SealOptions{
		CaseID:           "case-1",
		CaptureStartTime: start,
		CaptureEndTime:   time.Now(),
		Status:           StatusPartial,
		StatusDetail:     "2 regions unreadable",
		ToolName:         "flight-recorder",
		ToolVersion:      "0.1.0",
		KernelVersion:    "6.6.0-test",
		NodeName:         "node-1",
		Operator:         "tester",
	})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	if receipt.RootHash != tree.Root() {
		t.Error("receipt root does not match the tree it was built from")
	}
	if receipt.Status != StatusPartial || receipt.StatusDetail == "" {
		t.Error("acquisition status was not carried into the receipt")
	}
	if receipt.DumpSizeBytes != int64(len(data)) {
		t.Errorf("dump size = %d, want %d", receipt.DumpSizeBytes, len(data))
	}

	res, err := receipt.Verify(data, signer.Public())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() {
		t.Fatalf("verification failed on untampered data: %+v", res)
	}

	// Tamper: every check that should fail, must.
	tampered := append([]byte(nil), data...)
	tampered[len(tampered)/2] ^= 0x01

	res, err = receipt.Verify(tampered, signer.Public())
	if err != nil {
		t.Fatalf("Verify (tampered): %v", err)
	}
	if res.OK() {
		t.Fatal("verification passed on tampered data")
	}
	if res.RootMatches {
		t.Error("root matched despite a modified byte")
	}
	if res.FlatHashMatches {
		t.Error("flat digest matched despite a modified byte")
	}
	if !res.SignatureValid {
		t.Error("signature should still be valid: it covers the receipt's root, which was not edited")
	}
}

func TestReceiptFileRoundTrip(t *testing.T) {
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatalf("GenerateSigner: %v", err)
	}

	data := chunks(3, 1024)
	receipt, _, err := Seal(data, signer, SealOptions{CaseID: "case-file"})
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	path := filepath.Join(t.TempDir(), "receipt.json")
	if err := receipt.WriteFile(path); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	loaded, err := LoadReceipt(path)
	if err != nil {
		t.Fatalf("LoadReceipt: %v", err)
	}
	if loaded.RootHash != receipt.RootHash {
		t.Errorf("root hash changed: %s != %s", loaded.RootHash, receipt.RootHash)
	}

	res, err := loaded.Verify(data, signer.Public())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !res.OK() {
		t.Errorf("loaded receipt failed verification: %+v", res)
	}
}

func TestLoadReceiptRejectsMalformed(t *testing.T) {
	dir := t.TempDir()

	path := filepath.Join(dir, "not-json.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadReceipt(path); err == nil {
		t.Error("accepted malformed JSON")
	}

	path = filepath.Join(dir, "no-root.json")
	if err := os.WriteFile(path, []byte(`{"schema_version":"1.0"}`), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := LoadReceipt(path); err == nil {
		t.Error("accepted a receipt with no root hash")
	}
}
