package seal

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"golang.org/x/crypto/hkdf"
)

// Signer holds the ECDSA P-256 keypair used to attest captures.
//
// Key handling notes for production deployments: this implementation stores the
// key on the node's filesystem with 0600 permissions, which is appropriate for
// a self-contained DaemonSet but is NOT the end state. The roadmap item is to
// source the key from a KMS or Vault transit engine so that the private key
// never touches the node at all - see docs/architecture.md ADR-006.
type Signer struct {
	priv  *ecdsa.PrivateKey
	keyID string
}

// ErrNoPrivateKey is returned when an operation requires the private half of
// the keypair but only the public half is loaded.
var ErrNoPrivateKey = errors.New("seal: signer holds no private key")

// GenerateSigner creates a fresh P-256 keypair.
//
// P-256 is chosen over Ed25519 for one pragmatic reason: it is on the FIPS
// 186-4 approved list, and regulated environments (the ones that most need a
// court-admissible evidence trail) frequently cannot accept anything else.
func GenerateSigner() (*Signer, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("seal: generate P-256 key: %w", err)
	}
	return newSigner(priv)
}

func newSigner(priv *ecdsa.PrivateKey) (*Signer, error) {
	id, err := KeyID(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Signer{priv: priv, keyID: id}, nil
}

// LoadOrCreateSigner loads a PEM-encoded private key from path, generating and
// persisting one if the file does not exist.
//
// The parent directory is created with 0700 and the key file written with
// 0600. If the file exists with looser permissions the load fails: a
// world-readable signing key would let anyone forge an evidence attestation,
// which is worse than not signing at all.
func LoadOrCreateSigner(path string) (*Signer, bool, error) {
	info, err := os.Stat(path)
	switch {
	case err == nil:
		// Windows does not model POSIX permission bits: os.Stat reports 0666
		// for any writable file, so the check would reject every key. Access
		// control there is the ACL's job.
		if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
			return nil, false, fmt.Errorf("seal: signing key %s has permissions %04o; want 0600 (group/other access would allow evidence forgery)", path, info.Mode().Perm())
		}
		s, err := LoadSigner(path)
		return s, false, err

	case errors.Is(err, os.ErrNotExist):
		s, err := GenerateSigner()
		if err != nil {
			return nil, false, err
		}
		if err := s.Save(path); err != nil {
			return nil, false, err
		}
		return s, true, nil

	default:
		return nil, false, fmt.Errorf("seal: stat signing key %s: %w", path, err)
	}
}

// LoadSigner reads a PEM-encoded EC private key.
func LoadSigner(path string) (*Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seal: read signing key %s: %w", path, err)
	}
	return ParseSignerPEM(raw)
}

// ParseSignerPEM parses a PEM-encoded EC private key in either SEC 1 or PKCS 8
// form.
func ParseSignerPEM(raw []byte) (*Signer, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("seal: no PEM block found in key material")
	}

	switch block.Type {
	case "EC PRIVATE KEY":
		priv, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("seal: parse SEC1 EC key: %w", err)
		}
		return newSigner(priv)

	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("seal: parse PKCS8 key: %w", err)
		}
		priv, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("seal: key is %T, want *ecdsa.PrivateKey", key)
		}
		return newSigner(priv)

	default:
		return nil, fmt.Errorf("seal: unsupported PEM block type %q", block.Type)
	}
}

// Save writes the private key to path in SEC 1 PEM form with 0600 permissions.
func (s *Signer) Save(path string) error {
	if s.priv == nil {
		return ErrNoPrivateKey
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("seal: create key directory: %w", err)
	}

	der, err := x509.MarshalECPrivateKey(s.priv)
	if err != nil {
		return fmt.Errorf("seal: marshal EC key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	// O_EXCL is deliberate: never silently clobber an existing signing key,
	// because doing so would orphan every receipt signed with the old one.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("seal: create key file %s: %w", path, err)
	}
	defer f.Close()

	if _, err := f.Write(encoded); err != nil {
		return fmt.Errorf("seal: write key file %s: %w", path, err)
	}
	return f.Sync()
}

// WritePublicKey writes the PEM-encoded public key, which is what gets handed
// to a third party for independent verification.
func (s *Signer) WritePublicKey(path string) error {
	der, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		return fmt.Errorf("seal: marshal public key: %w", err)
	}
	encoded := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("seal: create public key directory: %w", err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		return fmt.Errorf("seal: write public key %s: %w", path, err)
	}
	return nil
}

// PublicKeyPEM returns the PEM-encoded public key.
func (s *Signer) PublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(s.Public())
	if err != nil {
		return nil, fmt.Errorf("seal: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

// Public returns the public half of the keypair.
func (s *Signer) Public() *ecdsa.PublicKey { return &s.priv.PublicKey }

// KeyIDString returns the fingerprint recorded in every receipt.
func (s *Signer) KeyIDString() string { return s.keyID }

// Sign produces an ASN.1 DER ECDSA signature over the 32-byte digest.
//
// The digest passed here is the Merkle root, which is already a SHA-256 hash;
// ECDSA signs the digest directly rather than re-hashing it.
func (s *Signer) Sign(digest [32]byte) (string, error) {
	if s.priv == nil {
		return "", ErrNoPrivateKey
	}
	sig, err := ecdsa.SignASN1(rand.Reader, s.priv, digest[:])
	if err != nil {
		return "", fmt.Errorf("seal: sign digest: %w", err)
	}
	return hex.EncodeToString(sig), nil
}

// DeriveEvidenceKey derives a 32-byte AES-256-GCM key from the signing key.
//
// HKDF-SHA256 with a per-bundle random salt means every evidence bundle gets a
// distinct content-encryption key while the operator still only has to protect
// (and back up) one secret. info binds the derivation to this tool and format
// version so the same key material can never be reused for another purpose.
func (s *Signer) DeriveEvidenceKey(salt []byte) ([]byte, error) {
	if s.priv == nil {
		return nil, ErrNoPrivateKey
	}
	if len(salt) < 16 {
		return nil, fmt.Errorf("seal: evidence key salt must be at least 16 bytes, got %d", len(salt))
	}

	secret := s.priv.D.Bytes()
	kdf := hkdf.New(sha256.New, secret, salt, []byte("flight-recorder/evidence/aes-256-gcm/v1"))
	key := make([]byte, 32)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return nil, fmt.Errorf("seal: derive evidence key: %w", err)
	}
	return key, nil
}

// KeyID computes a stable fingerprint for a public key: the hex-encoded
// SHA-256 of its PKIX DER encoding.
func KeyID(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("seal: marshal public key for fingerprint: %w", err)
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// LoadPublicKey reads a PEM-encoded public key for verification.
func LoadPublicKey(path string) (*ecdsa.PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("seal: read public key %s: %w", path, err)
	}
	return ParsePublicKeyPEM(raw)
}

// ParsePublicKeyPEM parses a PEM-encoded PKIX public key.
//
// A private key file is accepted too, so that `flight-recorder verify --key
// key.pem` works with whichever half the operator has to hand.
func ParsePublicKeyPEM(raw []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, errors.New("seal: no PEM block found in key material")
	}

	switch block.Type {
	case "PUBLIC KEY":
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("seal: parse PKIX public key: %w", err)
		}
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("seal: key is %T, want *ecdsa.PublicKey", key)
		}
		return pub, nil

	case "EC PRIVATE KEY", "PRIVATE KEY":
		s, err := ParseSignerPEM(raw)
		if err != nil {
			return nil, err
		}
		return s.Public(), nil

	default:
		return nil, fmt.Errorf("seal: unsupported PEM block type %q", block.Type)
	}
}

// VerifySignature checks a hex-encoded ASN.1 ECDSA signature over digest.
func VerifySignature(pub *ecdsa.PublicKey, digest [32]byte, signatureHex string) error {
	sig, err := hex.DecodeString(signatureHex)
	if err != nil {
		return fmt.Errorf("seal: decode signature: %w", err)
	}
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return errors.New("seal: signature does not verify against the supplied key")
	}
	return nil
}
