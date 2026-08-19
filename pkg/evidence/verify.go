package evidence

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	"github.com/Unspekable1654/flight-recorder/pkg/format"
	"github.com/Unspekable1654/flight-recorder/pkg/seal"
)

// FileCheck is the outcome of verifying one file in the manifest.
type FileCheck struct {
	Name     string `json:"name"`
	Expected string `json:"expected_sha256"`
	Actual   string `json:"actual_sha256"`
	OK       bool   `json:"ok"`
	Note     string `json:"note,omitempty"`
}

// Report is the complete verification outcome for a bundle.
//
// Every check is reported independently. "The evidence failed verification" is
// not an answer anyone can act on; "the payload is intact but the manifest was
// edited" is.
type Report struct {
	CaseID string `json:"case_id"`
	Dir    string `json:"dir"`

	ManifestPresent bool        `json:"manifest_present"`
	FileChecks      []FileCheck `json:"file_checks"`

	PayloadDecrypted   bool   `json:"payload_decrypted"`
	PayloadSHA256      string `json:"payload_sha256"`
	PayloadSHA256Match bool   `json:"payload_sha256_match"`

	ReceiptPresent bool                    `json:"receipt_present"`
	Seal           seal.VerificationResult `json:"seal"`
	SealChecked    bool                    `json:"seal_checked"`

	CASEPresent bool   `json:"case_present"`
	CASEValid   bool   `json:"case_valid"`
	CASEError   string `json:"case_error,omitempty"`

	Errors []string `json:"errors,omitempty"`

	// Skipped records checks that could not be performed, as opposed to checks
	// that were performed and failed. An examiner holding only the public key
	// cannot decrypt the payload, so the content checks are skipped; reporting
	// that as a failure would tell them their pristine evidence is broken.
	Skipped []string `json:"skipped,omitempty"`
}

// OK reports whether every performed check passed.
func (r *Report) OK() bool {
	if !r.ManifestPresent || !r.ReceiptPresent || len(r.Errors) > 0 {
		return false
	}
	for _, c := range r.FileChecks {
		if !c.OK {
			return false
		}
	}
	if r.CASEPresent && !r.CASEValid {
		return false
	}
	if !r.SealChecked || !r.Seal.OK() {
		return false
	}
	return r.PayloadDecrypted && r.PayloadSHA256Match
}

// SealVerified reports whether every check that could be performed passed.
//
// It differs from OK by tolerating checks skipped for want of the decryption
// key. That is the position a third-party examiner is in when handed the
// bundle and the public key alone, and it is a supported workflow: the
// signature over the receipt, the manifest digests and the CASE/UCO document
// are all still proven. What cannot be proven without the key is that the
// ciphertext decrypts to the plaintext the receipt names.
func (r *Report) SealVerified() bool {
	if !r.ManifestPresent || !r.ReceiptPresent || len(r.Errors) > 0 {
		return false
	}
	for _, c := range r.FileChecks {
		if !c.OK {
			return false
		}
	}
	if r.CASEPresent && !r.CASEValid {
		return false
	}
	if !r.SealChecked {
		return false
	}
	if r.PayloadDecrypted {
		// Full verification was possible, so hold it to the full standard.
		return r.Seal.OK() && r.PayloadSHA256Match
	}
	// Payload withheld: the receipt's own signature is what remains provable.
	return r.Seal.SignatureValid && r.Seal.KeyIDMatches
}

// Summary renders a one-line verdict.
func (r *Report) Summary() string {
	if r.OK() {
		return fmt.Sprintf("VERIFIED  %s  (merkle root %s)", r.CaseID, r.Seal.RecomputedRoot)
	}
	if r.SealVerified() {
		return fmt.Sprintf("SEAL VERIFIED  %s  (signature, manifest and CASE/UCO check out; payload not examined)", r.CaseID)
	}
	return fmt.Sprintf("FAILED    %s  (%d error(s))", r.CaseID, len(r.Errors))
}

// VerifyBundle re-derives every integrity property of a stored bundle.
//
// pub verifies the receipt signature. signer, when supplied, additionally
// decrypts the payload so the Merkle root can be recomputed from the actual
// bytes rather than trusted from the receipt. Verification without the
// decryption key still proves the manifest and receipt are internally
// consistent and correctly signed, which is often all a first responder needs.
func VerifyBundle(dir string, pub *ecdsa.PublicKey, signer *seal.Signer) (*Report, error) {
	report := &Report{Dir: dir}

	manifest, err := LoadManifest(dir)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report, err
	}
	report.ManifestPresent = true
	report.CaseID = manifest.CaseID

	// ---- every file listed in the manifest --------------------------------
	for _, entry := range manifest.Files {
		path := filepath.Join(dir, entry.Name)
		actual := fileDigest(path)
		check := FileCheck{Name: entry.Name, Expected: entry.SHA256, Actual: actual}

		switch {
		case actual == "":
			check.Note = "file is missing or unreadable"
		case entry.SHA256 == "":
			check.Note = "manifest records no digest for this file"
			check.OK = true
		default:
			check.OK = actual == entry.SHA256
			if !check.OK {
				check.Note = "stored bytes do not match the manifest digest"
			}
		}
		report.FileChecks = append(report.FileChecks, check)
	}

	// ---- the receipt -------------------------------------------------------
	receiptPath := filepath.Join(dir, FileReceipt)
	receipt, err := seal.LoadReceipt(receiptPath)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report, nil
	}
	report.ReceiptPresent = true

	// ---- the CASE/UCO metadata ---------------------------------------------
	metaPath := filepath.Join(dir, FileMetadata)
	if raw, err := os.ReadFile(metaPath); err == nil {
		report.CASEPresent = true
		bundle, perr := format.ParseBundle(raw)
		if perr != nil {
			report.CASEError = perr.Error()
		} else if verr := format.Validate(bundle); verr != nil {
			report.CASEError = verr.Error()
		} else {
			report.CASEValid = true
		}

		// The CASE bundle must agree with the receipt about the Merkle root;
		// a mismatch means one of the two documents was edited.
		if root, ok := bundle.FindFacetValue("fr:SealFacet", "fr:merkleRoot"); ok {
			if s, _ := root.(string); s != "" && s != receipt.RootHash {
				report.Errors = append(report.Errors,
					fmt.Sprintf("CASE bundle merkle root %s does not match receipt root %s", s, receipt.RootHash))
			}
		}
	}

	// ---- the payload --------------------------------------------------------
	if signer == nil {
		hasEncrypted := false
		for _, f := range manifest.Files {
			if f.Encrypted {
				hasEncrypted = true
			}
		}
		if hasEncrypted {
			if pub == nil {
				// No key of either kind: nothing cryptographic was checked, so
				// this is a genuine failure rather than a partial result.
				report.Errors = append(report.Errors,
					"payload is encrypted and no key was supplied: nothing could be verified")
				return report, nil
			}
			report.Skipped = append(report.Skipped,
				"payload is encrypted and no decryption key was supplied: content checks skipped")
			// The signature over the receipt's own claims is still provable.
			res, verr := verifySignatureOnly(receipt, pub)
			if verr != nil {
				report.Errors = append(report.Errors, verr.Error())
			}
			report.Seal = res
			report.SealChecked = true
			if !res.SignatureValid {
				report.Errors = append(report.Errors,
					"receipt signature does not verify against the supplied key")
			}
			return report, nil
		}
	}

	payload, err := ReadPayload(dir, signer)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
		return report, nil
	}
	report.PayloadDecrypted = true

	sum := sha256.Sum256(payload)
	report.PayloadSHA256 = hex.EncodeToString(sum[:])
	report.PayloadSHA256Match = report.PayloadSHA256 == receipt.DumpSHA256
	if !report.PayloadSHA256Match {
		report.Errors = append(report.Errors,
			fmt.Sprintf("payload digest %s does not match receipt digest %s", report.PayloadSHA256, receipt.DumpSHA256))
	}

	if pub == nil {
		report.Errors = append(report.Errors, "no public key supplied: signature not verified")
		return report, nil
	}

	res, err := receipt.Verify(payload, pub)
	if err != nil {
		report.Errors = append(report.Errors, err.Error())
	}
	report.Seal = res
	report.SealChecked = true

	if !res.SignatureValid {
		report.Errors = append(report.Errors, "receipt signature does not verify against the supplied key")
	}
	if !res.RootMatches {
		report.Errors = append(report.Errors,
			fmt.Sprintf("recomputed Merkle root %s does not match receipt root %s", res.RecomputedRoot, receipt.RootHash))
	}

	return report, nil
}

// verifySignatureOnly checks the receipt signature without access to the
// payload.
func verifySignatureOnly(receipt *seal.SealReceipt, pub *ecdsa.PublicKey) (seal.VerificationResult, error) {
	var res seal.VerificationResult

	keyID, err := seal.KeyID(pub)
	if err != nil {
		return res, err
	}
	res.KeyIDMatches = keyID == receipt.SignerKeyID

	rootBytes, err := hex.DecodeString(receipt.RootHash)
	if err != nil || len(rootBytes) != sha256.Size {
		return res, fmt.Errorf("evidence: receipt root_hash is not a SHA-256 digest")
	}
	var root [32]byte
	copy(root[:], rootBytes)

	if err := seal.VerifySignature(pub, root, receipt.Signature); err == nil {
		res.SignatureValid = true
	}
	return res, nil
}
