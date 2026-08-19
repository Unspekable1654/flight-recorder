package main

import (
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/Unspekable1654/flight-recorder/pkg/evidence"
	"github.com/Unspekable1654/flight-recorder/pkg/seal"
)

func newVerifyCommand() *cobra.Command {
	var (
		bundleDir string
		keyPath   string
		asJSON    bool
		all       bool
		root      string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Re-derive and check the cryptographic seal on stored evidence",
		Long: `Independently verify an evidence bundle.

Every property is recomputed from the stored bytes rather than trusted from the
receipt:

  1. each file's SHA-256 against the manifest
  2. the payload's plaintext SHA-256 after decryption and decompression
  3. the Merkle root, rebuilt from the payload at the recorded chunk size
  4. the ECDSA signature over that root, against the supplied public key
  5. structural validity of the CASE/UCO document, and that its recorded
     Merkle root agrees with the receipt

Any single failure is reported with the specific check that failed, because
"the manifest was edited" and "the payload was modified" call for very
different responses.

Exit status is 0 when every check that could be performed passed. Supplying
only the public key is a supported triage workflow: the signature, the manifest
digests and the CASE/UCO document are still proven, and the content checks are
reported as skipped rather than failed. Supplying no key at all verifies
nothing and is an error.`,
		Example: `  flight-recorder verify --bundle ./evidence/6f1c... --key /etc/flight-recorder/key.pem
  flight-recorder verify --all --root ./evidence --key ./pub.pem --json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && bundleDir == "" {
				bundleDir = args[0]
			}
			if !all && bundleDir == "" {
				return errors.New("specify --bundle <dir> or --all --root <dir>")
			}

			pub, signer, err := loadVerificationKeys(keyPath)
			if err != nil {
				return err
			}

			dirs := []string{bundleDir}
			if all {
				ids, err := evidence.ListBundles(root)
				if err != nil {
					return err
				}
				if len(ids) == 0 {
					return fmt.Errorf("no evidence bundles found under %s", root)
				}
				dirs = dirs[:0]
				for _, id := range ids {
					dirs = append(dirs, filepath.Join(root, id))
				}
			}

			reports := make([]*evidence.Report, 0, len(dirs))
			failures := 0

			for _, dir := range dirs {
				report, err := evidence.VerifyBundle(dir, pub, signer)
				if err != nil && report == nil {
					return err
				}
				reports = append(reports, report)
				if !report.SealVerified() {
					failures++
				}
			}

			out := cmd.OutOrStdout()

			if asJSON {
				payload := any(reports)
				if len(reports) == 1 {
					payload = reports[0]
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				if err := enc.Encode(payload); err != nil {
					return fmt.Errorf("encode report: %w", err)
				}
			} else {
				for _, r := range reports {
					printReport(cmd, r)
				}
			}

			if failures > 0 {
				return fmt.Errorf("%d of %d bundle(s) failed verification", failures, len(reports))
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&bundleDir, "bundle", "b", "", "evidence bundle directory")
	cmd.Flags().StringVarP(&keyPath, "key", "k", "/etc/flight-recorder/key.pem", "public or private key in PEM form")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit the full report as JSON")
	cmd.Flags().BoolVar(&all, "all", false, "verify every bundle under --root")
	cmd.Flags().StringVar(&root, "root", "/var/lib/flight-recorder/evidence", "evidence directory for --all")

	return cmd
}

func printReport(cmd *cobra.Command, r *evidence.Report) {
	out := cmd.OutOrStdout()

	fmt.Fprintf(out, "\nbundle:   %s\n", r.Dir)
	fmt.Fprintf(out, "case id:  %s\n", r.CaseID)

	check := func(label string, ok bool, detail string) {
		mark := "FAIL"
		if ok {
			mark = " OK "
		}
		if detail != "" {
			fmt.Fprintf(out, "  [%s] %-28s %s\n", mark, label, detail)
			return
		}
		fmt.Fprintf(out, "  [%s] %s\n", mark, label)
	}

	// A check that could not be run is not a check that failed. Without this
	// distinction, key-less triage of pristine evidence reads as a red wall.
	contentSkipped := !r.PayloadDecrypted && len(r.Skipped) > 0
	contentCheck := func(label string, ok bool, detail string) {
		if contentSkipped {
			fmt.Fprintf(out, "  [SKIP] %s\n", label)
			return
		}
		check(label, ok, detail)
	}

	filesOK := true
	for _, c := range r.FileChecks {
		if !c.OK {
			filesOK = false
		}
	}
	check("manifest file digests", filesOK && r.ManifestPresent, fmt.Sprintf("%d file(s)", len(r.FileChecks)))
	for _, c := range r.FileChecks {
		if !c.OK {
			fmt.Fprintf(out, "         %s: %s\n", c.Name, c.Note)
		}
	}

	contentCheck("payload decryption", r.PayloadDecrypted, "")
	contentCheck("payload sha256", r.PayloadSHA256Match, r.PayloadSHA256)
	contentCheck("merkle root", r.Seal.RootMatches, r.Seal.RecomputedRoot)
	contentCheck("leaf count", r.Seal.LeafCountMatches, "")
	check("ecdsa signature", r.Seal.SignatureValid, "")
	check("signer key id", r.Seal.KeyIDMatches, "")
	if r.CASEPresent {
		check("CASE/UCO structure", r.CASEValid, r.CASEError)
	}

	for _, sk := range r.Skipped {
		fmt.Fprintf(out, "  note: %s\n", sk)
	}
	for _, e := range r.Errors {
		fmt.Fprintf(out, "  note: %s\n", e)
	}

	fmt.Fprintf(out, "\n%s\n", r.Summary())
}

// loadVerificationKeys accepts either half of the keypair.
//
// With the private key the payload can be decrypted and the root recomputed
// from the actual bytes. With only the public key the signature and manifest
// are still checkable, which is what a third-party examiner who was given the
// public key alone can do.
func loadVerificationKeys(path string) (pub *ecdsa.PublicKey, signer *seal.Signer, err error) {
	if path == "" {
		return nil, nil, errors.New("a key is required: pass --key")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read key %s: %w", path, err)
	}

	if s, err := seal.ParseSignerPEM(raw); err == nil {
		return s.Public(), s, nil
	}

	publicKey, err := seal.ParsePublicKeyPEM(raw)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, nil, nil
}
