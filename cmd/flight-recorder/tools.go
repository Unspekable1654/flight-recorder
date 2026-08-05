package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Unspekable1654/flight-recorder/pkg/config"
	"github.com/Unspekable1654/flight-recorder/pkg/evidence"
	"github.com/Unspekable1654/flight-recorder/pkg/format"
	"github.com/Unspekable1654/flight-recorder/pkg/seal"
)

// -----------------------------------------------------------------------------
// keygen
// -----------------------------------------------------------------------------

func newKeygenCommand() *cobra.Command {
	var (
		keyPath string
		pubPath string
		force   bool
	)

	cmd := &cobra.Command{
		Use:   "keygen",
		Short: "Generate the ECDSA P-256 evidence signing key",
		Long: `Generate the signing keypair.

The private key signs every Merkle root and, through HKDF, derives the
AES-256-GCM key that encrypts every payload. Two consequences follow:

  * Back it up. Evidence sealed with a lost key can never be decrypted or
    verified again.
  * Protect it. Anyone holding it can forge an attestation and decrypt every
    bundle this node ever produced.

In production, source it from a KMS or Vault instead - see docs/architecture.md
ADR-006.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if _, err := os.Stat(keyPath); err == nil && !force {
				return fmt.Errorf("%s already exists; refusing to overwrite (use --force only if you understand that every existing bundle becomes unverifiable)", keyPath)
			} else if err == nil && force {
				if err := os.Remove(keyPath); err != nil {
					return fmt.Errorf("remove existing key: %w", err)
				}
			}

			signer, err := seal.GenerateSigner()
			if err != nil {
				return err
			}
			if err := signer.Save(keyPath); err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "private key: %s (mode 0600)\n", keyPath)

			if pubPath != "" {
				if err := signer.WritePublicKey(pubPath); err != nil {
					return err
				}
				fmt.Fprintf(out, "public key:  %s\n", pubPath)
			}
			fmt.Fprintf(out, "key id:      %s\n", signer.KeyIDString())
			return nil
		},
	}

	cmd.Flags().StringVarP(&keyPath, "key", "k", "/etc/flight-recorder/key.pem", "output path for the private key")
	cmd.Flags().StringVar(&pubPath, "pub", "", "also write the public key here (share this with examiners)")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing key")

	return cmd
}

// -----------------------------------------------------------------------------
// inspect
// -----------------------------------------------------------------------------

func newInspectCommand() *cobra.Command {
	var (
		bundleDir string
		asJSON    bool
		showCASE  bool
		regions   bool
	)

	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "Summarise an evidence bundle without decrypting it",
		Long: `Print what a bundle contains: the trigger, the workload, the acquisition
outcome and the seal parameters.

Nothing here requires the signing key, because none of it touches the payload.
This is the command to run first, on a machine that has no business holding the
decryption key.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && bundleDir == "" {
				bundleDir = args[0]
			}
			if bundleDir == "" {
				return fmt.Errorf("specify a bundle directory")
			}

			manifest, err := evidence.LoadManifest(bundleDir)
			if err != nil {
				return err
			}
			receipt, err := seal.LoadReceipt(filepath.Join(bundleDir, evidence.FileReceipt))
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()

			if asJSON {
				payload := map[string]any{"manifest": manifest, "receipt": receipt}
				if showCASE {
					if raw, err := os.ReadFile(filepath.Join(bundleDir, evidence.FileMetadata)); err == nil {
						var doc any
						if json.Unmarshal(raw, &doc) == nil {
							payload["case_bundle"] = doc
						}
					}
				}
				enc := json.NewEncoder(out)
				enc.SetIndent("", "  ")
				return enc.Encode(payload)
			}

			fmt.Fprintf(out, "case id:        %s\n", manifest.CaseID)
			fmt.Fprintf(out, "created:        %s\n", manifest.CreatedAt.Format(time.RFC3339))
			fmt.Fprintf(out, "node:           %s\n", manifest.NodeName)
			fmt.Fprintf(out, "tool:           %s %s\n", manifest.ToolName, manifest.ToolVersion)
			fmt.Fprintf(out, "classification: %s\n", manifest.Classification)
			fmt.Fprintln(out)
			fmt.Fprintf(out, "capture status: %s %s\n", receipt.Status, receipt.StatusDetail)
			fmt.Fprintf(out, "captured:       %s -> %s\n", receipt.CaptureStartTime.Format(time.RFC3339Nano), receipt.CaptureEndTime.Format(time.RFC3339Nano))
			fmt.Fprintf(out, "payload:        %d bytes, sha256 %s\n", receipt.DumpSizeBytes, receipt.DumpSHA256)
			fmt.Fprintf(out, "kernel:         %s\n", receipt.KernelVersion)
			fmt.Fprintln(out)
			fmt.Fprintf(out, "merkle root:    %s\n", receipt.RootHash)
			fmt.Fprintf(out, "tree:           %d leaves, depth %d, %d byte chunks, odd-leaf policy %q\n",
				receipt.LeafCount, receipt.TreeDepth, receipt.ChunkSizeBytes, receipt.OddLeafPolicy)
			fmt.Fprintf(out, "signature:      %s (%s)\n", truncateMiddle(receipt.Signature, 32), receipt.SignatureAlgorithm)
			fmt.Fprintf(out, "signer key id:  %s\n", receipt.SignerKeyID)
			if receipt.RedactionApplied {
				fmt.Fprintf(out, "redaction:      applied (%s)\n", strings.Join(receipt.RedactionPatterns, ", "))
			}
			fmt.Fprintln(out)

			fmt.Fprintln(out, "files:")
			for _, f := range manifest.Files {
				flags := []string{}
				if f.Encrypted {
					flags = append(flags, "encrypted")
				}
				if f.Compression != "" {
					flags = append(flags, f.Compression)
				}
				suffix := ""
				if len(flags) > 0 {
					suffix = " [" + strings.Join(flags, ", ") + "]"
				}
				fmt.Fprintf(out, "  %-24s %10d bytes%s\n", f.Name, f.Size, suffix)
			}

			if regions {
				raw, err := os.ReadFile(filepath.Join(bundleDir, evidence.FileRegions))
				if err == nil {
					fmt.Fprintln(out, "\nregions:")
					fmt.Fprintln(out, string(raw))
				}
			}

			if showCASE {
				raw, err := os.ReadFile(filepath.Join(bundleDir, evidence.FileMetadata))
				if err == nil {
					fmt.Fprintln(out, "\nCASE/UCO bundle:")
					fmt.Fprintln(out, string(raw))
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&bundleDir, "bundle", "b", "", "evidence bundle directory")
	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	cmd.Flags().BoolVar(&showCASE, "case", false, "also print the CASE/UCO document")
	cmd.Flags().BoolVar(&regions, "regions", false, "also print the memory region map")

	return cmd
}

func truncateMiddle(s string, n int) string {
	if len(s) <= n {
		return s
	}
	half := n / 2
	return s[:half] + "..." + s[len(s)-half:]
}

// -----------------------------------------------------------------------------
// decrypt
// -----------------------------------------------------------------------------

func newDecryptCommand() *cobra.Command {
	var (
		bundleDir string
		keyPath   string
		outPath   string
		verify    bool
	)

	cmd := &cobra.Command{
		Use:   "decrypt",
		Short: "Decrypt and decompress a bundle's memory dump",
		Long: `Write the plaintext memory dump to a file for analysis.

The output is raw process memory. It very likely contains credentials, session
tokens and personal data belonging to people who are not the subject of the
investigation. Treat the destination path accordingly - it inherits none of the
protections the bundle had.

With --verify the Merkle root is recomputed from the decrypted bytes before
anything is written, so a tampered payload is refused rather than analysed.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if bundleDir == "" || outPath == "" {
				return fmt.Errorf("both --bundle and --out are required")
			}

			signer, err := seal.LoadSigner(keyPath)
			if err != nil {
				return err
			}

			if verify {
				report, err := evidence.VerifyBundle(bundleDir, signer.Public(), signer)
				if err != nil {
					return err
				}
				if !report.OK() {
					return fmt.Errorf("refusing to decrypt: bundle failed verification (%s)", strings.Join(report.Errors, "; "))
				}
			}

			rc, err := evidence.OpenPayload(bundleDir, signer)
			if err != nil {
				return err
			}
			defer rc.Close()

			dst, err := os.OpenFile(outPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return fmt.Errorf("create output %s: %w", outPath, err)
			}
			defer dst.Close()

			n, err := io.Copy(dst, rc)
			if err != nil {
				return fmt.Errorf("write plaintext dump: %w", err)
			}

			fmt.Fprintf(cmd.OutOrStdout(), "wrote %d bytes to %s (mode 0600)\n", n, outPath)
			return nil
		},
	}

	cmd.Flags().StringVarP(&bundleDir, "bundle", "b", "", "evidence bundle directory")
	cmd.Flags().StringVarP(&keyPath, "key", "k", "/etc/flight-recorder/key.pem", "private key that sealed the bundle")
	cmd.Flags().StringVarP(&outPath, "out", "O", "", "output path for the plaintext dump")
	cmd.Flags().BoolVar(&verify, "verify", true, "verify the seal before decrypting")

	return cmd
}

// -----------------------------------------------------------------------------
// rules
// -----------------------------------------------------------------------------

func newRulesCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "Work with the trigger ruleset",
	}

	cmd.AddCommand(newRulesValidateCommand(), newRulesTestCommand(), newRulesDefaultCommand())
	return cmd
}

func newRulesValidateCommand() *cobra.Command {
	var path string

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate a triggers.yaml before deploying it",
		Long: `Parse and validate a ruleset.

Run this in CI against the ConfigMap you are about to apply. A rule with a
malformed regex is rejected at load time by the recorder, which means a bad
push leaves the previous ruleset running - safe, but silently not what you
asked for.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 1 && path == "" {
				path = args[0]
			}
			if path == "" {
				return fmt.Errorf("specify a config file")
			}

			cfg, err := config.Load(path)
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "%s is valid\n", path)
			fmt.Fprintf(out, "  mode:             %s\n", cfg.Mode)
			fmt.Fprintf(out, "  rules:            %d\n", len(cfg.Rules))
			fmt.Fprintf(out, "  rate limit:       %d/min global, %d/min per container\n", cfg.MaxCapturesPerMinute, cfg.MaxCapturesPerContainerPerMin)
			fmt.Fprintf(out, "  dump size cap:    %d MB\n", cfg.MaxDumpSizeMB)
			fmt.Fprintf(out, "  disk cap:         %d MB\n", cfg.MaxDiskUsageMB)
			fmt.Fprintf(out, "  retention:        %d days\n", cfg.RetentionDays)
			fmt.Fprintf(out, "  namespace filter: %s %v\n", cfg.NamespaceFilter.Mode, cfg.NamespaceFilter.Namespaces)
			if cfg.RedactionEnabled {
				fmt.Fprintln(out, "  redaction:        ENABLED (sealed bytes differ from acquired bytes)")
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&path, "config", "c", "", "path to triggers.yaml")
	return cmd
}

func newRulesTestCommand() *cobra.Command {
	var (
		path    string
		cmdline string
		comm    string
	)

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Check which rule a given command line would match",
		Long: `Evaluate a command line against a ruleset.

Use this before an engagement to confirm a rule fires on the exact string the
kernel will see. eBPF observes raw execve arguments: shell built-ins, aliases
and functions never reach it, and "cat /etc/shadow" typed at a prompt arrives
as the argv of /usr/bin/cat.`,
		Example: `  flight-recorder rules test -c triggers.yaml --cmdline "/usr/bin/cat /etc/shadow"`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cmdline == "" {
				return fmt.Errorf("--cmdline is required")
			}

			cfg := config.Default()
			if path != "" {
				loaded, err := config.Load(path)
				if err != nil {
					return err
				}
				cfg = loaded
			}

			if comm == "" {
				fields := strings.Fields(cmdline)
				if len(fields) > 0 {
					comm = filepath.Base(fields[0])
					if len(comm) > 15 {
						comm = comm[:15]
					}
				}
			}

			rule, matched := cfg.Match(cmdline, comm)
			out := cmd.OutOrStdout()

			if !matched {
				fmt.Fprintf(out, "no rule matches %q (comm %q)\n", cmdline, comm)
				return nil
			}

			fmt.Fprintf(out, "matched rule:  %s\n", rule.Name)
			fmt.Fprintf(out, "severity:      %s\n", rule.Severity)
			if rule.MITRE != "" {
				fmt.Fprintf(out, "mitre:         %s\n", rule.MITRE)
			}
			if rule.Description != "" {
				fmt.Fprintf(out, "description:   %s\n", rule.Description)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&path, "config", "c", "", "path to triggers.yaml (defaults to the built-in ruleset)")
	cmd.Flags().StringVar(&cmdline, "cmdline", "", "command line to evaluate")
	cmd.Flags().StringVar(&comm, "comm", "", "process name (inferred from the command line when omitted)")

	return cmd
}

func newRulesDefaultCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "default",
		Short: "Print the built-in ruleset as YAML",
		Long:  "Emit the default triggers.yaml, ready to be edited and mounted as a ConfigMap.",
		RunE: func(cmd *cobra.Command, _ []string) error {
			raw, err := config.Default().Marshal()
			if err != nil {
				return err
			}
			fmt.Fprint(cmd.OutOrStdout(), string(raw))
			return nil
		},
	}
}

// caseBundleSummary is used by the demo command to print a CASE bundle digest
// without duplicating the format package's internals.
func caseBundleSummary(raw []byte) string {
	bundle, err := format.ParseBundle(raw)
	if err != nil {
		return "unparseable"
	}
	return fmt.Sprintf("%d objects, digest %s", len(bundle.Graph), format.BundleDigest(raw)[:16])
}
