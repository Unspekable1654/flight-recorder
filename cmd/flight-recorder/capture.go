package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/Unspekable1654/flight-recorder/pkg/capture"
	"github.com/Unspekable1654/flight-recorder/pkg/container"
	"github.com/Unspekable1654/flight-recorder/pkg/evidence"
	"github.com/Unspekable1654/flight-recorder/pkg/pipeline"
	"github.com/Unspekable1654/flight-recorder/pkg/probe"
	"github.com/Unspekable1654/flight-recorder/pkg/seal"
)

func newCaptureCommand() *cobra.Command {
	var (
		pid          int
		output       string
		keyPath      string
		procRoot     string
		nodeName     string
		operator     string
		maxDumpMB    int
		includeFiles bool
		includeVDSO  bool
		noEncrypt    bool
		noCompress   bool
		timeout      time.Duration
	)

	cmd := &cobra.Command{
		Use:   "capture",
		Short: "Acquire, seal and store the memory of one running process",
		Long: `Capture a specific process on demand.

Use this when the process of interest is already known - a container you are
about to delete, a suspicious PID surfaced by another tool - and waiting for a
trigger to fire would waste the window.

The target is never stopped: acquisition uses process_vm_readv, so the process
keeps running and cannot detect the read through the usual ptrace checks.

Requires CAP_SYS_PTRACE (or root).`,
		Example: `  sudo flight-recorder capture --pid 48291 --output ./evidence --key ./key.pem`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if pid <= 0 {
				return fmt.Errorf("--pid is required")
			}

			log := newLogger()

			signer, generated, err := seal.LoadOrCreateSigner(keyPath)
			if err != nil {
				return err
			}
			if generated {
				log.Warn().Str("path", keyPath).Str("key_id", signer.KeyIDString()).Msg("generated a new signing key")
			}

			writerOpts := evidence.DefaultWriterOptions(output, signer)
			writerOpts.Encrypt = !noEncrypt
			writerOpts.Compress = !noCompress
			writer, err := evidence.NewWriter(writerOpts)
			if err != nil {
				return err
			}

			filter := capture.DefaultFilterOptions()
			filter.IncludeFileBacked = includeFiles
			filter.IncludeVDSO = includeVDSO

			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			compression := evidence.CompressionZstd
			if noCompress {
				compression = ""
			}

			start := time.Now()
			result, err := pipeline.CaptureOnce(ctx, pipeline.OneShotOptions{
				PID:           pid,
				Signer:        signer,
				Writer:        writer,
				Resolver:      container.NewResolver(container.WithProcRoot(procRoot), container.WithNodeName(nodeName)),
				ProcRoot:      procRoot,
				EvidenceRoot:  output,
				NodeName:      resolveNodeName(nodeName),
				Operator:      operator,
				KernelVersion: probe.KernelVersion(),
				MaxBytes:      int64(maxDumpMB) * 1024 * 1024,
				Filter:        filter,
				Encrypted:     !noEncrypt,
				Compression:   compression,
			})
			if err != nil {
				return err
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "case id:      %s\n", result.Receipt.CaseID)
			fmt.Fprintf(out, "bundle:       %s\n", result.Written.Dir)
			fmt.Fprintf(out, "acquired:     %d bytes across %d regions (%s)\n",
				result.Receipt.DumpSizeBytes, result.Receipt.LeafCount, result.Receipt.Status)
			fmt.Fprintf(out, "merkle root:  %s\n", result.Receipt.RootHash)
			fmt.Fprintf(out, "signer key:   %s\n", result.Receipt.SignerKeyID)
			fmt.Fprintf(out, "stored:       %d bytes on disk\n", result.Written.PayloadBytes)
			fmt.Fprintf(out, "elapsed:      %s\n", time.Since(start).Round(time.Millisecond))
			fmt.Fprintf(out, "\nverify with:\n  flight-recorder verify --bundle %s --key %s\n", result.Written.Dir, keyPath)
			return nil
		},
	}

	f := cmd.Flags()
	f.IntVarP(&pid, "pid", "p", 0, "target process id (host PID namespace)")
	f.StringVarP(&output, "output", "o", "./evidence", "evidence directory")
	f.StringVarP(&keyPath, "key", "k", "./flight-recorder-key.pem", "signing key (created if absent)")
	f.StringVar(&procRoot, "proc-root", "/proc", "procfs mount point")
	f.StringVar(&nodeName, "node-name", "", "node name recorded in evidence")
	f.StringVar(&operator, "operator", "", "operator identity recorded in the chain of custody")
	f.IntVar(&maxDumpMB, "max-dump-size-mb", 512, "per-capture size cap")
	f.BoolVar(&includeFiles, "include-file-backed", false, "acquire read-only file-backed mappings")
	f.BoolVar(&includeVDSO, "include-vdso", false, "acquire [vdso] and kernel pseudo-mappings")
	f.BoolVar(&noEncrypt, "no-encrypt", false, "store the payload unencrypted")
	f.BoolVar(&noCompress, "no-compress", false, "store the payload uncompressed")
	f.DurationVar(&timeout, "timeout", 60*time.Second, "acquisition timeout")

	return cmd
}
