package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/Unspekable1654/flight-recorder/pkg/version"
)

// globalFlags are shared by every subcommand.
type globalFlags struct {
	logLevel string
	logJSON  bool
}

var global globalFlags

func newRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:   "flight-recorder",
		Short: "Forensic preservation for ephemeral compute",
		Long: `Flight Recorder preserves volatile evidence from containers that do not
live long enough to be investigated.

eBPF probes observe process execution in the kernel. When an execution matches a
trigger rule, the process's memory is acquired with process_vm_readv - without
stopping, signalling or ptrace-attaching the target - then sealed with a SHA-256
Merkle tree, signed with ECDSA P-256, and exported as a CASE/UCO JSON-LD bundle
suitable for legal proceedings.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		Version:       version.Version,
	}

	root.PersistentFlags().StringVar(&global.logLevel, "log-level", "info",
		"log verbosity: trace, debug, info, warn, error")
	root.PersistentFlags().BoolVar(&global.logJSON, "log-json", false,
		"emit structured JSON logs instead of console output")

	root.AddCommand(
		newStartCommand(),
		newCaptureCommand(),
		newVerifyCommand(),
		newInspectCommand(),
		newDecryptCommand(),
		newKeygenCommand(),
		newRulesCommand(),
		newDemoCommand(),
		newVersionCommand(),
	)

	return root
}

// newLogger builds the process logger.
//
// Console output is the default because the primary consumers are a human at a
// terminal during a demo and a human reading `kubectl logs` during an incident.
// --log-json switches to the machine-readable form for log shipping.
func newLogger() zerolog.Logger {
	level, err := zerolog.ParseLevel(strings.ToLower(global.logLevel))
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.TimeFieldFormat = time.RFC3339Nano

	if global.logJSON {
		return zerolog.New(os.Stderr).Level(level).With().Timestamp().Logger()
	}

	writer := zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: "15:04:05.000"}
	return zerolog.New(writer).Level(level).With().Timestamp().Logger()
}

func newVersionCommand() *cobra.Command {
	var asJSON bool

	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print build identity, including the binary's own SHA-256",
		Long: `Print the build identity recorded in every evidence bundle.

The self SHA-256 is the hash of this executable. An examiner can re-hash the
released binary and confirm it matches the value recorded in the receipt, which
establishes exactly which build produced a given piece of evidence.`,
		RunE: func(cmd *cobra.Command, _ []string) error {
			info := version.Get()
			if asJSON {
				out, err := json.MarshalIndent(info, "", "  ")
				if err != nil {
					return fmt.Errorf("marshal version: %w", err)
				}
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
				return nil
			}

			fmt.Fprintln(cmd.OutOrStdout(), info.String())
			fmt.Fprintln(cmd.OutOrStdout(), "self sha256:", info.SelfSHA256)
			return nil
		},
	}

	cmd.Flags().BoolVar(&asJSON, "json", false, "emit JSON")
	return cmd
}
