// Command flight-recorder preserves volatile evidence from ephemeral compute.
//
// It attaches eBPF probes to process execution, acquires the memory of
// processes matching a trigger rule without stopping them, seals the result
// with a Merkle tree and an ECDSA signature, and exports it in the CASE/UCO
// forensic interchange format.
//
//	flight-recorder start --config /etc/flight-recorder/triggers.yaml
//	flight-recorder verify --bundle ./evidence/<case-id> --key ./key.pem
//	flight-recorder demo   --output /tmp/demo   # full pipeline, no kernel needed
package main

import (
	"fmt"
	"os"
)

func main() {
	if err := newRootCommand().Execute(); err != nil {
		// Cobra has already printed the usage line where appropriate; this
		// prints the failure itself so that the exit code and the message
		// always agree.
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
