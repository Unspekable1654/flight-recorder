// Package version carries build identity for Flight Recorder.
//
// Forensic output must be attributable to an exact build: ISO/IEC 27037 and
// the Daubert reliability criteria both require that the acquisition tool be
// identifiable and its behaviour reproducible. Every evidence bundle therefore
// records the values in this package plus a self-hash of the running binary.
package version

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"sync"
)

// Build-time overridable identity. Set with:
//
//	go build -ldflags "-X github.com/Unspekable1654/flight-recorder/pkg/version.Version=v0.2.0"
var (
	// Version is the semantic version of this build.
	Version = "0.1.0-dev"
	// Commit is the git revision the binary was built from.
	Commit = "unknown"
	// BuildDate is the RFC 3339 build timestamp.
	BuildDate = "unknown"
)

// Name is the canonical tool name recorded in forensic output.
const Name = "flight-recorder"

var (
	selfHashOnce sync.Once
	selfHash     string
	selfHashErr  error
)

// Info describes the running build.
type Info struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	BuildDate  string `json:"build_date"`
	GoVersion  string `json:"go_version"`
	Platform   string `json:"platform"`
	SelfSHA256 string `json:"self_sha256"`
}

// Get returns the build identity, including the SHA-256 of the executable.
//
// The self-hash is best effort: if the executable cannot be read (for example
// on a read-only filesystem where /proc/self/exe is unavailable), the field is
// set to "unavailable" rather than failing the capture.
func Get() Info {
	commit := Commit
	if commit == "unknown" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, s := range bi.Settings {
				if s.Key == "vcs.revision" {
					commit = s.Value
				}
			}
		}
	}

	hash, err := SelfHash()
	if err != nil {
		hash = "unavailable"
	}

	return Info{
		Name:       Name,
		Version:    Version,
		Commit:     commit,
		BuildDate:  BuildDate,
		GoVersion:  runtime.Version(),
		Platform:   runtime.GOOS + "/" + runtime.GOARCH,
		SelfSHA256: hash,
	}
}

// SelfHash returns the hex-encoded SHA-256 of the running executable.
//
// This is the tool's self-attestation: an examiner can re-hash the released
// binary and confirm that the exact artefact recorded in the evidence bundle
// produced it. The result is computed once and cached.
func SelfHash() (string, error) {
	selfHashOnce.Do(func() {
		path, err := os.Executable()
		if err != nil {
			selfHashErr = fmt.Errorf("locate executable: %w", err)
			return
		}
		f, err := os.Open(path)
		if err != nil {
			selfHashErr = fmt.Errorf("open executable %s: %w", path, err)
			return
		}
		defer f.Close()

		h := sha256.New()
		if _, err := io.Copy(h, f); err != nil {
			selfHashErr = fmt.Errorf("hash executable %s: %w", path, err)
			return
		}
		selfHash = hex.EncodeToString(h.Sum(nil))
	})
	return selfHash, selfHashErr
}

// String renders a single-line human-readable version banner.
func (i Info) String() string {
	return fmt.Sprintf("%s %s (commit %s, built %s, %s, %s)",
		i.Name, i.Version, i.Commit, i.BuildDate, i.GoVersion, i.Platform)
}
