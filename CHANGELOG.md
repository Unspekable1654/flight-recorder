# Changelog

All notable changes to this project are recorded here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Changes that affect what a verifier can prove about stored evidence are called
out explicitly, because they matter more than ordinary behaviour changes.

## [Unreleased]

### Fixed

- `verify` reported `FAILED` on pristine evidence when given only the public
  key. The message said content verification was *skipped*, but the text was
  appended to the error list, so the bundle was judged failed and the process
  exited non-zero. Third-party triage with the public key alone is a supported
  workflow and now reports `SEAL VERIFIED`: the signature, manifest digests and
  CASE/UCO document are proven, and the four content checks render as `[SKIP]`.
  Supplying no key at all still fails, because nothing is verified in that case.
  **No change to the evidence format or to what is cryptographically proven** —
  only to how the result is reported.
- `demo --keep` corrupted the bundle it promised to keep. The flag was
  documented as skipping the destructive tamper-detection step, but was only
  ever consulted when deciding whether to print the closing warning. The step
  ran regardless, so `--keep` left behind a corrupted bundle *and* suppressed
  the notice that it had been corrupted. The step is now actually skipped.
- The release notes pointed at a `deploy.yaml` asset that no job produced, so
  the documented `kubectl apply` one-liner returned a 404. The single-file
  manifest is now assembled from `deploy/k8s` and attached to the release.

### Added

- Prebuilt binaries for **Windows and macOS** alongside Linux, on both amd64
  and arm64. Live acquisition still requires Linux, but the evidence pipeline —
  seal, sign, render CASE/UCO, compress, encrypt, verify, decrypt, inspect — is
  pure userspace and now ships for every desktop platform.
- `examples/demo-bundle`, a real sealed evidence bundle committed to the
  repository, with the public key needed to verify it. Its payload is
  synthetic. Four of its six files are plaintext and readable in a browser.
- A cross-platform CI job that builds and exercises the whole pipeline on
  Windows and macOS runners, and verifies the committed sample bundle.
- A CI job that fails the build if private key material is ever committed.
- `make build-cross`, which cross-compiles every published target, and
  `make verify-example`.
- A project landing page published from `docs/`, and a terminal recording of
  the demo in the README.
- Issue and pull request templates, `dependabot.yml`, `CODEOWNERS` and this
  changelog. CONTRIBUTING gains two rules that follow from what the tool
  handles: never attach evidence or keys to an issue, and never claim more
  than the code proves.

### Changed

- The README opens with a plain-English explanation of the problem and a
  one-command way to see the tool work, ahead of the technical material.
- `docs/pitch-deck.md` is linked from the documentation index; it was
  previously present but unreferenced.

## [0.1.0] - 2026-08-05

Initial release: eBPF-triggered forensic memory preservation for ephemeral
compute.

- eBPF probes on `sys_enter_execve` and `sched_process_exit` feeding a 16 MB
  lock-free ring buffer.
- Memory acquisition through `process_vm_readv(2)`, without stopping,
  signalling or ptrace-attaching the target.
- SHA-256 Merkle sealing with ECDSA P-256 signatures over the root.
- CASE/UCO 1.3.0 JSON-LD evidence bundles, zstd-compressed and AES-256-GCM
  encrypted in 1 MB frames.
- Hot-reloaded trigger rulesets, where a ruleset that fails validation is
  rejected and the previous one stays active.
- Exporters for Splunk HEC, Elasticsearch, syslog, webhook, gRPC and
  Prometheus, all of which carry metadata and never the dump itself.
- Kubernetes manifests and a Helm chart, with signed container images and
  SLSA build provenance.

[Unreleased]: https://github.com/Unspekable1654/flight-recorder/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/Unspekable1654/flight-recorder/releases/tag/v0.1.0
