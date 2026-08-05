# Contributing

## Development environment

You need Linux with a kernel exposing BTF. WSL2 works; a VM works; a cloud VM
works. macOS and Windows can build and run the unit tests, but not the kernel
paths.

```bash
# Check the kernel is usable
uname -r                        # 5.8 minimum, 6.1+ recommended
ls -la /sys/kernel/btf/vmlinux  # must exist for CO-RE

# Toolchain
sudo apt-get install -y golang-go clang llvm libbpf-dev linux-tools-common

git clone https://github.com/Unspekable1654/flight-recorder
cd flight-recorder
make check       # fmt, vet, unit tests with -race
make demo        # full pipeline against a synthetic capture, no root needed
```

The generated eBPF artefacts (`pkg/probe/recorder_bpfel.{go,o}`) are committed,
so `go build` works with no clang. You only need the toolchain if you change
`bpf/recorder.c` — then run `make generate` and commit the result.

## Testing

```bash
make test              # unit tests, race detector
sudo make test-integration   # real eBPF, real process_vm_readv
make fuzz              # the /proc/maps parser
make bench             # Merkle throughput
```

Integration tests skip rather than fail without root, so `make test` stays
useful on a laptop. CI runs them privileged and expects them to execute.

## What a change needs

**Tests that could fail.** A test that passes against a broken implementation
is worse than no test. Prefer asserting on behaviour that would actually break:
that a tampered byte fails verification, that a rejected config leaves the
previous ruleset active, that a dropped capture is counted.

**Comments explaining why, not what.** The code says what it does. Comments
should carry the reasoning a reader cannot recover: why duplicate-last for odd
Merkle leaves, why the ring buffer reader must not block, why EINVAL is
returned rather than panicking.

**Honest failure modes.** If something cannot be done, say so in the error and
in the docs. This is a forensic tool; overstating what it captured is the one
unforgivable defect.

## Areas that need particular care

### eBPF (`bpf/recorder.c`)

The verifier is unforgiving and its errors are cryptic.

- Bound every variable offset before a write, and mask it as well. The verifier
  needs both to prove a store into ring buffer memory is in range.
- The BPF stack is 512 bytes. `struct fr_event` is 448, which is why it is
  populated in place after `bpf_ringbuf_reserve` rather than on the stack.
- Changing `struct fr_event` means changing three things together:
  `bpf/headers/common.h`, the offsets in `pkg/probe/event.go`, and
  `FR_EVENT_SIZE`. `TestEventSizeMatchesKernelStruct` fails if you miss one.
- Read kernel memory only through `bpf_core_read` / `BPF_CORE_READ`, never a
  direct dereference: CO-RE relocation is what makes one object work across
  kernel versions.

### Acquisition (`pkg/capture`)

- `procmaps.go` parses attacker-influenced input. It must remain total: skip
  what it cannot parse, never panic, never allocate unboundedly. Add fuzz seeds
  for any new format you encounter.
- Every `process_vm_readv` errno has a defined handling strategy, documented in
  `memory_linux.go`. Do not add a bare `default:` that swallows a new one.
- Never re-parse the maps and retry an acquisition. The PID may already belong
  to a different process.

### Sealing (`pkg/seal`)

- The Merkle construction is a published, permanent contract. Changing leaf
  hashing, the odd-leaf policy or the chunk size invalidates every bundle ever
  produced. If it must change, bump `ReceiptSchemaVersion` and keep the old
  verification path.
- `VerifyProof` must stay dependency-free, so an examiner can lift it out of
  this repository and run it years from now.

### Evidence format (`pkg/evidence`, `pkg/format`)

- Bundles are read by tools that do not exist yet. Add fields; do not repurpose
  or remove them.
- CASE/UCO output is validated before it is written. Extend under the `fr:`
  namespace, never by inventing terms inside `case-*` or `uco-*`.

## Style

- `gofmt`, no exceptions. CI checks it.
- Errors wrap with `%w` and name the operation that failed, including the
  operational remedy where there is one ("requires CAP_SYS_PTRACE; add
  SYS_PTRACE to the DaemonSet securityContext").
- Exported identifiers have doc comments.
- No new dependency without a reason that survives the question "what would we
  write ourselves instead?" Kubernetes enrichment is 200 lines of HTTP here
  precisely because client-go would have been larger than the rest of the tool.

## Commits and pull requests

Conventional commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`,
`chore:`). Explain *why* in the body when it is not obvious.

Before opening a PR:

```bash
make check
make helm-lint
sudo make test-integration   # if you touched capture, probe or pipeline
```

CI runs unit tests with the race detector, fuzzing, golangci-lint, an eBPF
compile-and-regenerate check, a multi-architecture build, privileged
integration tests, manifest validation and a container build. All of it must
pass.

## Security issues

Do not open a public issue. See [SECURITY.md](SECURITY.md).
