# Security Policy

Flight Recorder runs as a privileged DaemonSet on every node of a cluster. It
holds `CAP_SYS_PTRACE`, reads other processes' memory, and writes files that
contain credentials belonging to third parties. It is a high-value target, and
this document treats it as one.

## Reporting a vulnerability

Report privately through GitHub's advisory workflow:

**https://github.com/Unspekable1654/flight-recorder/security/advisories/new**

Please do not open a public issue for a security defect.

Include: affected version, kernel version and distribution, reproduction steps,
and the impact you believe it has. A proof of concept helps enormously.

| Stage | Target |
|---|---|
| Acknowledgement | 72 hours |
| Initial assessment | 7 days |
| Fix or mitigation plan | 30 days |
| Public advisory | Coordinated, default 90 days |

Reporters are credited in the advisory unless they ask otherwise.

## What counts as a vulnerability here

Treated as security defects:

- Any path by which a monitored workload can execute code in the recorder, read
  its signing key, or escape via its capabilities.
- Forging or altering evidence such that `flight-recorder verify` still passes.
- Reading evidence content without the key, including through metadata leakage.
- Making a node unmonitored without that being visible in the readiness probe,
  metrics or audit log — a silent monitoring gap is a vulnerability, not a bug.
- Denial of service against the node achieved through the recorder (disk
  exhaustion, CPU exhaustion, memory exhaustion) beyond the configured caps.
- Path traversal, injection or unbounded allocation from any attacker-influenced
  input: `/proc/[pid]/maps`, cgroup paths, argv, container ids, API responses.

Not vulnerabilities, by design:

- Anything requiring an already-compromised kernel. eBPF and `/proc` both rely
  on the kernel telling the truth.
- Root on the host unloading eBPF programs or reading the evidence directory.
  Root on the host has already won.
- Inability to read SGX/TDX enclave memory.
- Missing captures for activity that never triggers a monitored syscall.
- Memory dumps containing sensitive data. That is the point of the tool; the
  controls are encryption at rest, retention limits and optional redaction.

## Threat model

**Defended against**

- Fileless malware that executes in memory and never touches disk.
- Ephemeral containers that self-destruct after executing a payload.
- Post-capture tampering with evidence — detected by the Merkle root and the
  ECDSA signature over it.
- Anti-forensics aimed at disk-based collection.
- A workload deliberately triggering captures to exhaust node resources —
  bounded by global and per-container rate limits, a dump size cap, and a disk
  usage guard.

**Not defended against**

- A compromised kernel, or a rootkit that subverts eBPF or `/proc`.
- Hardware-encrypted memory (SGX, TDX).
- An attacker with host root who unloads the programs. A watchdog on BPF
  program lifecycle events is a roadmap item, not a current control.
- Exfiltration completed before any monitored syscall fires.

## Security properties of the implementation

- **Acquisition is read-only.** `process_vm_readv(2)` copies from the target's
  address space. No ptrace attach, no `SIGSTOP`, no writes. This is what
  satisfies the ACPO principle that acquisition must not alter the evidence.
- **The signing key gates everything.** It signs Merkle roots and, through
  HKDF-SHA256 with a per-bundle salt, derives every payload's AES-256-GCM key.
  Loading a key whose file permissions allow group or world access is refused.
- **Payloads are encrypted at rest** in 1 MB authenticated frames. A modified
  ciphertext fails authentication rather than decrypting to garbage.
- **The tool self-attests.** Every receipt records the SHA-256 of the running
  executable, so evidence can be tied to an exact published build.
- **Every privileged action is audited.** Captures, drops, deletions, config
  reloads and export attempts are appended to `audit.jsonl` and fsynced before
  the call returns.
- **The container is minimal.** distroless/static, read-only root filesystem,
  all capabilities dropped except the four that are required, no shell.
- **Attacker-influenced parsers are fuzzed.** The `/proc/[pid]/maps` parser is
  total: it skips what it cannot parse and never panics. `FuzzParseProcMaps`
  runs in CI on every change.

## Deployment hardening

1. Store the signing key in a Secret, back it up, and rotate it deliberately.
   Evidence sealed with a lost key can never be verified or decrypted.
2. Restrict access to the evidence directory. It contains other people's
   credentials.
3. Keep `--pprof` off in production. Profiling endpoints on a process holding
   `CAP_SYS_PTRACE` disclose more than they should.
4. Enable TLS on the gRPC evidence API, or leave it disabled. It discloses
   which workloads were captured and why.
5. Alert on `flight_recorder_ready == 0` and on
   `flight_recorder_ringbuf_lost_total` increasing. The first means a node is
   unmonitored; the second means events are being lost.
6. Keep the memory limit above `max_dump_size_mb`. The dump is held in memory
   while it is sealed; an OOM kill mid-capture loses the evidence.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

Pre-1.0: security fixes land on `main` and in the next tagged release.
