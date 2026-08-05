# Flight Recorder: Forensic Preservation for Ephemeral Compute

**eBPF-triggered volatile memory acquisition with cryptographic sealing and
CASE/UCO export**

Version 0.1.0 · Apache 2.0 · https://github.com/Unspekable1654/flight-recorder

---

## Abstract

Container workloads routinely live for less time than it takes a security
operations centre to act on an alert about them. When the container is
reclaimed, its process memory — where fileless payloads, command-and-control
addresses and stolen credentials exist — is freed, and the investigation
begins at an empty crime scene. Existing eBPF security tools (Tracee, Tetragon,
Falco) observe and report events; none preserve the artefact those events refer
to.

This paper describes Flight Recorder, an open-source tool that closes the gap
between detection and preservation. Kernel probes observe process execution
with CO-RE eBPF. When an execution matches a configurable rule, the target's
memory is acquired via `process_vm_readv(2)` without stopping, signalling or
ptrace-attaching the process, then sealed with a SHA-256 Merkle tree over
page-aligned chunks, signed with ECDSA P-256, and exported as a validated
CASE/UCO JSON-LD bundle.

Measured on Linux 6.6: acquisition sustains 3.0 GB/s, a small container process
is captured in 0.4 ms, sealing 100 MB takes 85 ms, and the complete path from
kernel event to a stored, independently verified evidence bundle completes in
13 ms. A burst of 1000 process executions was observed with zero ring buffer
loss. The design's failure modes — partial reads, PID reuse, ring buffer
saturation, shutdown mid-capture — are each detected, classified and recorded
in the signed receipt rather than hidden.

---

## 1. Problem statement

### 1.1 The ephemeral evidence gap

Three timelines, in a typical incident:

| Timeline | Duration |
|---|---|
| Container executes payload, exits | seconds |
| Detection to alert | minutes |
| Alert to responder action | tens of minutes |

By the time anyone can act, the process is gone. Specifically gone:

- **Process memory** — freed at exit. This is where fileless payloads live by
  definition, where decrypted configuration sits, and where C2 addresses and
  session tokens are held.
- **The container filesystem** — an overlay upper layer, discarded on removal.
- **Network state** — connection tables torn down with the network namespace.

What remains is logs: a record that something happened, without the thing
itself. An analyst can see that `curl | sh` executed. They cannot see what was
downloaded, where it called home, or what it took.

### 1.2 What existing tools do and do not do

Falco, Tracee and Tetragon are mature, well-engineered eBPF tools. They detect,
alert and enforce. All three answer *"did something bad happen?"*

None answers *"what was in that process?"* — none captures memory contents, and
none produces output structured for evidentiary use. That is not a criticism;
it is a different problem, occupying the post-detection, pre-analysis position
in the incident response timeline, and it is currently unoccupied.

### 1.3 Requirements

R1. Capture within the lifetime of a short-lived container (target: sub-second
from kernel event to acquisition start).
R2. Do not alter the target. Acquisition must not stop, signal or attach to the
process — required by ACPO principles, and also by operational reality:
stopping a container's main process can trigger a liveness probe and destroy
the evidence.
R3. Overhead low enough for production (target: <3% idle).
R4. Output that is tamper-evident, independently verifiable, and interoperable
without this tool.
R5. Honest failure. Partial evidence must be labelled as partial, in a form
that cannot be edited away.

---

## 2. Related work

**Tracee** (Aqua Security) — eBPF runtime detection with signature-based event
analysis. Rich event coverage; no memory acquisition, no evidentiary output.

**Tetragon** (Isovalent/Cilium) — eBPF observability with in-kernel enforcement
and process lineage. Excellent process context; enforcement-oriented rather
than preservation-oriented.

**Falco** (CNCF) — the de facto Kubernetes runtime security standard. Rule
engine over syscall events; alerting, not artefact capture.

**Traditional memory forensics** (LiME, AVML, Volatility) — full-system or
full-process acquisition, designed for a machine an investigator already has.
Acquisition times measured in minutes; no trigger mechanism; nothing to attach
to once a container is gone.

**Container forensics research** — the literature documents the ephemerality
problem thoroughly and generally concludes that host-level or snapshot-based
collection is required. Snapshotting a node to capture a three-second container
is not operationally viable.

**The gap.** No tool combines a kernel-speed trigger, non-intrusive memory
acquisition, cryptographic sealing, and a standards-based evidence format.
Flight Recorder occupies exactly that intersection.

---

## 3. Architecture

### 3.1 Kernel space

Two CO-RE eBPF programs, compiled once against a vendored BTF-derived
`vmlinux.h`:

- `tracepoint/syscalls/sys_enter_execve` — the primary trigger. Entry rather
  than exit, because at entry the argv pointers still reference readable user
  memory; after exit the image has been replaced.
- `tracepoint/sched/sched_process_exit` — lifecycle bookkeeping. Exit records
  are what distinguish "we were 12 ms too slow" from "nothing happened".

Tracepoints rather than kprobes: a stable ABI matters for a tool whose failure
mode is silence.

Each event carries host PID, namespace PID, thread group id, uid, cgroup id, a
`CLOCK_BOOTTIME` timestamp, `comm`, the binary path and up to four argv
entries — 448 bytes, populated in place in the ring buffer because the BPF
stack is only 512 bytes. Delivery is via a 16 MB `BPF_MAP_TYPE_RINGBUF`.

### 3.2 PID namespace resolution

The hard part of eBPF in Kubernetes. A process that is PID 1 inside a container
is PID 48291 on the host. Acquisition needs the host PID; the forensic record
needs the container PID.

`bpf_get_ns_current_pid_tgid()` cannot help: it answers "what is my PID in the
namespace identified by (dev, ino)", requiring knowledge of the target's
namespace before the event occurs. Instead the probe walks the task structure
with CO-RE:

```c
level  = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
upids  = (struct upid *)((__u8 *)thread_pid + bpf_core_field_offset(struct pid, numbers));
bpf_core_read(&ns_pid, sizeof(ns_pid), &upids[level].nr);
```

`numbers[]` is a flexible array member, so the index cannot be constant in
`BPF_CORE_READ`; the code takes the relocated offset and indexes directly.
Userspace independently parses `NSpid:` from `/proc/[pid]/status` as a
cross-check and fallback.

### 3.3 Acquisition

```go
unix.ProcessVMReadv(pid, localIov, remoteIov, 0)
```

Read-only, no ptrace attach, no `SIGSTOP`. The target continues executing and
cannot detect the capture through the usual `TracerPid` check.

Region selection defaults to `[heap]`, `[stack]`, anonymous mappings and
writable file-backed segments — the regions holding process-specific state.
Read-only file-backed mappings (shared library text) are excluded by default:
those bytes are recoverable from the container image, and including them
multiplies dump size for no evidentiary gain. Device mappings are excluded
outright.

Acquisition is deliberately single-pass. The address map is parsed once, then
read. It is never re-parsed and retried, because by the time a retry executed
the PID could belong to a different process — evidence attributed to the wrong
workload is worse than partial evidence.

Every `process_vm_readv` errno has a defined strategy:

| errno | Meaning | Strategy |
|---|---|---|
| `ESRCH` | Target exited | Stop; return what was acquired; mark `process_exited` |
| `EFAULT` | Pages not resident (lazy allocation, swap, guard page) | Skip region, record it, continue. Normal, not exceptional |
| `ENOMEM` | Kernel allocation failure | Retry the chunk with backoff (100/400/1600 ms), halving the transfer each time |
| `EPERM` | Missing `CAP_SYS_PTRACE` | Fatal configuration error, reported with the remedy |
| `EINVAL` | Malformed iovec | Internal bug; fail this capture loudly rather than panic and stop monitoring the node |
| short read | Fewer bytes than requested | Accept; record `bytes_read`; mark `partial` |

### 3.4 Sealing

The payload is split into 4096-byte chunks — the page size on both supported
architectures, so a leaf corresponds to exactly one page of the captured
address space. Each chunk is SHA-256 hashed into a leaf; the tree is built
bottom-up, duplicating the final node at odd levels; the root is signed with
ECDSA P-256.

The tree, rather than a flat hash, buys two things. **Selective disclosure**: an
examiner can prove one page authentic without producing a dump full of
unrelated third parties' data. **Localised tamper evidence**: the tree
identifies which chunk changed.

The duplicate-last convention's known weakness — a duplicate-extended leaf
sequence colliding with a shorter one — is closed by recording `leaf_count` in
the receipt and rejecting a mismatch at verification.

### 3.5 Storage

```
evidence/<case-id>/
├── manifest.json     inventory: role, size, digest per file
├── metadata.jsonld   CASE/UCO bundle (plaintext: metadata and hashes only)
├── receipt.json      signed Merkle receipt
├── regions.json      memory map, per-region outcome, offset within the payload
├── dump.bin.zst.enc  payload: zstd-3, then AES-256-GCM in 1 MB frames
└── dump.bin.sha256   digest of the plaintext payload
```

Compression precedes encryption (encrypted data does not compress). The Merkle
tree covers the *uncompressed* bytes, because verification must reproduce what
was acquired.

Framed AEAD rather than single-shot: a 512 MB single-shot seal would need the
entire ciphertext in memory on a DaemonSet with a memory limit, and framing
means a damaged bundle is partially recoverable — everything up to the
corrupted frame still decrypts and still verifies against its leaves.

Content keys are derived per bundle: HKDF-SHA256 over the signing key with a
random per-bundle salt. One secret to protect; no key reuse across bundles.

---

## 4. Evidentiary design

### 4.1 CASE/UCO output

Output conforms to CASE 1.3.0, endorsed by INTERPOL, Europol EC3 and NIST. The
`@graph` carries: the memory dump as `uco-observable:ObservableObject` with
content, file and acquisition facets; the source `uco-observable:Process`; the
executed binary; the container; the trigger event; the
`case-investigation:InvestigativeAction`; the
`case-investigation:ProvenanceRecord` holding the seal; the `uco-tool:Tool`;
the operator identity; and typed relationships linking them.

Tool-specific fields — container identity, Merkle parameters, acquisition
completeness — are emitted under a documented `fr:` extension namespace, the
mechanism CASE itself prescribes. Every bundle is validated before it is
written: unbound prefixes, dangling references, duplicate identifiers, missing
required classes and malformed digests are errors, not warnings.

### 4.2 Chain of custody

The signed receipt records tool name, version, commit, **SHA-256 of the running
executable**, kernel version, node name, operator identity, monotonic capture
timestamps, and the complete Merkle parameters. The binary self-hash lets an
examiner tie a piece of evidence to an exact published artefact, whose digest
is published with each release.

### 4.3 Standards analysis

| Standard | Requirement | Compliance argument |
|---|---|---|
| **Daubert** | Testable, peer-reviewable, known error rate | Deterministic algorithm with a published specification; open source; SHA-256 collision probability 2⁻¹²⁸ |
| **ISO/IEC 27037** | Tool identity, methodology, verification, custody | All recorded in the signed receipt, including the tool's own binary digest |
| **ACPO Principle 1** | Actions must not change the evidence | `process_vm_readv` is read-only; the target is never stopped or signalled |
| **ACPO Principle 3** | An audit trail must exist and be reproducible | Append-only `audit.jsonl`, fsynced per entry; verification is reproducible from published algorithms |
| **FRE 901(b)(9)** | Authentication by a process or system | ECDSA-signed Merkle root plus a CASE/UCO provenance chain |

### 4.4 Honest incompleteness

Every acquisition carries a status in the *signed* receipt: `complete`,
`partial`, `truncated`, `process_exited` or `partial_shutdown`, with a detail
line counting full, partial, failed and skipped regions. `regions.json` records
each mapping and its outcome.

This is a design commitment. A forensic tool that presents partial evidence as
complete is not merely buggy — it is the defect that discredits everything else
it produced.

---

## 5. Evaluation

Measurements from the integration suite (`sudo make test-integration`) and the
benchmark suite (`make bench`).

**Platform.** Linux 6.6.87 (WSL2), Intel Core Ultra 7 155H, 22 logical cores,
Go 1.25, cgroup v2, BTF present.

### 5.1 Acquisition throughput

| Target | Bytes | Regions | Latency | Throughput |
|---|---|---|---|---|
| Python process, 32 MB buffer | 38.9 MB | — | 8.7 / 12.5 / 27.6 ms (min/p50/max, n=5) | **~3.0 GB/s** |
| Shell process | 373 KB | 9 | 0.41 ms | — |
| Self (test process) | 108 MB | 32 | 56–60 ms | ~1.8 GB/s |

### 5.2 The race window

The interval between parsing `/proc/[pid]/maps` and the first read is the
window in which the map could change. Measured: **0.03 ms**.

Capture against processes of known lifetime:

| Target lifetime | Acquisition | Outcome |
|---|---|---|
| 0 ms (immediate exit) | 501 µs | complete |
| 5 ms | 459 µs | complete |
| 25 ms | 373 µs | complete |
| 100 ms | 1.12 ms | complete |
| 500 ms | 410 µs | complete |

Every case was captured. The limiting factor is scheduling latency between the
kernel event and the worker starting, not acquisition itself.

### 5.3 Sealing

| Operation | Size | Time | Throughput |
|---|---|---|---|
| Merkle tree construction | 100 MB | **85.5 ms** | 1226 MB/s |
| Inclusion proof generation | 4096-leaf tree | 1.9 µs | — |

The design target was under 2 seconds for 100 MB. Measured 85 ms, 23× inside
budget, so sealing is never the bottleneck in the capture window.

### 5.4 End-to-end

Kernel event → rule match → resolve → acquire → seal → sign → CASE/UCO →
compress → encrypt → write → verify:

```
trigger matched     trigger_latency_ms=0.425
evidence sealed     acquire_ms=0.339  total_ms=13.011  bytes=372736  regions=9
verified            VERIFIED (merkle root 0efaab446d70fb13...)
```

**13 ms** from kernel event to a stored, independently verified bundle.

### 5.5 Event throughput

1000 rapid process executions:

| Metric | Value |
|---|---|
| Wall time | 575 ms |
| Kernel observed | 1001 |
| Submitted to ring buffer | 1001 |
| Dropped by kernel (buffer full) | **0** |
| Lost in userspace | **0** |
| Delivered to the consumer | 1001 |

Approximately 1740 events/second sustained with no loss. The 16 MB ring buffer
holds roughly 37,000 events, giving substantial headroom before back-pressure.

### 5.6 Verification and tamper detection

Every tamper class in the test suite is detected and *distinguished*:

| Tamper | Detected by |
|---|---|
| One byte flipped in the payload | Merkle root mismatch; payload digest mismatch; GCM authentication failure |
| Receipt edited (root substituted) | ECDSA signature invalid |
| Manifest file removed | Manifest digest check |
| Wrong verification key | Key id mismatch; signature invalid |
| CASE bundle root altered | Cross-check against the receipt |

Reporting checks separately is deliberate: "the manifest was edited" and "the
payload was modified" call for very different responses.

### 5.7 Threats to validity

Single machine, single kernel version. WSL2 runs a Microsoft-configured kernel
whose scheduling and I/O characteristics differ from a bare-metal node. Sample
sizes are small (n=5 for latency). Numbers are indicative of order of
magnitude, not a benchmark suite. Multi-kernel (5.15/6.1/6.8) and bare-metal
validation are outstanding.

---

## 6. Limitations

- **Kernel rootkits.** If the kernel is compromised, eBPF and `/proc` both lie.
  Explicitly outside the threat model.
- **Encrypted memory.** SGX/TDX enclave contents cannot be read.
- **Pre-trigger completion.** An attacker who finishes before any monitored
  syscall fires leaves nothing to capture. Mitigation: capture-all mode, at
  higher CPU cost.
- **Anti-eBPF.** Host root can unload BPF programs. bpffs pinning raises the
  bar; a watchdog on BPF lifecycle events is a roadmap item.
- **PID reuse.** Mitigated by validating cgroup id and process start time
  before acquisition; a mismatched identity refuses the capture rather than
  risking misattribution.
- **argv truncation.** Four arguments of 64 bytes, a verifier and bandwidth
  trade-off. Rules match substrings accordingly.
- **Single-node scope.** Cross-node correlation (distributed Merkle trees) is
  future work.

---

## 7. Future work

1. Multi-kernel validation across 5.15, 6.1 and 6.8 on bare metal.
2. KMS/Vault-backed signing so the private key never touches the node.
3. Cross-node evidence correlation for lateral movement.
4. A watchdog alerting on unauthorised BPF program unload.
5. S3-compatible evidence offload with server-side encryption.
6. Automatic MITRE ATT&CK mapping from captured indicators.
7. Volatility profile generation from the region map, so existing memory
   forensics tooling can consume these dumps directly.

---

## 8. Conclusion

The gap between detection and evidence is where attackers live. Flight Recorder
closes it by inverting the model: rather than analysing after the fact, it
preserves at kernel speed, seals cryptographically, and emits an interchange
format built for the courtroom.

The measurements show the approach is viable — 13 ms end to end, 3 GB/s
acquisition, zero event loss under burst — and, equally importantly, that its
failure modes are detectable and honestly reported. Evidence you cannot trust
is worse than no evidence. Every design decision here follows from that.

---

## References

1. Gregg, B. *BPF Performance Tools*. Addison-Wesley, 2019.
2. Merkle, R. "A Digital Signature Based on a Conventional Encryption
   Function." CRYPTO '87.
3. Casey, E., Barnum, S., Griffith, R., et al. "Advancing coordinated
   cyber-investigations and tool interoperability using a community developed
   specification language." *Digital Investigation*, 2017.
4. ISO/IEC 27037:2012. *Guidelines for identification, collection, acquisition
   and preservation of digital evidence*.
5. NIST SP 800-86. *Guide to Integrating Forensic Techniques into Incident
   Response*.
6. *Daubert v. Merrell Dow Pharmaceuticals*, 509 U.S. 579 (1993).
7. ACPO. *Good Practice Guide for Digital Evidence*, v5.
8. Linux kernel. `process_vm_readv(2)` — introduced in Linux 3.2.
9. Linux kernel. BPF ring buffer — introduced in Linux 5.8.
10. Cilium. *cilium/ebpf* — Go eBPF library.
11. Aqua Security. *Tracee*; Isovalent. *Tetragon*; CNCF. *Falco*.
12. Sysdig. *Annual Cloud-Native Security and Usage Report* — container
    lifetime distribution.
