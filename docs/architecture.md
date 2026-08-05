# Architecture Decision Records

Each record states the decision, the reasoning, what was rejected, and the cost
of being wrong. They are written so that a future maintainer can overturn one
knowingly rather than by accident.

---

## ADR-001: eBPF tracepoints, not kprobes or an LSM

**Status:** Accepted

**Decision.** Attach to `tracepoint/syscalls/sys_enter_execve` and
`tracepoint/sched/sched_process_exit`.

**Why.** Tracepoints are a stable kernel ABI. A kprobe on
`do_execveat_common` binds to a symbol that has been renamed twice in recent
memory and would break silently on kernel upgrade — silently being the
operative word for a monitoring tool.

`sys_enter` rather than `sys_exit` matters: at entry the argv pointers still
reference the *calling* process's readable user memory. At exit the image has
been replaced and the original argv is gone.

**Rejected.** BPF LSM hooks (`bpf_lsm_bprm_check_security`) give richer
context, but require `CONFIG_BPF_LSM` and kernel 5.7+ with the LSM enabled at
boot — not available on most managed Kubernetes offerings.

**Cost if wrong.** Missing an execution class. Mitigated by the exit
tracepoint, which reveals processes that appeared and vanished without a
matching capture.

---

## ADR-002: CO-RE with a vendored `vmlinux.h`

**Status:** Accepted

**Decision.** Compile once against a vendored BTF-derived `vmlinux.h`, read all
kernel structures through `bpf_core_read`, and ship one object.

**Why.** The alternative — compiling on the target node against its kernel
headers — requires a compiler, headers and several seconds of startup on every
node. Nodes in a managed cluster frequently have none of those.

The vendored header is generated from kernel 6.6 and relocates correctly on
older and newer kernels because CO-RE resolves field offsets at load time from
the *running* kernel's BTF.

**Cost if wrong.** A structure that does not exist on an older kernel causes a
load-time relocation error rather than silent corruption — which is the correct
failure mode, and is why the error message names the kernel requirement.

---

## ADR-003: PID namespace resolution by walking `task_struct`

**Status:** Accepted

**Decision.** Resolve the container-local PID in kernel space via
`task->nsproxy->pid_ns_for_children->level` and
`task->thread_pid->numbers[level].nr`.

**Why.** `bpf_get_ns_current_pid_tgid()` answers "what is my PID inside the
namespace identified by (dev, ino)". That requires knowing the target
container's namespace *before* the event. During monitoring we do not: every
container has a different one.

The CO-RE walk needs no prior knowledge. `numbers[]` is a flexible array
member, so the index cannot be a constant in `BPF_CORE_READ`; the code takes
the relocated offset of the array and indexes it directly.

Userspace independently reads `NSpid:` from `/proc/[pid]/status` as a
cross-check and as the fallback where the walk fails.

**Consequence.** The host PID is used for acquisition; the namespace PID is
reported in the evidence. Confusing the two is the most common way an eBPF tool
in Kubernetes produces evidence that correlates with nothing.

---

## ADR-004: `process_vm_readv`, not ptrace or `/proc/[pid]/mem`

**Status:** Accepted

**Decision.** Acquire memory with `process_vm_readv(2)`.

**Why.** Three properties, in order of importance:

1. **The target is never stopped.** No `PTRACE_ATTACH`, no `SIGSTOP`. This is
   what satisfies the ACPO principle that acquisition must not alter the
   evidence, and it means the attacker's process cannot detect the capture
   through the usual `TracerPid` check.
2. **A stopped process is a changed process.** Stopping a container's main
   process to dump it can trigger liveness probes, restart it, and destroy the
   thing being investigated.
3. **It is fast.** One syscall per 4 MB chunk; measured at ~3 GB/s.

**Rejected.** `/proc/[pid]/mem` requires the same capability and offers no
advantage; ptrace changes observable process state; core dumps require
signalling the target and produce files subject to `MADV_DONTDUMP` exclusions —
and `MADV_DONTDUMP` regions are exactly where cryptographic keys live.

**Cost if wrong.** Torn reads: the address space is live and can change during
acquisition. Accepted and recorded — the receipt carries the maps-parse-to-read
gap so a reader can judge how atomic the snapshot was.

---

## ADR-005: Single-pass acquisition, never retry the whole operation

**Status:** Accepted

**Decision.** Parse the address map once. Read each region once. On `ESRCH`,
stop and return what was acquired. Never re-parse and retry.

**Why.** The window between parsing the map and reading is a genuine race. The
tempting fix — re-parse and retry — is actively dangerous: by the time the
retry runs the PID may belong to a different process, and the result would be
evidence attributed to the wrong workload. That is worse than partial evidence.

**Consequences.** Per-errno handling is explicit: `EFAULT` skips the region
(non-resident pages are normal), `ENOMEM` retries the *chunk* with backoff and
a halved size, `EPERM` is a fatal configuration error, `ESRCH` ends the
acquisition. Partial and failed region counts are recorded and signed.

---

## ADR-006: Filesystem signing key, with KMS as the roadmap

**Status:** Accepted, with a known gap

**Decision.** Generate an ECDSA P-256 key on first run, store it at
`/etc/flight-recorder/key.pem` with mode 0600, refuse to load it if the
permissions are looser.

**Why P-256 over Ed25519.** FIPS 186-4 approval. The environments that most
need a court-admissible trail are frequently the ones that cannot accept
anything else.

**The gap.** A node-local private key means node compromise implies evidence
forgery capability for that node. The end state is a KMS or Vault transit
engine, so the key never touches the node. This is documented rather than
hidden because an evaluator should know exactly what the current guarantee is.

**Consequence.** The same key derives payload encryption keys via HKDF-SHA256
with a per-bundle salt. One secret to protect, one to back up, and no key reuse
across bundles.

---

## ADR-007: Merkle tree over 4 KB chunks

**Status:** Accepted

**Decision.** SHA-256 leaves over 4096-byte chunks; odd levels duplicate the
last node; the leaf count is recorded in the receipt.

**Why a tree at all.** A flat hash proves "something changed". A tree localises
the change and — more importantly — allows selective disclosure: an examiner
can prove one page is authentic without producing a dump full of unrelated
third parties' data.

**Why 4096.** It is the page size on both supported architectures, so a leaf is
exactly one page of the captured address space. "Page 0x7f3a1000 is authentic"
is a statement someone can act on.

**Why duplicate-last.** Forensic reproducibility requires one documented,
deterministic rule, and this is the convention an independent implementer is
most likely to already have. Its known weakness — a duplicate-extended leaf
sequence colliding with a shorter one — is closed by recording `leaf_count` and
rejecting a mismatch during verification.

**Cost if wrong.** Changing any of this invalidates every bundle ever produced.
Hence `ReceiptSchemaVersion`.

---

## ADR-008: The ring buffer reader must never block

**Status:** Accepted

**Decision.** Rules are evaluated on the reader goroutine. Acquisition, sealing
and export run on a bounded worker pool. A full queue drops explicitly, counts
the drop, and audits it.

**Why.** A container that executes a payload and exits three seconds later
gives a window measured in hundreds of milliseconds. Any design where a slow
capture stalls event consumption loses the *next* event entirely — and the next
event may be the one that mattered.

Dropping in userspace is strictly better than back-pressuring the kernel ring
buffer, because a userspace drop is observable and attributable while a kernel
drop is a counter with no context.

**Consequence.** Under sustained overload the tool degrades by losing captures,
not by losing monitoring. Both losses are counted:
`flight_recorder_captures_dropped_total` and
`flight_recorder_ringbuf_lost_total`.

---

## ADR-009: Rate limits, size caps and a disk guard are mandatory, not optional

**Status:** Accepted

**Decision.** Global and per-container capture rate limits, a per-capture size
cap, and a disk usage guard, all enforced by default.

**Why.** An attacker who discovers the tool is running can execute trigger
commands in a loop. Each costs a memory read, a Merkle tree, a compression pass
and a disk write. Without caps that is an effective denial of service against
the node — and the tool would be doing exactly what it was configured to do
while causing it. A full node disk takes down every workload on the node, not
just this one.

A sliding window is used rather than a token bucket so the configured semantics
("no more than 10 captures in any 60 seconds") are checkable after the fact
from the audit log.

---

## ADR-010: Only metadata leaves the node

**Status:** Accepted

**Decision.** SIEM, SOAR and gRPC receive metadata, hashes and a URI. The
payload stays on the node (or in an object store the operator controls).

**Why.** Two independent reasons, either sufficient. Cost: forwarding
half-gigabyte dumps into a SIEM is ruinous. Data protection: the dump contains
credentials and personal data belonging to people who are not the subject of
the investigation, and a SIEM is the last place that should live.

---

## ADR-011: Payloads compressed then encrypted, in authenticated frames

**Status:** Accepted

**Decision.** zstd level 3, then AES-256-GCM in 1 MB frames. The Merkle tree is
built over the *uncompressed* bytes.

**Why in that order.** Encrypted data does not compress. Compressing first
gives 5–10× on typical memory dumps.

**Why frames.** A single-shot AEAD over 512 MB needs the whole ciphertext in
memory, on a DaemonSet with a memory limit. Frames also mean a damaged bundle
is partially recoverable: everything up to the corrupted frame still decrypts
and still verifies against its Merkle leaves.

**Why the tree covers plaintext.** Verification must reproduce the acquired
bytes. A tree over ciphertext would prove only that the ciphertext is intact,
which is not the claim being made.

**Known trade-off.** Compressing before encrypting is the CRIME/BREACH shape.
It is not exploitable here: there is no attacker-chosen plaintext mixed with a
secret, no adaptive oracle, and the output is a file at rest rather than a
stream an attacker can observe repeatedly.

---

## ADR-012: Kubernetes enrichment over plain HTTP, not client-go

**Status:** Accepted

**Decision.** Query the API server directly with the service account token, a
scoped `LIST` of pods on this node, refreshed in the background.

**Why.** client-go and its transitive dependencies are larger than the rest of
this tool. All that is needed is one scoped list. For a security tool, a
smaller dependency graph is a smaller attack surface and a smaller SBOM to
justify in procurement.

The list is scoped to one node deliberately: listing every pod in a large
cluster from every node is a well-known way to overload an API server.

**Consequence.** Enrichment is best-effort and cached. A capture never blocks
on an API round trip — by the time the API answers, the container may be gone.
Without enrichment, evidence still carries container ids.

---

## ADR-013: Published CASE 1.3.0 namespaces, not the design document's

**Status:** Accepted, deviating from the design documents

**Decision.** Emit `case-investigation:InvestigativeAction` and
`case-investigation:ProvenanceRecord`, not `case-core:*` as the internal design
documents specify. Tool-specific fields go under a documented `fr:` extension
namespace.

**Why.** In the published ontology those classes live in `case-investigation`.
Output that a CASE validator rejects is not interoperable, whatever an internal
document says, and interoperability is the entire reason for choosing CASE.

Extension via a documented namespace is the mechanism CASE prescribes.
Inventing terms inside `case-*` or `uco-*` would produce output that looks
conformant and is not.

---

## ADR-014: eBPF objects pinned to bpffs

**Status:** Accepted

**Decision.** Pin programs, maps and links to `/sys/fs/bpf/flight-recorder`. On
startup, re-attach to existing pinned links when present.

**Why.** eBPF programs are owned by the loading process's file descriptors. A
DaemonSet rolling update would otherwise unload them, leaving a monitoring gap
exactly as long as the pod restart — and an attacker who can trigger a restart
gets a scheduled blind spot.

**Consequence.** Objects survive process exit by design. `flight-recorder`
leaves them pinned on shutdown; removing monitoring entirely requires
unpinning.

---

## ADR-015: Generated eBPF artefacts are committed

**Status:** Accepted

**Decision.** `pkg/probe/recorder_bpfel.{go,o}` are in version control.

**Why.** `go build`, `go install` and `go test` all work with no clang, no
libbpf and no `make`. For a tool people are asked to evaluate quickly, that
matters more than the purity of not committing build output.

**How the risk is managed.** CI recompiles the object from source on every
change and runs the probe tests against the freshly generated bindings, so a
stale or divergent committed artefact fails the build.
