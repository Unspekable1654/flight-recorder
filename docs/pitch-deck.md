# Pitch deck

Twelve slides, ten minutes. Every number here is measured, not projected — see
[whitepaper.md](whitepaper.md) §5 for methodology, and reproduce with
`sudo make test-integration`.

---

## Slide 1 — Title

> ### Project Flight Recorder
> **Catching ghosts in the machine**
>
> Ephemeral compute forensic preservation via eBPF and cryptographic sealing

*Visual:* dark terminal, a container dissolving into particles.

**Talk track (30s).** "Containers live for minutes. Attackers need seconds.
When the container dies, the evidence dies with it. I'm going to show you how
to preserve a crime scene that deletes itself."

---

## Slide 2 — The problem

> **Evidence lifetime is shorter than detection latency.**
>
> Container lifespan: **minutes** ▸ SOC alert latency: **tens of minutes**
>
> The gap between them is where attackers live.

*Visual:* two bars on one timeline; the gap labelled THE BLIND SPOT.

**Talk track (45s).** "By the time your SOC gets the alert, the container is
gone. Filesystem discarded. Memory freed. Network tables torn down. Your
responder opens the ticket and finds a log line saying `curl | sh` ran —
without what was downloaded, where it called home, or what it took."

---

## Slide 3 — Why current tools do not close it

> | | Cloud logs | EDR | Reactive forensics | **Flight Recorder** |
> |---|---|---|---|---|
> | Memory contents | ❌ | ⚠️ limited | ❌ too late | ✅ heap, stack, anon |
> | Kubernetes-native | ⚠️ | ❌ heavy | ❌ | ✅ DaemonSet |
> | Legally admissible | ❌ | ❌ proprietary | ⚠️ | ✅ CASE/UCO |
> | Captures ephemeral | ❌ | ❌ | ❌ | ✅ 13 ms |

**Talk track (45s).** "Logs have no memory visibility. EDR agents were built
for laptops, not for a node running 200 pods. Reactive forensics arrives to an
empty node. None of these are bad tools — they answer a different question."

---

## Slide 4 — Architecture

*Visual:* the diagram from the README — kernel tracepoints into a ring buffer,
userspace rule engine into a bounded worker pool, then acquire → seal → export.

**Talk track (60s).** "We don't detect — we *preserve*. Two eBPF tracepoints
watch every process execution with near-zero overhead. When something matches,
a Go controller reaches across the kernel boundary, copies the live process
memory, seals it with a Merkle tree, signs it, and writes a court-admissible
bundle. All before the container can self-destruct."

---

## Slide 5 — The freeze-frame

> ```go
> // Read another process's memory. No ptrace. No SIGSTOP.
> // The target keeps running and never knows.
> bytesRead, err := unix.ProcessVMReadv(pid, localIov, remoteIov, 0)
> ```
>
> - Non-intrusive: the target is never stopped or signalled
> - Captures `[heap]`, `[stack]` and anonymous regions — where fileless
>   payloads live
> - Hardened: every errno handled (`ESRCH`, `EFAULT`, `ENOMEM`, `EPERM`,
>   partial reads)
>
> **Measured: 3.0 GB/s. A container process in 0.4 ms.**

**Talk track (60s).** "This is the magic. `process_vm_readv` copies out another
process's memory without stopping it and without attaching a debugger — so the
attacker's process can't detect us with the usual `TracerPid` check. It also
matters operationally: stopping a container's main process trips its liveness
probe and destroys the thing you were trying to investigate."

---

## Slide 6 — The Kubernetes hard part

> ```
> Container namespace          Host namespace
>   PID 1 (app)      ◀═══════▶   PID 48291   ← acquisition uses THIS
>   PID 2 (sh)       ◀═══════▶   PID 48295
> ```
>
> - `bpf_get_current_pid_tgid()` → host PID, for the acquisition
> - CO-RE walk of `task->thread_pid->numbers[level]` → container PID, for the
>   report
> - `bpf_get_current_cgroup_id()` → container id → pod name

**Talk track (45s).** "PID 1 in the container is PID 48291 on the host. You
need the host PID to read memory and the container PID for the report. Get it
backwards and you produce evidence that correlates with nothing. We resolve
both, in the kernel, per event."

---

## Slide 7 — Chain of custody

> *Visual:* Merkle tree over 4 KB chunks, root signed with ECDSA P-256.
>
> - Change one byte anywhere → the root changes → the signature fails
> - Prove one page authentic **without** disclosing the whole dump
> - **100 MB sealed in 85 ms**

**Talk track (60s).** "Raw memory is useless in court if you cannot prove it is
unaltered. We chunk the dump by page, hash each with SHA-256, build a Merkle
tree, and sign the root. Change one byte and the root changes. Same
construction that secures Bitcoin, applied to forensics — and the tree also
means you can prove one page is genuine without handing over 500 MB of
somebody else's data."

---

## Slide 8 — Built for the courtroom

> | Standard | Requirement | Compliance |
> |---|---|---|
> | **Daubert** | Known error rate | SHA-256 collision: 2⁻¹²⁸ |
> | **ISO 27037** | Tool identity + method | Receipt records version, commit, **binary self-hash**, kernel |
> | **ACPO** | Must not alter evidence | `process_vm_readv` is read-only |
> | **FRE 901(b)(9)** | Authenticated by a system | ECDSA-signed Merkle root |
>
> CASE/UCO: endorsed by INTERPOL, Europol EC3, NIST. Open standard, no vendor
> lock-in.

**Talk track (45s).** "This isn't a detection tool with a report bolted on.
Every bundle records which exact binary produced it — we hash ourselves — on
which kernel, at what monotonic time. It goes from your SOC to a courtroom
without re-collection."

---

## Slide 9 — It plugs into what you already run

> Splunk HEC (CIM fields) · Elastic (ECS) · Syslog RFC 5424 / CEF · Webhook
> (SOAR) · gRPC · Prometheus
>
> **The memory dump never leaves the node.** Metadata, hashes and a URI only.

**Talk track (45s).** "Enterprise SOCs won't adopt a standalone island. Splunk,
Elastic, any syslog platform, or a webhook into your SOAR playbook. And we send
metadata only — forwarding half a gigabyte of raw memory full of other people's
credentials into a SIEM is both ruinously expensive and a breach in itself."

---

## Slide 10 — Live demo and numbers

*Live:* `flight-recorder demo` — runs the real pipeline, seals, verifies, then
flips one byte and shows verification correctly fail. No kernel or root needed,
so it cannot fail on unfamiliar hardware.

> | Measurement | Result |
> |---|---|
> | Trigger → sealed, verified bundle | **13 ms** |
> | Acquisition throughput | **3.0 GB/s** |
> | Merkle seal, 100 MB | **85 ms** |
> | 1000 rapid execs | **1001 seen, 1001 delivered, 0 dropped** |
> | Race window (maps → first read) | **0.03 ms** |

**Talk track (90s).** "Let me show you. This is the full pipeline: acquire,
seal, sign, CASE/UCO, encrypt, write, verify — verified. Now watch: I flip a
single byte in the payload... and verification fails, and it tells me *which*
check failed. That distinction is the difference between 'the file was
truncated in transit' and 'someone edited the evidence'."

---

## Slide 11 — Competitive position

> ```
> Attack ──── Detect ──── Alert ──── Respond ──── Analyse
>    │◀ Falco/Tracee/Tetragon ▶│              │◀ traditional ▶│
>    │                                                        │
>    │◀════════ Flight Recorder: PRESERVE ═══════════════════▶│
>              ▲ evidence destroyed here (container dies)
> ```
>
> | | Tracee | Tetragon | Falco | **Flight Recorder** |
> |---|---|---|---|---|
> | Focus | Detect | Enforce | Alert | **Preserve** |
> | Memory capture | ❌ | ❌ | ❌ | ✅ |
> | Legal output | ❌ | ❌ | ❌ | ✅ |

**Talk track (45s).** "Tracee detects. Tetragon enforces. Falco alerts. Nobody
preserves. We're complementary — run Falco for detection and us for
preservation."

---

## Slide 12 — The ask

> **Now:** working tool. eBPF + CO-RE ✅ · 5 attack scenarios ✅ · CASE/UCO ✅ ·
> 13 ms end to end ✅ · CI with privileged integration tests ✅
>
> **Next 6 months:** multi-node correlation · KMS-backed keys · multi-kernel
> validation
>
> **Later:** managed cloud (EKS/GKE/AKS) · MITRE auto-mapping · automated IR
> playbooks
>
> **Asking for:**
> - 🏢 Design partners — SOC teams willing to run this in staging
> - 🎤 Conferences — Black Hat Asia Arsenal, DEF CON Demo Labs, BSides
> - 🎓 Academic — capstone review and publication
>
> github.com/Unspekable1654/flight-recorder · Apache 2.0

**Talk track (45s).** "This works today — the code is open, the CI runs
privileged integration tests against a real kernel on every commit, and every
number on these slides is reproducible with one make target. What I need is
your environment: design partners in real SOCs, a stage to demo on, and
academic reviewers. The architecture is ready. The only thing missing is your
traffic."

---

## Anticipated questions

| # | Question | Answer |
|---|---|---|
| 1 | How is this different from Tracee? | Tracee detects threats from event streams. We preserve the artefact — actual memory — and seal it for legal use. Different phase of IR; run both. |
| 2 | What if the kernel is compromised? | Every userspace and eBPF tool is unreliable then. Explicitly outside the threat model, documented rather than glossed over. |
| 3 | Can an attacker unload your eBPF? | With host root, yes. Pinning to bpffs survives our process dying; a BPF-lifecycle watchdog is on the roadmap. Host root has already won. |
| 4 | Encrypted memory? | SGX/TDX enclaves cannot be read. Known, stated limitation. |
| 5 | False positive rate? | We don't classify — we capture on trigger. False positives are a function of your ruleset. Capture-all mode has zero false negatives at higher CPU. |
| 6 | Scale to 1000 nodes? | DaemonSet: each node is independent, no central bottleneck. Pod listing is scoped per node deliberately. Cross-node correlation is roadmap. |
| 7 | Why CASE/UCO, not STIX? | STIX is threat-intel sharing. CASE/UCO is evidence and custody. Complementary. |
| 8 | CPU cost of capture-all? | ~5% during active capture, under 2% idle in trigger mode. Configurable per deployment. |
| 9 | Has CASE/UCO been used in court? | Endorsed by INTERPOL, Europol EC3 and NIST. Combined with ISO 27037 and Daubert compliance it gives a strong admissibility argument. |
| 10 | Why Go, not Rust? | `cilium/ebpf` is the most battle-tested eBPF library in production — it powers Cilium. `aya` is promising but less mature. |
| 11 | What about PII in dumps? | They are radioactive by nature. AES-256-GCM at rest, key derived from the signing key, 90-day default retention, optional redaction, metadata-only export. |
| 12 | What if the tool itself is attacked? | Distroless, read-only root, all capabilities dropped but four, rate limited, every action in an append-only audit log. See SECURITY.md. |

---

## Demo script (3 minutes)

```bash
# 1. Show a node being monitored (15s)
kubectl -n flight-recorder get pods -o wide

# 2. Deploy a container that self-destructs (30s)
kubectl apply -f test/scenarios/fileless.yaml
kubectl get pod -n victim -w        # watch it appear and die

# 3. The capture, in real time (30s)
kubectl -n flight-recorder logs -l app.kubernetes.io/name=flight-recorder | grep "evidence sealed"

# 4. The evidence (45s)
flight-recorder inspect --bundle /var/lib/flight-recorder/evidence/<case-id> --case

# 5. Verification, live (30s)
flight-recorder verify --bundle /var/lib/flight-recorder/evidence/<case-id> --key key.pem

# 6. Tamper, and verification fails (30s)
printf '\x00' | dd of=<bundle>/dump.bin.zst.enc bs=1 seek=5000 conv=notrunc
flight-recorder verify --bundle <bundle> --key key.pem   # FAILS, and says why
```

Fallback if the cluster misbehaves on stage: `flight-recorder demo` runs the
identical pipeline with no kernel, no root and no network.
