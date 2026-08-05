# Operational runbook

For the person who has to run this at 03:00.

---

## 1. Is this node actually being monitored?

The single most important question, and the one with a non-obvious answer: the
process can be perfectly healthy while the node is completely blind.

```bash
kubectl -n flight-recorder get pods -o wide
```

`Running` but **not** `Ready` means the eBPF programs did not attach. That node
is unmonitored. The readiness probe distinguishes the two states precisely so
this cannot pass unnoticed.

```bash
curl -s localhost:8080/readyz | jq
# {"status":"not ready","reason":"eBPF programs are not attached", ...}
```

**Alert on this.** The two rules worth paging on:

```yaml
- alert: FlightRecorderNodeUnmonitored
  expr: flight_recorder_ready == 0
  for: 5m
  annotations:
    summary: "Node {{ $labels.instance }} is not being monitored"

- alert: FlightRecorderLosingEvents
  expr: rate(flight_recorder_ringbuf_lost_total[5m]) > 0
  for: 10m
  annotations:
    summary: "Kernel ring buffer is dropping events on {{ $labels.instance }}"
```

---

## 2. Startup failures

| Message | Cause | Fix |
|---|---|---|
| `raise RLIMIT_MEMLOCK` | Pre-5.11 kernel, no `CAP_SYS_RESOURCE` | Add `SYS_RESOURCE` to the securityContext |
| `loading eBPF was denied` | Missing `CAP_BPF`/`CAP_PERFMON` | Add both; on kernels < 5.8 use `SYS_ADMIN` instead |
| `eBPF verifier rejected the program` | Kernel too old, or a local change to `recorder.c` | Read the full verifier log in the message; check kernel ≥ 5.8 |
| `open ring buffer reader` | `BPF_MAP_TYPE_RINGBUF` unsupported | Kernel ≥ 5.8 required |
| `attach tracepoint ...` | Tracepoint absent | `cat /sys/kernel/debug/tracing/available_events \| grep sys_enter_execve` |
| `is not on a bpffs mount` | `/sys/fs/bpf` not mounted | `mount -t bpf bpf /sys/fs/bpf`, or run with `--no-pin` |
| `running inside a PID namespace` | `hostPID: true` missing | Set it. Without it, host PIDs from eBPF are unresolvable |
| `signing key ... has permissions 0644` | Key too permissive | `chmod 600`; a readable key means forgeable evidence |

---

## 3. Nothing is being captured

Work down this list in order.

**a. Is the rule matching what the kernel actually sees?**

eBPF observes raw `execve` arguments. Shell built-ins, aliases and functions
never reach it. `cat /etc/shadow` typed at a prompt arrives as the argv of
`/usr/bin/cat`.

```bash
flight-recorder rules test --config triggers.yaml --cmdline "/usr/bin/cat /etc/shadow"
```

**b. Is the argv being truncated?** The probe copies at most four arguments of
64 bytes. A match that depends on the fifth argument will never fire. Match on
something earlier.

**c. Is the namespace filtered out?**

```bash
kubectl -n flight-recorder get cm flight-recorder-config -o yaml | grep -A5 namespace_filter
```

**d. Is the rate limiter closed?**

```
flight_recorder_captures_dropped_total{reason="global rate limit"}
flight_recorder_captures_dropped_total{reason="per-container rate limit"}
```

**e. Is the disk guard tripped?**

```
flight_recorder_captures_dropped_total{reason="evidence disk usage limit reached"}
flight_recorder_evidence_bytes
```

**f. Are events reaching userspace at all?** Run with `--dry-run --log-level
debug`: rules are evaluated and logged, and no memory is read.

---

## 4. Captures are failing

```bash
kubectl -n flight-recorder logs -l app.kubernetes.io/name=flight-recorder | grep -E "capture failed|target vanished"
```

| Log | Meaning | Action |
|---|---|---|
| `target vanished before acquisition` | The container died first | Expected for very short-lived pods. Compare `flight_recorder_trigger_latency_ms` against the pod's lifetime |
| `requires CAP_SYS_PTRACE` | Missing capability | Add `SYS_PTRACE` |
| `PID identity changed` | PID reused before acquisition | Working as intended: capturing the wrong process is worse than capturing nothing |
| `acquisition produced no readable memory` | Every region was unreadable | Usually a process that had already exec'd away; check `skipped_regions` in the log |
| `process_vm_readv returned EINVAL` | Internal bug | Please report it with the region range from the message |

Partial captures are normal. `EFAULT` on lazily allocated pages is expected and
recorded per region in `regions.json`; the receipt status will be `partial`.

---

## 5. Verifying evidence

```bash
# Triage first: no key required, reads nothing sensitive
flight-recorder inspect --bundle /var/lib/flight-recorder/evidence/<case-id>

# Full verification
flight-recorder verify --bundle /var/lib/flight-recorder/evidence/<case-id> --key key.pem

# Everything on this node
flight-recorder verify --all --root /var/lib/flight-recorder/evidence --key key.pem --json
```

Reading a failure:

| Failed check | Interpretation |
|---|---|
| `manifest file digests` | A file was modified or removed after the bundle was written |
| `payload sha256` | The payload changed; the acquired bytes are no longer what was sealed |
| `merkle root` | Content changed. Combined with a valid signature: the payload was edited, the receipt was not |
| `ecdsa signature` | The receipt was edited, or the wrong key was supplied |
| `signer key id` | Right structure, wrong key — check which node produced it |
| `CASE/UCO structure` | Metadata document is malformed or its Merkle root disagrees with the receipt |

Verification with only the public key still checks the manifest, the receipt
and the signature. It cannot check the payload, and says so.

---

## 6. Extracting the evidence

```bash
flight-recorder decrypt --bundle <dir> --key key.pem --out /secure/dump.bin
```

The output is raw process memory. It contains credentials, session tokens and
personal data belonging to people who are not the subject of the
investigation, and it inherits none of the bundle's protections. Write it to
encrypted storage, and delete it when finished.

Locate content within the dump using `regions.json`: each entry carries the
mapping's address range and its byte offset in the payload.

```bash
jq '.regions[] | {label, start_addr, dump_offset, bytes_read}' <dir>/regions.json
strings -t d /secure/dump.bin | grep -i "http\|password\|BEGIN.*PRIVATE"
```

---

## 7. Tuning

**CPU too high.** Check the mode first: `all` captures every execution. Then
check capture volume — `rate(flight_recorder_captures_total[5m])`. Idle
monitoring should sit under 2%; sustained higher usage means the rules are too
broad.

**Captures too slow.** `flight_recorder_capture_duration_ms` is end to end.
Split it: acquisition scales with resident memory,
`flight_recorder_seal_duration_ms` with dump size. `--include-file-backed`
multiplies dump size several-fold and is off by default for that reason.

**Ring buffer losses.** `flight_recorder_ringbuf_lost_total` increasing means
the kernel could not enqueue. Raise `--workers` so the consumer drains faster,
or enable `kernel_prefilter` with comm-scoped rules to reduce volume at source.

**Memory pressure / OOM kills.** The container limit must exceed
`max_dump_size_mb`: the dump is held in memory while it is sealed. The shipped
defaults are 512 MB cap against a 1 Gi limit. Lower the cap, or raise the
limit — never leave the cap above the limit.

**Disk filling.** Lower `retention_days` or `max_disk_usage_mb`, or ship
bundles to object storage and set `--evidence-uri-prefix`.

---

## 8. Changing rules without a restart

The ConfigMap is hot-reloaded. An invalid ruleset is rejected and the previous
one stays active.

```bash
# Always validate before applying
flight-recorder rules validate --config new-triggers.yaml

kubectl -n flight-recorder create configmap flight-recorder-config \
  --from-file=triggers.yaml=new-triggers.yaml \
  --dry-run=client -o yaml | kubectl apply -f -

# Confirm it was accepted, not rejected
kubectl -n flight-recorder logs -l app.kubernetes.io/name=flight-recorder --tail=20 | grep -i reload
```

`flight_recorder_config_reloads_total{result="failure"}` increasing means pods
are still running the old ruleset. `SIGHUP` forces a reload of the same file.

---

## 9. During an incident

```bash
# 1. Widen capture on the affected namespace (higher CPU, no missed executions)
kubectl -n flight-recorder patch cm flight-recorder-config --type merge -p \
  '{"data":{"triggers.yaml":"version: \"1\"\nmode: all\nmax_captures_per_minute: 60\n..."}}'

# 2. Raise the rate limits so the burst is not throttled away
#    (max_captures_per_minute, max_captures_per_container_per_minute)

# 3. Preserve what exists before retention or a disk guard removes it
kubectl -n flight-recorder exec <pod> -- tar czf - /var/lib/flight-recorder/evidence \
  > evidence-$(date +%Y%m%dT%H%M%SZ).tar.gz

# 4. Verify every bundle before anyone relies on it
flight-recorder verify --all --root ./evidence --key key.pem --json > verification.json
```

Restore `mode: trigger` afterwards.

---

## 10. Key management

```bash
flight-recorder keygen --key key.pem --pub pub.pem
kubectl -n flight-recorder create secret generic flight-recorder-signing-key --from-file=key.pem
```

- **Back the key up.** Evidence sealed with a lost key can never be verified or
  decrypted. There is no recovery path; that is what makes the seal meaningful.
- **Distribute only the public key** to examiners. It is enough to verify.
- **Rotating** does not invalidate old evidence, but the old key is still
  needed to verify and decrypt it. Retain retired keys for at least the
  evidence retention period.

---

## 11. The audit log

`/var/log/flight-recorder/audit.jsonl` records every privileged action: each
capture, drop, deletion, config reload and export attempt, fsynced before the
call returns.

```bash
# What did this tool actually do on this node today?
jq -r 'select(.action=="bundle_written") | "\(.time) \(.case_id) \(.rule) \(.pod_name) \(.bytes)"' audit.jsonl

# What did it decline to do, and why?
jq -r 'select(.action=="capture_dropped") | "\(.time) \(.reason) \(.cmdline)"' audit.jsonl

# What was deleted by retention?
jq -r 'select(.action=="bundle_deleted") | "\(.time) \(.case_id) \(.reason)"' audit.jsonl
```

When the tool itself comes under scrutiny — and a process holding
`CAP_SYS_PTRACE` on every node eventually will — this file is the answer.

---

## 12. Uninstalling cleanly

```bash
kubectl delete -f deploy/k8s/daemonset.yaml

# eBPF objects are pinned and survive pod deletion by design. Remove them:
kubectl debug node/<node> -it --image=busybox -- rm -rf /host/sys/fs/bpf/flight-recorder

# Evidence and the audit log are host paths and are NOT removed automatically.
# Deliberate: uninstalling a tool must not destroy the evidence it collected.
```
