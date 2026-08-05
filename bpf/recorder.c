// SPDX-License-Identifier: Apache-2.0
//
// recorder.c - Flight Recorder kernel probes.
//
// Two programs are loaded:
//
//   1. tracepoint/syscalls/sys_enter_execve  - the primary trigger. Every
//      process creation is observed here, before the new image runs, so the
//      argv of the *incoming* program is still readable from user memory.
//
//   2. tracepoint/sched/sched_process_exit   - lifecycle bookkeeping. The
//      userspace pipeline uses exit records to distinguish "we were too slow"
//      from "the process was never there", which is the single most useful
//      datum when characterising the ephemeral-capture race window.
//
// The code is CO-RE: it includes a vendored vmlinux.h generated from kernel
// BTF and reads kernel structures exclusively through bpf_core_read(), so a
// single object file relocates correctly across kernel versions without
// depending on kernel headers at runtime.

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "headers/common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// events is the ring buffer carrying fr_event records to userspace.
// 16 MB is sized so that a burst of ~37k events can queue while the Go
// consumer is blocked on a slow capture.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

// fr_config_map holds a single fr_config record, updated at runtime by userspace.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct fr_config);
} fr_config_map SEC(".maps");

// trigger_comms is the optional kernel-side prefilter. Keys are 16-byte
// task comm values; presence means "submit this exec". Userspace still runs
// the full rule engine (regex over the complete command line) - this map only
// exists to keep ring buffer pressure down on very busy nodes.
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u8[FR_TASK_COMM_LEN]);
	__type(value, __u8);
} trigger_comms SEC(".maps");

// stats exposes kernel-side counters that have no other way of reaching
// userspace (most importantly: ring buffer reservation failures).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, FR_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static __always_inline void bump(__u32 slot)
{
	__u64 *val = bpf_map_lookup_elem(&stats, &slot);
	if (val)
		__sync_fetch_and_add(val, 1);
}

static __always_inline struct fr_config *get_config(void)
{
	__u32 key = 0;
	return bpf_map_lookup_elem(&fr_config_map, &key);
}

// fill_ns_pid resolves the PID as observed inside the task's own PID
// namespace.
//
// bpf_get_ns_current_pid_tgid() is deliberately NOT used here: that helper
// answers "what is my PID inside the namespace identified by (dev, ino)",
// which requires knowing the target container's namespace before the event
// happens. During monitoring we do not - every container has a different one.
//
// Instead we walk the task_struct with CO-RE:
//
//   task->nsproxy->pid_ns_for_children->level  -> nesting depth
//   task->thread_pid->numbers[level].nr        -> pid at that depth
//
// numbers[] is a flexible array member, so the index cannot be a constant in
// BPF_CORE_READ(). We take the CO-RE-relocated offset of the array and do the
// indexing ourselves; the read itself is a normal probe read of kernel memory,
// which the verifier permits with a runtime index.
static __always_inline void fill_ns_pid(struct fr_event *e)
{
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	if (!task)
		return;

	unsigned int level = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, level);
	if (level > 8)
		level = 0;

	struct pid *thread_pid = BPF_CORE_READ(task, thread_pid);
	if (!thread_pid) {
		e->ns_pid = e->host_pid;
		e->ns_level = 0;
		return;
	}

	__u32 numbers_off = bpf_core_field_offset(struct pid, numbers);
	struct upid *upids = (struct upid *)((__u8 *)thread_pid + numbers_off);

	__u32 nr = 0;
	if (bpf_core_read(&nr, sizeof(nr), &upids[level].nr) != 0 || nr == 0) {
		e->ns_pid = e->host_pid;
		e->ns_level = 0;
		return;
	}

	e->ns_pid = nr;
	e->ns_level = level;
}

// copy_args walks the userspace argv array and packs up to FR_MAX_ARGS
// NUL-separated entries into e->args.
//
// Verifier notes: the destination offset is masked to the buffer size AND
// explicitly bounded before every write, which is what lets the verifier
// prove the variable-offset store into ring buffer memory is in range.
static __always_inline void copy_args(struct fr_event *e, const char *const *argv)
{
	__u32 off = 0;
	__u32 count = 0;

#pragma unroll
	for (int i = 0; i < FR_MAX_ARGS; i++) {
		const char *argp = NULL;

		if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) != 0)
			break;
		if (!argp)
			break;

		off &= (FR_ARGS_LEN - 1);
		if (off > FR_ARGS_LEN - FR_ARG_CHUNK)
			break;

		long n = bpf_probe_read_user_str(&e->args[off], FR_ARG_CHUNK, argp);
		if (n <= 0)
			break;

		off += (__u32)n; // includes the trailing NUL, which is our separator
		count++;
	}

	e->args_len = off & (FR_ARGS_LEN - 1);
	e->args_count = count;
}

static __always_inline int should_submit(struct fr_config *cfg, struct fr_event *e)
{
	if (!cfg)
		return 1;

	if (cfg->self_tgid != 0 && e->host_tgid == cfg->self_tgid)
		return 0;
	if (cfg->min_uid != 0 && e->uid < cfg->min_uid)
		return 0;

	if (cfg->prefilter) {
		__u8 key[FR_TASK_COMM_LEN];
		__builtin_memcpy(key, e->comm, FR_TASK_COMM_LEN);
		if (!bpf_map_lookup_elem(&trigger_comms, key))
			return 0;
	}

	return 1;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int fr_trace_execve(struct trace_event_raw_sys_enter *ctx)
{
	bump(FR_STAT_EXEC_SEEN);

	struct fr_config *cfg = get_config();

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 host_pid = (__u32)pid_tgid;
	__u32 host_tgid = (__u32)(pid_tgid >> 32);

	// Reserve first, populate in place: this avoids a 448-byte stack copy,
	// which matters because the BPF stack is only 512 bytes.
	struct fr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump(FR_STAT_RINGBUF_DROPPED);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));

	e->kind = FR_EVENT_EXEC;
	e->host_pid = host_pid;
	e->host_tgid = host_tgid;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->timestamp_ns = bpf_ktime_get_boot_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));

	if (!should_submit(cfg, e)) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}

	fill_ns_pid(e);

	const char *filename = (const char *)BPF_CORE_READ(ctx, args[0]);
	if (filename)
		bpf_probe_read_user_str(&e->filename, sizeof(e->filename), filename);

	const char *const *argv = (const char *const *)BPF_CORE_READ(ctx, args[1]);
	if (argv)
		copy_args(e, argv);

	bpf_ringbuf_submit(e, 0);
	bump(FR_STAT_EXEC_SUBMITTED);
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int fr_trace_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct fr_config *cfg = get_config();
	if (!cfg || !cfg->track_exits)
		return 0;

	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u32 host_pid = (__u32)pid_tgid;
	__u32 host_tgid = (__u32)(pid_tgid >> 32);

	// Only thread group leaders: a thread exiting is not a process dying.
	if (host_pid != host_tgid)
		return 0;

	if (cfg->self_tgid != 0 && host_tgid == cfg->self_tgid)
		return 0;

	struct fr_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		bump(FR_STAT_RINGBUF_DROPPED);
		return 0;
	}

	__builtin_memset(e, 0, sizeof(*e));

	e->kind = FR_EVENT_EXIT;
	e->host_pid = host_pid;
	e->host_tgid = host_tgid;
	e->uid = (__u32)bpf_get_current_uid_gid();
	e->cgroup_id = bpf_get_current_cgroup_id();
	e->timestamp_ns = bpf_ktime_get_boot_ns();
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	fill_ns_pid(e);

	bpf_ringbuf_submit(e, 0);
	bump(FR_STAT_EXIT_SUBMITTED);
	return 0;
}
