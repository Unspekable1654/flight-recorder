/* SPDX-License-Identifier: Apache-2.0 */
/*
 * common.h - structures shared between the eBPF kernel probes (bpf/recorder.c)
 * and the Go userspace decoder (pkg/probe/event.go).
 *
 * WIRE FORMAT CONTRACT
 * --------------------
 * The Go decoder parses these structures with encoding/binary in little-endian
 * order, field by field, in exactly the order declared here. The layout has been
 * chosen so that the C compiler inserts NO implicit padding on either amd64 or
 * arm64:
 *
 *   offset  size  field
 *   ------  ----  -----------------------------------------------
 *        0     4  kind
 *        4     4  host_pid
 *        8     4  ns_pid
 *       12     4  host_tgid
 *       16     4  uid
 *       20     4  ns_level
 *       24     4  args_len
 *       28     4  args_count
 *       32     8  cgroup_id
 *       40     8  timestamp_ns
 *       48    16  comm
 *       64   128  filename
 *      192   256  args
 *      ---------
 *      448 bytes total
 *
 * pkg/probe has a compile-time assertion (TestEventSizeMatchesKernelStruct)
 * that pins the Go struct size to FR_EVENT_SIZE below. If you change this
 * struct you MUST update both sides.
 */

#ifndef __FR_COMMON_H__
#define __FR_COMMON_H__

#define FR_TASK_COMM_LEN 16
#define FR_FILENAME_LEN 128
#define FR_ARGS_LEN 256
#define FR_ARG_CHUNK 64
#define FR_MAX_ARGS 4
#define FR_EVENT_SIZE 448

/* Event kinds. */
#define FR_EVENT_EXEC 1
#define FR_EVENT_EXIT 2

/*
 * fr_event is the record pushed through the BPF ring buffer for every
 * observed process lifecycle transition.
 */
struct fr_event {
	__u32 kind;         /* FR_EVENT_EXEC or FR_EVENT_EXIT                  */
	__u32 host_pid;     /* PID (thread id) as seen from the host namespace */
	__u32 ns_pid;       /* PID as seen from the innermost PID namespace    */
	__u32 host_tgid;    /* Thread group id (the "process") on the host     */
	__u32 uid;          /* Real UID of the calling task                    */
	__u32 ns_level;     /* PID namespace nesting depth (0 == host)         */
	__u32 args_len;     /* Bytes populated in args[]                       */
	__u32 args_count;   /* Number of argv entries copied into args[]       */
	__u64 cgroup_id;    /* cgroup v2 id, used for container resolution     */
	__u64 timestamp_ns; /* CLOCK_BOOTTIME nanoseconds (monotonic)          */
	__u8 comm[FR_TASK_COMM_LEN];
	__u8 filename[FR_FILENAME_LEN];
	__u8 args[FR_ARGS_LEN]; /* NUL-separated argv entries                  */
};

/*
 * fr_config is a single-entry array map written by userspace to control
 * kernel-side filtering without reloading the program.
 */
struct fr_config {
	__u32 self_tgid;   /* Flight Recorder's own tgid; its events are skipped */
	__u32 prefilter;   /* 1 = only submit execs whose comm is in trigger_comms */
	__u32 track_exits; /* 1 = also submit FR_EVENT_EXIT records              */
	__u32 min_uid;     /* Only submit events for uid >= min_uid (0 = all)    */
};

/* Statistics slots in the fr_stats array map. */
#define FR_STAT_EXEC_SEEN 0
#define FR_STAT_EXEC_SUBMITTED 1
#define FR_STAT_RINGBUF_DROPPED 2
#define FR_STAT_EXIT_SUBMITTED 3
#define FR_STAT_MAX 4

#endif /* __FR_COMMON_H__ */
