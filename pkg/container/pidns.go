package container

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// NamespacePID returns the PID of a process as observed inside its innermost
// PID namespace, along with the namespace nesting level.
//
// This is the userspace counterpart to the CO-RE walk performed in
// bpf/recorder.c. It exists for three reasons: as a cross-check on the kernel
// value, as the fallback on kernels where the BTF walk fails, and because
// resolution of an already-observed PID sometimes happens after the fact.
//
// The kernel exposes the mapping in /proc/[pid]/status:
//
//	NSpid:	48291	42	1
//
// Fields are ordered outermost (host) to innermost (container). A single field
// means the process is in the host namespace.
func NamespacePID(procRoot string, pid int) (nsPID, level int, err error) {
	pids, err := NSPidChain(procRoot, pid)
	if err != nil {
		return 0, 0, err
	}
	if len(pids) == 0 {
		return 0, 0, fmt.Errorf("container: no NSpid entry for pid %d", pid)
	}
	return pids[len(pids)-1], len(pids) - 1, nil
}

// NSPidChain returns the full outermost-to-innermost PID chain for a process.
func NSPidChain(procRoot string, pid int) ([]int, error) {
	raw, err := os.ReadFile(procPath(procRoot, pid, "status"))
	if err != nil {
		return nil, fmt.Errorf("container: read status for pid %d: %w", pid, err)
	}
	return ParseNSPid(string(raw))
}

// ParseNSPid extracts the NSpid chain from the contents of
// /proc/[pid]/status.
//
// Kernels built without CONFIG_PID_NS omit the line entirely; that is not an
// error, and the caller receives the host PID chain via the Pid: line instead.
func ParseNSPid(status string) ([]int, error) {
	var hostPID int
	for _, line := range strings.Split(status, "\n") {
		switch {
		case strings.HasPrefix(line, "NSpid:"):
			fields := strings.Fields(strings.TrimPrefix(line, "NSpid:"))
			pids := make([]int, 0, len(fields))
			for _, f := range fields {
				v, err := strconv.Atoi(f)
				if err != nil {
					return nil, fmt.Errorf("container: malformed NSpid entry %q: %w", f, err)
				}
				pids = append(pids, v)
			}
			if len(pids) == 0 {
				return nil, fmt.Errorf("container: empty NSpid line")
			}
			return pids, nil

		case strings.HasPrefix(line, "Pid:"):
			f := strings.Fields(strings.TrimPrefix(line, "Pid:"))
			if len(f) > 0 {
				if v, err := strconv.Atoi(f[0]); err == nil {
					hostPID = v
				}
			}
		}
	}

	if hostPID != 0 {
		return []int{hostPID}, nil
	}
	return nil, fmt.Errorf("container: status has neither NSpid nor Pid")
}

// NamespaceIDs identifies the kernel namespaces a process belongs to. Two
// processes sharing a pid namespace inode are in the same container, which is
// a cheap correlation key that does not depend on any runtime's conventions.
type NamespaceIDs struct {
	PID    uint64 `json:"pid_ns"`
	Mount  uint64 `json:"mnt_ns"`
	Net    uint64 `json:"net_ns"`
	UTS    uint64 `json:"uts_ns"`
	IPC    uint64 `json:"ipc_ns"`
	Cgroup uint64 `json:"cgroup_ns"`
	User   uint64 `json:"user_ns"`
}

// ReadNamespaceIDs reads the namespace inode numbers for a process.
//
// /proc/[pid]/ns/* are symlinks of the form "pid:[4026532278]". Missing
// entries are left as zero rather than failing: an unprivileged reader may not
// see all of them, and partial namespace data is still useful for correlation.
func ReadNamespaceIDs(procRoot string, pid int) (NamespaceIDs, error) {
	var ids NamespaceIDs
	targets := map[string]*uint64{
		"pid":    &ids.PID,
		"mnt":    &ids.Mount,
		"net":    &ids.Net,
		"uts":    &ids.UTS,
		"ipc":    &ids.IPC,
		"cgroup": &ids.Cgroup,
		"user":   &ids.User,
	}

	found := false
	for name, dst := range targets {
		link, err := os.Readlink(procPath(procRoot, pid, "ns/"+name))
		if err != nil {
			continue
		}
		if v, ok := parseNSLink(link); ok {
			*dst = v
			found = true
		}
	}

	if !found {
		return ids, fmt.Errorf("container: no readable namespace links for pid %d", pid)
	}
	return ids, nil
}

// InHostPIDNamespace reports whether this process shares the PID namespace of
// PID 1 in the given procfs.
//
// This matters more than it looks. eBPF reports PIDs as numbered in the host
// namespace; if the recorder runs without hostPID: true, those numbers are
// meaningless to it and every capture fails with "process does not exist".
// Detecting the condition at startup turns a mystifying runtime failure into a
// deployment error the operator can fix.
func InHostPIDNamespace(procRoot string) (bool, error) {
	self, err := os.Readlink(procPath(procRoot, os.Getpid(), "ns/pid"))
	if err != nil {
		// /proc/self/ns is not always readable; treat unknown as "assume host"
		// rather than refusing to run.
		return true, fmt.Errorf("container: read own pid namespace: %w", err)
	}

	init, err := os.Readlink(procPath(procRoot, 1, "ns/pid"))
	if err != nil {
		return true, fmt.Errorf("container: read init pid namespace: %w", err)
	}

	return self == init, nil
}

func parseNSLink(link string) (uint64, bool) {
	open := strings.IndexByte(link, '[')
	closeIdx := strings.IndexByte(link, ']')
	if open < 0 || closeIdx <= open+1 {
		return 0, false
	}
	v, err := strconv.ParseUint(link[open+1:closeIdx], 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
