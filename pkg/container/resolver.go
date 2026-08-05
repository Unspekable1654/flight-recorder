// Package container maps a raw kernel event onto the workload that produced it.
//
// An eBPF event carries a host PID and a cgroup id. Neither means anything to
// an incident responder. This package turns them into a container id, a
// Kubernetes pod, and the PID as it appears inside the container - the three
// identifiers an examiner actually correlates against.
//
// All resolution happens in userspace. The eBPF program deliberately does not
// attempt it: walking cgroup paths and querying the Kubernetes API from a
// kernel probe is neither possible nor desirable.
package container

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Runtime identifies the container runtime that created a cgroup.
type Runtime string

// Recognised runtimes.
const (
	RuntimeContainerd Runtime = "containerd"
	RuntimeCRIO       Runtime = "cri-o"
	RuntimeDocker     Runtime = "docker"
	RuntimeUnknown    Runtime = "unknown"
	RuntimeHost       Runtime = "host"
)

// Info describes the workload behind an event.
type Info struct {
	ContainerID  string  `json:"container_id"`
	ShortID      string  `json:"short_id"`
	PodName      string  `json:"pod_name"`
	PodNamespace string  `json:"pod_namespace"`
	PodUID       string  `json:"pod_uid"`
	QoSClass     string  `json:"qos_class"`
	Runtime      Runtime `json:"runtime"`
	HostPID      int     `json:"host_pid"`
	NamespacePID int     `json:"namespace_pid"`
	NSLevel      int     `json:"ns_level"`
	CgroupPath   string  `json:"cgroup_path"`
	CgroupID     uint64  `json:"cgroup_id"`
	NodeName     string  `json:"node_name"`
	// Enriched is true when Kubernetes API metadata (pod name/namespace) was
	// obtained rather than inferred.
	Enriched bool `json:"enriched"`
}

// InContainer reports whether the event came from a container rather than from
// a host process.
func (i *Info) InContainer() bool { return i.ContainerID != "" }

// Describe returns a compact identifier for logs.
func (i *Info) Describe() string {
	switch {
	case i.PodName != "":
		return fmt.Sprintf("%s/%s (%s)", i.PodNamespace, i.PodName, i.ShortID)
	case i.ContainerID != "":
		return fmt.Sprintf("container %s", i.ShortID)
	default:
		return fmt.Sprintf("host pid %d", i.HostPID)
	}
}

// Resolver turns kernel identifiers into workload metadata.
//
// Resolution results are cached by cgroup id: a busy pod produces thousands of
// events for the same container, and re-reading procfs for each one is pure
// waste. Entries expire so that a recycled cgroup id cannot serve stale
// metadata.
type Resolver struct {
	procRoot string
	nodeName string
	enricher PodEnricher

	mu    sync.RWMutex
	cache map[uint64]cacheEntry
	ttl   time.Duration
}

type cacheEntry struct {
	info     Info
	cachedAt time.Time
}

// PodEnricher supplies Kubernetes metadata for a pod UID. It is an interface so
// that the resolver can run without any Kubernetes connectivity at all, which
// is the case in the standalone and test configurations.
type PodEnricher interface {
	LookupPodByUID(uid string) (PodMeta, bool)
	LookupPodByContainerID(containerID string) (PodMeta, bool)
}

// PodMeta is the subset of pod metadata recorded in evidence.
type PodMeta struct {
	Name      string
	Namespace string
	UID       string
	NodeName  string
}

// ResolverOption configures a Resolver.
type ResolverOption func(*Resolver)

// WithProcRoot points the resolver at an alternative procfs mount.
func WithProcRoot(root string) ResolverOption {
	return func(r *Resolver) { r.procRoot = root }
}

// WithNodeName records the Kubernetes node name in resolved metadata.
func WithNodeName(name string) ResolverOption {
	return func(r *Resolver) { r.nodeName = name }
}

// WithEnricher attaches a Kubernetes metadata source.
func WithEnricher(e PodEnricher) ResolverOption {
	return func(r *Resolver) { r.enricher = e }
}

// WithCacheTTL overrides the resolution cache lifetime.
func WithCacheTTL(ttl time.Duration) ResolverOption {
	return func(r *Resolver) { r.ttl = ttl }
}

// NewResolver builds a resolver.
func NewResolver(opts ...ResolverOption) *Resolver {
	r := &Resolver{
		procRoot: "/proc",
		cache:    make(map[uint64]cacheEntry),
		ttl:      2 * time.Minute,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Resolve maps a cgroup id and host PID onto workload metadata.
//
// The host PID is what process_vm_readv must be given; the namespace PID is
// what the forensic record must report. Confusing the two is the single most
// common way an eBPF tool in Kubernetes produces evidence that correlates with
// nothing.
func (r *Resolver) Resolve(cgroupID uint64, hostPID int) (*Info, error) {
	if cgroupID != 0 {
		r.mu.RLock()
		entry, ok := r.cache[cgroupID]
		r.mu.RUnlock()
		if ok && time.Since(entry.cachedAt) < r.ttl {
			info := entry.info
			info.HostPID = hostPID
			// The namespace PID is per-process, never cached.
			if ns, level, err := NamespacePID(r.procRoot, hostPID); err == nil {
				info.NamespacePID, info.NSLevel = ns, level
			}
			return &info, nil
		}
	}

	info := Info{
		HostPID:  hostPID,
		CgroupID: cgroupID,
		Runtime:  RuntimeHost,
		NodeName: r.nodeName,
	}

	cgroupPath, err := ReadCgroupPath(r.procRoot, hostPID)
	if err != nil {
		// A process that exited before resolution is the common case, not an
		// exceptional one. Return what we know instead of failing the capture.
		if os.IsNotExist(err) {
			return &info, nil
		}
		return &info, err
	}
	info.CgroupPath = cgroupPath

	parsed := ParseCgroupPath(cgroupPath)
	info.ContainerID = parsed.ContainerID
	info.ShortID = shortID(parsed.ContainerID)
	info.PodUID = parsed.PodUID
	info.QoSClass = parsed.QoSClass
	if parsed.Runtime != RuntimeUnknown {
		info.Runtime = parsed.Runtime
	}

	if ns, level, err := NamespacePID(r.procRoot, hostPID); err == nil {
		info.NamespacePID, info.NSLevel = ns, level
	}

	if r.enricher != nil {
		if meta, ok := r.lookupPod(parsed); ok {
			info.PodName = meta.Name
			info.PodNamespace = meta.Namespace
			if info.PodUID == "" {
				info.PodUID = meta.UID
			}
			if meta.NodeName != "" {
				info.NodeName = meta.NodeName
			}
			info.Enriched = true
		}
	}

	if cgroupID != 0 && info.ContainerID != "" {
		r.mu.Lock()
		r.cache[cgroupID] = cacheEntry{info: info, cachedAt: time.Now()}
		r.mu.Unlock()
	}

	return &info, nil
}

func (r *Resolver) lookupPod(parsed CgroupInfo) (PodMeta, bool) {
	if parsed.PodUID != "" {
		if meta, ok := r.enricher.LookupPodByUID(parsed.PodUID); ok {
			return meta, true
		}
	}
	if parsed.ContainerID != "" {
		if meta, ok := r.enricher.LookupPodByContainerID(parsed.ContainerID); ok {
			return meta, true
		}
	}
	return PodMeta{}, false
}

// Purge drops cache entries older than the TTL. Called periodically by the
// pipeline so that a long-running recorder does not accumulate metadata for
// containers that no longer exist.
func (r *Resolver) Purge() int {
	r.mu.Lock()
	defer r.mu.Unlock()

	removed := 0
	for k, v := range r.cache {
		if time.Since(v.cachedAt) >= r.ttl {
			delete(r.cache, k)
			removed++
		}
	}
	return removed
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// CgroupInfo is what can be derived from a cgroup path alone.
type CgroupInfo struct {
	ContainerID string
	PodUID      string
	QoSClass    string
	Runtime     Runtime
}

var (
	// 64-character hex container ids, optionally prefixed by the runtime.
	containerIDRe = regexp.MustCompile(`(?:^|[-/:])(?:docker-|crio-|containerd-|cri-containerd-)?([0-9a-f]{64})(?:\.scope)?$`)
	// Pod UID in either dashed or underscored form, as written by kubelet.
	podUIDRe = regexp.MustCompile(`pod([0-9a-fA-F]{8}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{4}[-_][0-9a-fA-F]{12})`)
	qosRe    = regexp.MustCompile(`(?i)(besteffort|burstable|guaranteed)`)
)

// ParseCgroupPath extracts container identity from a cgroup path.
//
// The layouts differ per runtime and per cgroup driver, and all of these occur
// in the wild:
//
//	containerd + systemd driver:
//	  /kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod<uid>.slice/cri-containerd-<id>.scope
//	containerd + cgroupfs driver:
//	  /kubepods/burstable/pod<uid>/<id>
//	cri-o:
//	  /kubepods.slice/.../crio-<id>.scope
//	plain docker:
//	  /docker/<id>
func ParseCgroupPath(path string) CgroupInfo {
	info := CgroupInfo{Runtime: RuntimeUnknown}
	if path == "" {
		return info
	}

	switch {
	case strings.Contains(path, "crio-"):
		info.Runtime = RuntimeCRIO
	case strings.Contains(path, "containerd-"):
		info.Runtime = RuntimeContainerd
	case strings.Contains(path, "docker"):
		info.Runtime = RuntimeDocker
	case strings.Contains(path, "kubepods"):
		// kubelet default runtime when no prefix is present.
		info.Runtime = RuntimeContainerd
	}

	segments := strings.Split(strings.Trim(path, "/"), "/")
	for i := len(segments) - 1; i >= 0; i-- {
		seg := strings.TrimSuffix(segments[i], ".scope")
		seg = strings.TrimSuffix(seg, ".slice")
		if m := containerIDRe.FindStringSubmatch(seg); m != nil {
			info.ContainerID = m[1]
			break
		}
	}

	if m := podUIDRe.FindStringSubmatch(path); m != nil {
		uid := strings.ReplaceAll(m[1], "_", "-")
		info.PodUID = strings.ToLower(uid)
	}

	if m := qosRe.FindStringSubmatch(path); m != nil {
		info.QoSClass = strings.ToLower(m[1])
	} else if strings.Contains(path, "kubepods") && info.PodUID != "" {
		// Guaranteed pods sit directly under kubepods with no QoS segment.
		info.QoSClass = "guaranteed"
	}

	return info
}

// ReadCgroupPath returns the unified (v2) cgroup path for a process, falling
// back to any v1 controller path when the host is still on cgroup v1.
func ReadCgroupPath(procRoot string, pid int) (string, error) {
	path := procPath(procRoot, pid, "cgroup")
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return ParseCgroupFile(string(raw)), nil
}

// ParseCgroupFile extracts the most useful path from /proc/[pid]/cgroup.
//
// cgroup v2 emits a single "0::<path>" line. cgroup v1 emits one line per
// controller. Hybrid hosts emit both, and there the v2 line is frequently just
// "0::/" while the container identity lives on the v1 controller lines - so a
// root-only v2 path is not preferred over a v1 path that actually says
// something.
func ParseCgroupFile(content string) string {
	var unified, fallback string

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 {
			continue
		}
		hierarchy, controllers, path := parts[0], parts[1], parts[2]

		if hierarchy == "0" && controllers == "" {
			unified = path
			if path != "" && path != "/" {
				return path // unified hierarchy with real content
			}
			continue
		}
		if fallback == "" && path != "/" {
			fallback = path
		}
	}

	if fallback != "" {
		return fallback
	}
	return unified
}

func procPath(procRoot string, pid int, name string) string {
	if procRoot == "" {
		procRoot = "/proc"
	}
	return fmt.Sprintf("%s/%d/%s", strings.TrimRight(procRoot, "/"), pid, name)
}
