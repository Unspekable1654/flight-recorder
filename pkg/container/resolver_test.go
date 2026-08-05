package container

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseCgroupPathAcrossRuntimes(t *testing.T) {
	const id = "3f2b1c0d9e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c"

	cases := []struct {
		name        string
		path        string
		wantID      string
		wantPodUID  string
		wantRuntime Runtime
		wantQoS     string
	}{
		{
			name:        "containerd systemd driver",
			path:        "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podb6c5d4e3_f2a1_4b0c_9d8e_7f6a5b4c3d2e.slice/cri-containerd-" + id + ".scope",
			wantID:      id,
			wantPodUID:  "b6c5d4e3-f2a1-4b0c-9d8e-7f6a5b4c3d2e",
			wantRuntime: RuntimeContainerd,
			wantQoS:     "burstable",
		},
		{
			name:        "containerd cgroupfs driver",
			path:        "/kubepods/besteffort/podb6c5d4e3-f2a1-4b0c-9d8e-7f6a5b4c3d2e/" + id,
			wantID:      id,
			wantPodUID:  "b6c5d4e3-f2a1-4b0c-9d8e-7f6a5b4c3d2e",
			wantRuntime: RuntimeContainerd,
			wantQoS:     "besteffort",
		},
		{
			name:        "cri-o",
			path:        "/kubepods.slice/kubepods-pod b6c5d4e3_f2a1_4b0c_9d8e_7f6a5b4c3d2e.slice/crio-" + id + ".scope",
			wantID:      id,
			wantRuntime: RuntimeCRIO,
		},
		{
			name:        "plain docker",
			path:        "/docker/" + id,
			wantID:      id,
			wantRuntime: RuntimeDocker,
		},
		{
			name:        "docker systemd scope",
			path:        "/system.slice/docker-" + id + ".scope",
			wantID:      id,
			wantRuntime: RuntimeDocker,
		},
		{
			name:        "guaranteed pod without a qos segment",
			path:        "/kubepods.slice/kubepods-podb6c5d4e3_f2a1_4b0c_9d8e_7f6a5b4c3d2e.slice/cri-containerd-" + id + ".scope",
			wantID:      id,
			wantPodUID:  "b6c5d4e3-f2a1-4b0c-9d8e-7f6a5b4c3d2e",
			wantRuntime: RuntimeContainerd,
			wantQoS:     "guaranteed",
		},
		{
			name:        "host process",
			path:        "/user.slice/user-1000.slice/session-3.scope",
			wantID:      "",
			wantRuntime: RuntimeUnknown,
		},
		{
			name:        "empty",
			path:        "",
			wantID:      "",
			wantRuntime: RuntimeUnknown,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ParseCgroupPath(tc.path)

			if got.ContainerID != tc.wantID {
				t.Errorf("container id = %q, want %q", got.ContainerID, tc.wantID)
			}
			if tc.wantPodUID != "" && got.PodUID != tc.wantPodUID {
				t.Errorf("pod uid = %q, want %q", got.PodUID, tc.wantPodUID)
			}
			if got.Runtime != tc.wantRuntime {
				t.Errorf("runtime = %q, want %q", got.Runtime, tc.wantRuntime)
			}
			if tc.wantQoS != "" && got.QoSClass != tc.wantQoS {
				t.Errorf("qos = %q, want %q", got.QoSClass, tc.wantQoS)
			}
		})
	}
}

func TestParseCgroupFile(t *testing.T) {
	v2 := "0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-abc.scope\n"
	if got := ParseCgroupFile(v2); !strings.HasPrefix(got, "/kubepods.slice") {
		t.Errorf("cgroup v2 path = %q", got)
	}

	v1 := strings.Join([]string{
		"12:pids:/kubepods/burstable/pod123/abc",
		"11:memory:/kubepods/burstable/pod123/abc",
		"0::/",
		"",
	}, "\n")
	if got := ParseCgroupFile(v1); got != "/kubepods/burstable/pod123/abc" {
		t.Errorf("cgroup v1 path = %q", got)
	}

	if got := ParseCgroupFile("garbage\nlines\n"); got != "" {
		t.Errorf("malformed content returned %q", got)
	}
	if got := ParseCgroupFile(""); got != "" {
		t.Errorf("empty content returned %q", got)
	}
}

func TestParseNSPid(t *testing.T) {
	cases := []struct {
		name   string
		status string
		want   []int
	}{
		{
			name:   "nested container",
			status: "Name:\tsh\nPid:\t48291\nNSpid:\t48291\t42\t1\n",
			want:   []int{48291, 42, 1},
		},
		{
			name:   "host process",
			status: "Name:\tbash\nPid:\t1234\nNSpid:\t1234\n",
			want:   []int{1234},
		},
		{
			name:   "kernel without pid namespaces",
			status: "Name:\tinit\nPid:\t1\nPPid:\t0\n",
			want:   []int{1},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseNSPid(tc.status)
			if err != nil {
				t.Fatalf("ParseNSPid: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("chain = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("chain = %v, want %v", got, tc.want)
				}
			}
		})
	}

	if _, err := ParseNSPid("Name:\tsh\n"); err == nil {
		t.Error("status with neither NSpid nor Pid was accepted")
	}
	if _, err := ParseNSPid("NSpid:\tnotanumber\n"); err == nil {
		t.Error("a malformed NSpid entry was accepted")
	}
}

// The whole point of the resolver: PID 1 inside a container is a high PID on
// the host, and confusing the two produces evidence that correlates with
// nothing.
func TestNamespacePIDFromFakeProcfs(t *testing.T) {
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "48291")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	status := "Name:\tsh\nPid:\t48291\nNSpid:\t48291\t1\n"
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	nsPID, level, err := NamespacePID(procRoot, 48291)
	if err != nil {
		t.Fatalf("NamespacePID: %v", err)
	}
	if nsPID != 1 {
		t.Errorf("namespace pid = %d, want 1", nsPID)
	}
	if level != 1 {
		t.Errorf("namespace level = %d, want 1", level)
	}
}

func TestResolveFromFakeProcfs(t *testing.T) {
	const containerID = "3f2b1c0d9e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c"
	const podUID = "b6c5d4e3-f2a1-4b0c-9d8e-7f6a5b4c3d2e"

	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "48291")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}

	cgroup := "0::/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-podb6c5d4e3_f2a1_4b0c_9d8e_7f6a5b4c3d2e.slice/cri-containerd-" + containerID + ".scope\n"
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroup), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte("Pid:\t48291\nNSpid:\t48291\t1\n"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	enricher := &StaticEnricher{
		ByUID: map[string]PodMeta{
			podUID: {Name: "victim-app-7d9f8b6c5-x2kqp", Namespace: "victim", UID: podUID, NodeName: "worker-3"},
		},
	}

	resolver := NewResolver(
		WithProcRoot(procRoot),
		WithNodeName("worker-3"),
		WithEnricher(enricher),
	)

	info, err := resolver.Resolve(91237845, 48291)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	if info.ContainerID != containerID {
		t.Errorf("container id = %q", info.ContainerID)
	}
	if info.ShortID != containerID[:12] {
		t.Errorf("short id = %q", info.ShortID)
	}
	if info.PodName != "victim-app-7d9f8b6c5-x2kqp" || info.PodNamespace != "victim" {
		t.Errorf("pod = %s/%s", info.PodNamespace, info.PodName)
	}
	if !info.Enriched {
		t.Error("Enriched should be true when API metadata was found")
	}
	if info.HostPID != 48291 || info.NamespacePID != 1 {
		t.Errorf("pids = host %d, ns %d", info.HostPID, info.NamespacePID)
	}
	if info.Runtime != RuntimeContainerd {
		t.Errorf("runtime = %q", info.Runtime)
	}
	if !info.InContainer() {
		t.Error("InContainer = false for a container process")
	}
	if !strings.Contains(info.Describe(), "victim/victim-app") {
		t.Errorf("Describe = %q", info.Describe())
	}

	// Second resolution must hit the cache and still be correct.
	again, err := resolver.Resolve(91237845, 48291)
	if err != nil {
		t.Fatalf("Resolve (cached): %v", err)
	}
	if again.ContainerID != containerID || again.PodName != info.PodName {
		t.Error("cached resolution returned different metadata")
	}
}

func TestResolveMissingProcessIsNotFatal(t *testing.T) {
	resolver := NewResolver(WithProcRoot(t.TempDir()), WithNodeName("node"))

	info, err := resolver.Resolve(1234, 999999)
	if err != nil {
		t.Fatalf("Resolve of a vanished process returned an error: %v", err)
	}
	if info == nil {
		t.Fatal("Resolve returned no info")
	}
	if info.HostPID != 999999 {
		t.Errorf("host pid = %d", info.HostPID)
	}
	if info.InContainer() {
		t.Error("a process with no cgroup data was reported as containerised")
	}
	if !strings.Contains(info.Describe(), "host pid") {
		t.Errorf("Describe = %q", info.Describe())
	}
}

func TestResolverCacheExpiry(t *testing.T) {
	procRoot := t.TempDir()
	pidDir := filepath.Join(procRoot, "100")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	cgroup := "0::/docker/3f2b1c0d9e8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a3b2c\n"
	if err := os.WriteFile(filepath.Join(pidDir, "cgroup"), []byte(cgroup), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	resolver := NewResolver(WithProcRoot(procRoot), WithCacheTTL(time.Nanosecond))
	if _, err := resolver.Resolve(42, 100); err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	time.Sleep(time.Millisecond)
	if purged := resolver.Purge(); purged != 1 {
		t.Errorf("Purge removed %d entries, want 1", purged)
	}
}

func TestTrimContainerIDPrefix(t *testing.T) {
	cases := map[string]string{
		"containerd://abc123": "abc123",
		"docker://def456":     "def456",
		"cri-o://ghi789":      "ghi789",
		"plainid":             "plainid",
		"":                    "",
	}
	for in, want := range cases {
		if got := TrimContainerIDPrefix(in); got != want {
			t.Errorf("TrimContainerIDPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestStaticEnricher(t *testing.T) {
	e := &StaticEnricher{
		ByUID:       map[string]PodMeta{"uid-1": {Name: "pod-1"}},
		ByContainer: map[string]PodMeta{"cid-1": {Name: "pod-2"}},
	}

	if meta, ok := e.LookupPodByUID("uid-1"); !ok || meta.Name != "pod-1" {
		t.Error("lookup by uid failed")
	}
	if meta, ok := e.LookupPodByContainerID("cid-1"); !ok || meta.Name != "pod-2" {
		t.Error("lookup by container id failed")
	}
	if _, ok := e.LookupPodByUID("missing"); ok {
		t.Error("lookup of an unknown uid succeeded")
	}
}

func TestNewKubeEnricherOutsideCluster(t *testing.T) {
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	if _, err := NewKubeEnricher(KubeConfig{}); err == nil {
		t.Error("expected an error when not running in-cluster")
	}
}

func TestParseNSLink(t *testing.T) {
	if v, ok := parseNSLink("pid:[4026532278]"); !ok || v != 4026532278 {
		t.Errorf("parseNSLink = %d, %v", v, ok)
	}
	for _, bad := range []string{"", "pid:", "pid:[]", "pid:[abc]", "no brackets"} {
		if _, ok := parseNSLink(bad); ok {
			t.Errorf("parseNSLink(%q) succeeded", bad)
		}
	}
}
