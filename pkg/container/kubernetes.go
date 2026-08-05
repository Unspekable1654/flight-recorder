package container

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Kubernetes service account mount points, fixed by the kubelet.
const (
	// The fixed kubelet mount PATH, not a credential.
	// #nosec G101
	saTokenPath     = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCACertPath    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	saNamespacePath = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
)

// KubeEnricher resolves pod metadata from the Kubernetes API.
//
// It speaks to the API server directly over HTTPS with the pod's service
// account token rather than depending on client-go. That is a deliberate
// supply-chain decision: client-go and its transitive dependencies are larger
// than the rest of this tool combined, and all that is needed here is a single
// scoped LIST of pods on one node.
//
// The pod list is cached and refreshed in the background. A capture must never
// block on an API round trip - by the time the API answers, the container may
// be gone.
type KubeEnricher struct {
	client   *http.Client
	host     string
	token    string
	nodeName string

	mu           sync.RWMutex
	byUID        map[string]PodMeta
	byContainer  map[string]PodMeta
	lastRefresh  time.Time
	lastError    error
	refreshCount uint64
}

// KubeConfig configures the enricher.
type KubeConfig struct {
	// NodeName restricts the pod list to one node. Required in production:
	// listing every pod in a large cluster on every node is a well known way
	// to melt an API server.
	NodeName string
	// RefreshInterval is how often the pod cache is rebuilt.
	RefreshInterval time.Duration
	// Timeout bounds a single API request.
	Timeout time.Duration
}

// NewKubeEnricher builds an enricher from the in-cluster service account.
//
// It returns an error when the process is not running inside a pod, which the
// caller should treat as "Kubernetes enrichment unavailable" rather than as a
// fatal condition: the tool still produces valid evidence with container ids
// only.
func NewKubeEnricher(cfg KubeConfig) (*KubeEnricher, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		return nil, fmt.Errorf("container: not running in-cluster (KUBERNETES_SERVICE_HOST unset)")
	}

	tokenRaw, err := os.ReadFile(saTokenPath)
	if err != nil {
		return nil, fmt.Errorf("container: read service account token: %w", err)
	}

	caRaw, err := os.ReadFile(saCACertPath)
	if err != nil {
		return nil, fmt.Errorf("container: read service account CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caRaw) {
		return nil, fmt.Errorf("container: service account CA bundle contains no usable certificates")
	}

	if cfg.RefreshInterval <= 0 {
		cfg.RefreshInterval = 30 * time.Second
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.NodeName == "" {
		cfg.NodeName = os.Getenv("NODE_NAME")
	}

	transport := &http.Transport{
		TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		MaxIdleConns:        4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		DialContext:         (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
	}

	return &KubeEnricher{
		client:      &http.Client{Transport: transport, Timeout: cfg.Timeout},
		host:        "https://" + net.JoinHostPort(host, port),
		token:       strings.TrimSpace(string(tokenRaw)),
		nodeName:    cfg.NodeName,
		byUID:       make(map[string]PodMeta),
		byContainer: make(map[string]PodMeta),
	}, nil
}

// Start performs an initial refresh and then keeps the cache warm until ctx is
// cancelled.
func (k *KubeEnricher) Start(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 30 * time.Second
	}

	// A failed first refresh is not fatal: the ticker will retry, and captures
	// proceed with container ids in the meantime.
	_ = k.Refresh(ctx)

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				_ = k.Refresh(ctx)
			}
		}
	}()
}

type podList struct {
	Items []struct {
		Metadata struct {
			Name      string `json:"name"`
			Namespace string `json:"namespace"`
			UID       string `json:"uid"`
		} `json:"metadata"`
		Spec struct {
			NodeName string `json:"nodeName"`
		} `json:"spec"`
		Status struct {
			ContainerStatuses []struct {
				ContainerID string `json:"containerID"`
				Name        string `json:"name"`
			} `json:"containerStatuses"`
			InitContainerStatuses []struct {
				ContainerID string `json:"containerID"`
				Name        string `json:"name"`
			} `json:"initContainerStatuses"`
			EphemeralContainerStatuses []struct {
				ContainerID string `json:"containerID"`
				Name        string `json:"name"`
			} `json:"ephemeralContainerStatuses"`
		} `json:"status"`
	} `json:"items"`
}

// Refresh rebuilds the pod cache from the API server.
func (k *KubeEnricher) Refresh(ctx context.Context) error {
	url := k.host + "/api/v1/pods"
	if k.nodeName != "" {
		url += "?fieldSelector=spec.nodeName%3D" + k.nodeName
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return k.recordError(fmt.Errorf("container: build pod list request: %w", err))
	}
	req.Header.Set("Authorization", "Bearer "+k.token)
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return k.recordError(fmt.Errorf("container: list pods: %w", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return k.recordError(fmt.Errorf("container: list pods: API returned %s", resp.Status))
	}

	var list podList
	if err := json.NewDecoder(resp.Body).Decode(&list); err != nil {
		return k.recordError(fmt.Errorf("container: decode pod list: %w", err))
	}

	byUID := make(map[string]PodMeta, len(list.Items))
	byContainer := make(map[string]PodMeta, len(list.Items)*2)

	for _, item := range list.Items {
		meta := PodMeta{
			Name:      item.Metadata.Name,
			Namespace: item.Metadata.Namespace,
			UID:       item.Metadata.UID,
			NodeName:  item.Spec.NodeName,
		}
		byUID[item.Metadata.UID] = meta

		statuses := item.Status.ContainerStatuses
		statuses = append(statuses, item.Status.InitContainerStatuses...)
		statuses = append(statuses, item.Status.EphemeralContainerStatuses...)
		for _, cs := range statuses {
			if id := TrimContainerIDPrefix(cs.ContainerID); id != "" {
				byContainer[id] = meta
			}
		}
	}

	k.mu.Lock()
	k.byUID = byUID
	k.byContainer = byContainer
	k.lastRefresh = time.Now()
	k.lastError = nil
	k.refreshCount++
	k.mu.Unlock()

	return nil
}

func (k *KubeEnricher) recordError(err error) error {
	k.mu.Lock()
	k.lastError = err
	k.mu.Unlock()
	return err
}

// LookupPodByUID implements PodEnricher.
func (k *KubeEnricher) LookupPodByUID(uid string) (PodMeta, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	meta, ok := k.byUID[uid]
	return meta, ok
}

// LookupPodByContainerID implements PodEnricher.
func (k *KubeEnricher) LookupPodByContainerID(id string) (PodMeta, bool) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	meta, ok := k.byContainer[id]
	return meta, ok
}

// Status reports cache health for the readiness probe and metrics.
func (k *KubeEnricher) Status() (pods int, lastRefresh time.Time, err error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return len(k.byUID), k.lastRefresh, k.lastError
}

// TrimContainerIDPrefix strips the runtime scheme from a CRI container id
// ("containerd://<id>" -> "<id>").
func TrimContainerIDPrefix(id string) string {
	if i := strings.Index(id, "://"); i >= 0 {
		return id[i+3:]
	}
	return id
}

// InClusterNamespace returns the namespace the recorder itself runs in, used
// to exclude its own activity from monitoring.
func InClusterNamespace() string {
	raw, err := os.ReadFile(saNamespacePath)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// StaticEnricher is a fixed pod table used by tests and by air-gapped
// deployments where the API server is unreachable by policy.
type StaticEnricher struct {
	ByUID       map[string]PodMeta
	ByContainer map[string]PodMeta
}

// LookupPodByUID implements PodEnricher.
func (s *StaticEnricher) LookupPodByUID(uid string) (PodMeta, bool) {
	meta, ok := s.ByUID[uid]
	return meta, ok
}

// LookupPodByContainerID implements PodEnricher.
func (s *StaticEnricher) LookupPodByContainerID(id string) (PodMeta, bool) {
	meta, ok := s.ByContainer[id]
	return meta, ok
}
