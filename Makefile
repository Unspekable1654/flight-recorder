# Flight Recorder build.
#
# The only unusual step is `generate`: the eBPF C is compiled to BPF bytecode by
# clang and embedded into the Go binary by bpf2go. The generated files are
# committed, so `make build` works with no clang installed - you only need the
# toolchain if you change bpf/recorder.c.

SHELL := /bin/bash
.DEFAULT_GOAL := build

BINARY      := flight-recorder
MODULE      := github.com/Unspekable1654/flight-recorder
CMD         := ./cmd/flight-recorder
OUT         := ./bin

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/pkg/version.Version=$(VERSION) \
	-X $(MODULE)/pkg/version.Commit=$(COMMIT) \
	-X $(MODULE)/pkg/version.BuildDate=$(BUILD_DATE)

# eBPF toolchain. Override BPF_CLANG if your clang is versioned (clang-17 etc).
BPF_CLANG  ?= clang
BPF_CFLAGS ?= -O2 -g -Wall -Werror -D__TARGET_ARCH_x86

IMAGE_REPO ?= ghcr.io/unspekable1654/flight-recorder
IMAGE_TAG  ?= $(VERSION)

GOOS   ?= linux
GOARCH ?= amd64

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

# -----------------------------------------------------------------------------
# eBPF
# -----------------------------------------------------------------------------

.PHONY: generate
generate: ## Compile bpf/recorder.c and regenerate the Go bindings (needs clang)
	@command -v $(BPF_CLANG) >/dev/null || { echo "error: $(BPF_CLANG) not found. Install clang 14+ or set BPF_CLANG."; exit 1; }
	BPF_CLANG=$(BPF_CLANG) BPF_CFLAGS="$(BPF_CFLAGS)" go generate ./pkg/probe/...
	@echo "generated: pkg/probe/recorder_bpfel.go pkg/probe/recorder_bpfel.o"

.PHONY: vmlinux
vmlinux: ## Regenerate bpf/vmlinux.h from this machine's kernel BTF
	@test -r /sys/kernel/btf/vmlinux || { echo "error: /sys/kernel/btf/vmlinux not readable; this kernel has no BTF"; exit 1; }
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
	@echo "wrote bpf/vmlinux.h ($$(wc -c < bpf/vmlinux.h) bytes)"

.PHONY: bpf-verify
bpf-verify: ## Compile the eBPF object only, without regenerating Go bindings
	$(BPF_CLANG) -target bpf $(BPF_CFLAGS) -I bpf -I bpf/include -c bpf/recorder.c -o /tmp/recorder.o
	@echo "eBPF object compiled: /tmp/recorder.o"

# -----------------------------------------------------------------------------
# Build
# -----------------------------------------------------------------------------

.PHONY: build
build: ## Build the binary for the host platform
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o $(OUT)/$(BINARY) $(CMD)
	@echo "built $(OUT)/$(BINARY) ($(VERSION))"

.PHONY: build-all
build-all: ## Cross-compile for linux/amd64 and linux/arm64
	@for arch in amd64 arm64; do \
		echo "building linux/$$arch"; \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(OUT)/$(BINARY)-linux-$$arch $(CMD) || exit 1; \
	done
	@ls -la $(OUT)

.PHONY: install
install: build ## Install to /usr/local/bin with CAP_SYS_PTRACE
	install -m 0755 $(OUT)/$(BINARY) /usr/local/bin/$(BINARY)
	setcap cap_sys_ptrace,cap_bpf,cap_perfmon,cap_sys_resource+ep /usr/local/bin/$(BINARY) || \
		echo "warning: setcap failed; run as root or set capabilities manually"

# -----------------------------------------------------------------------------
# Test
# -----------------------------------------------------------------------------

.PHONY: test
test: ## Run unit tests with the race detector
	go test -race -count=1 ./pkg/...

.PHONY: test-short
test-short: ## Run unit tests without the race detector
	go test -count=1 ./pkg/...

.PHONY: test-integration
test-integration: ## Run integration tests (needs root and a real kernel)
	@test "$$(id -u)" = "0" || { echo "error: integration tests need root (eBPF + CAP_SYS_PTRACE)"; exit 1; }
	go test -tags=integration -v -timeout 10m ./test/integration/...

.PHONY: fuzz
fuzz: ## Fuzz the /proc/[pid]/maps parser for 60 seconds
	go test -run=XXX -fuzz=FuzzParseProcMaps -fuzztime=60s ./pkg/capture/

.PHONY: bench
bench: ## Run benchmarks (Merkle sealing throughput)
	go test -run=XXX -bench=. -benchmem ./pkg/seal/

.PHONY: cover
cover: ## Produce a coverage report
	go test -coverprofile=coverage.out -covermode=atomic ./pkg/...
	go tool cover -func=coverage.out | tail -1
	@echo "html report: go tool cover -html=coverage.out"

.PHONY: demo
demo: build ## Run the full pipeline against a synthetic capture
	$(OUT)/$(BINARY) demo --output /tmp/flight-recorder-demo

# -----------------------------------------------------------------------------
# Quality
# -----------------------------------------------------------------------------

.PHONY: fmt
fmt: ## Format Go source
	gofmt -w ./cmd ./pkg ./test

.PHONY: vet
vet: ## Run go vet for linux/amd64 and linux/arm64
	go vet ./...
	GOOS=linux GOARCH=arm64 go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	@command -v golangci-lint >/dev/null || { echo "error: golangci-lint not installed: https://golangci-lint.run/welcome/install/"; exit 1; }
	golangci-lint run ./...

.PHONY: check
check: fmt vet test ## Format, vet and test

.PHONY: tidy
tidy: ## Tidy and verify the module graph
	go mod tidy
	go mod verify

# -----------------------------------------------------------------------------
# Protobuf
# -----------------------------------------------------------------------------

.PHONY: proto
proto: ## Regenerate the gRPC evidence API bindings
	@command -v protoc >/dev/null || { echo "error: protoc not installed"; exit 1; }
	protoc --proto_path=pkg/export/grpc \
		--go_out=paths=source_relative:pkg/export/grpc \
		--go-grpc_out=paths=source_relative:pkg/export/grpc \
		pkg/export/grpc/evidence.proto

.PHONY: tools
tools: ## Install the code generation tools
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# -----------------------------------------------------------------------------
# Container and deployment
# -----------------------------------------------------------------------------

.PHONY: docker
docker: ## Build the container image
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE_REPO):$(IMAGE_TAG) .

.PHONY: docker-push
docker-push: docker ## Push the container image
	docker push $(IMAGE_REPO):$(IMAGE_TAG)

.PHONY: deploy
deploy: ## Apply the raw Kubernetes manifests
	kubectl apply -f deploy/k8s/rbac.yaml
	kubectl apply -f deploy/k8s/configmap.yaml
	kubectl apply -f deploy/k8s/daemonset.yaml

.PHONY: undeploy
undeploy: ## Remove the Kubernetes deployment
	kubectl delete -f deploy/k8s/daemonset.yaml --ignore-not-found
	kubectl delete -f deploy/k8s/configmap.yaml --ignore-not-found
	kubectl delete -f deploy/k8s/rbac.yaml --ignore-not-found

.PHONY: helm-lint
helm-lint: ## Lint and render the Helm chart
	helm lint deploy/helm/flight-recorder
	helm template flight-recorder deploy/helm/flight-recorder >/dev/null && echo "chart renders cleanly"

.PHONY: scenarios
scenarios: ## Deploy the attack simulation scenarios
	kubectl apply -f test/scenarios/namespace.yaml
	kubectl apply -f test/scenarios/

.PHONY: scenarios-clean
scenarios-clean: ## Remove the attack simulation scenarios
	kubectl delete -f test/scenarios/ --ignore-not-found

.PHONY: sbom
sbom: ## Generate a CycloneDX SBOM
	@command -v syft >/dev/null || { echo "error: syft not installed: https://github.com/anchore/syft"; exit 1; }
	syft . -o cyclonedx-json=sbom.cdx.json
	@echo "wrote sbom.cdx.json"

.PHONY: clean
clean: ## Remove build artefacts
	rm -rf $(OUT) coverage.out sbom.cdx.json
	go clean -testcache
