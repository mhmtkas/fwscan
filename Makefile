# fwscan — see CONTRIBUTING.md. Every target is safe to run from a fresh clone.
GO      ?= go
BINARY  := fwscan
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.DEFAULT_GOAL := help

.PHONY: help
help: ## List the available targets
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) | sort | \
		awk -F':.*?## ' '{printf "  \033[1m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## Build ./bin/fwscan with the version stamped in
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/fwscan

# The race detector needs a 48-bit virtual address space on arm64. Several
# single-board kernels are built narrower -- the Orange Pi 5's RK3588 kernel is
# 39-bit, the Raspberry Pi 5's is 47 -- and `go test -race` there dies with
# "ThreadSanitizer: unsupported VMA range" before running a single test. Probing
# for it keeps `make test` usable on those machines; CI runs on amd64 and always
# has it.
RACE := $(shell d=$$(mktemp -d); printf 'package main\nfunc main(){}\n' > $$d/rc.go; \
	(cd $$d && $(GO) mod init rc >/dev/null 2>&1 && $(GO) run -race ./rc.go >/dev/null 2>&1) \
	&& echo -race; rm -rf $$d)

.PHONY: test
test: ## Run the unit tests with coverage, and the race detector where it works
	@test -n "$(RACE)" || echo "note: race detector unavailable on this kernel, running without it"
	$(GO) test ./... $(RACE) -cover

.PHONY: test-race
test-race: ## Run the unit tests, insisting on the race detector
	@test -n "$(RACE)" || { echo "the race detector does not work on this kernel"; exit 1; }
	$(GO) test ./... -race -cover

.PHONY: test-integration
test-integration: ## Run the tests that hit the real OSV API
	$(GO) test -tags integration -count=1 ./...

.PHONY: test-apk-oracle
test-apk-oracle: ## Check the apk version comparator against apk itself (needs Docker)
	$(GO) test -tags apkoracle -count=1 -run AgainstAPK ./internal/match/

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run

.PHONY: fixtures
fixtures: ## Rebuild the lz4/zstd/xz squashfs variants from the committed gzip image
	@command -v unsquashfs >/dev/null 2>&1 && command -v mksquashfs >/dev/null 2>&1 || { \
		echo "squashfs-tools 4.4 or newer is required."; \
		echo "  apt install squashfs-tools   /   brew install squashfs"; \
		exit 1; }
	@rm -rf bin/fixture-src
	@mkdir -p bin
	unsquashfs -no-progress -quiet -d bin/fixture-src testdata/images/mini-rootfs.squashfs
	@for comp in lz4 zstd xz; do \
		echo "  building mini-rootfs.$$comp.squashfs"; \
		rm -f testdata/images/mini-rootfs.$$comp.squashfs; \
		mksquashfs bin/fixture-src testdata/images/mini-rootfs.$$comp.squashfs \
			-comp $$comp -noappend -all-root -no-xattrs -quiet -no-progress; \
	done
	@rm -rf bin/fixture-src

.PHONY: validate-sbom
validate-sbom: build ## Generate an SBOM from the fixture and validate it against the CycloneDX 1.6 schema
	@command -v cyclonedx >/dev/null 2>&1 || { \
		echo "cyclonedx-cli not found. Install it from"; \
		echo "  https://github.com/CycloneDX/cyclonedx-cli/releases"; \
		echo "or, on macOS: brew install cyclonedx/cyclonedx/cyclonedx-cli"; \
		exit 1; }
	@mkdir -p bin
	./bin/$(BINARY) scan --no-network --sbom bin/fixture.cdx.json testdata/images/mini-rootfs.tar.gz >/dev/null
	cyclonedx validate --input-file bin/fixture.cdx.json --input-format json --input-version v1_6 --fail-on-errors

.PHONY: fmt
fmt: ## Rewrite source with gofmt
	$(GO) fmt ./...

.PHONY: tidy
tidy: ## Sync go.mod/go.sum
	$(GO) mod tidy

.PHONY: demo
demo: build ## Scan the fixture image, for an asciinema recording
	@echo '$$ fwscan scan testdata/images/mini-rootfs.tar.gz'
	@./bin/$(BINARY) scan testdata/images/mini-rootfs.tar.gz || true

.PHONY: snapshot
snapshot: ## Build release artifacts locally without publishing
	@command -v goreleaser >/dev/null 2>&1 || { \
		echo "goreleaser not found: https://goreleaser.com/install/"; exit 1; }
	goreleaser release --snapshot --clean --skip=publish

.PHONY: clean
clean: ## Remove build output
	rm -rf bin/ dist/
