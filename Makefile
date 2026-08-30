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

.PHONY: test
test: ## Run the unit tests with the race detector and coverage
	$(GO) test ./... -race -cover

.PHONY: test-integration
test-integration: ## Run the tests that hit the real OSV API
	$(GO) test -tags integration -count=1 ./...

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run

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

.PHONY: clean
clean: ## Remove build output
	rm -rf bin/
