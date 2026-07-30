.PHONY: test fmt fmt-check lint vuln secure vendor vendor-scrub vendor-check release-check

GO ?= go

# Module's own package dirs, excluding vendor/ and any nested .worktrees/
# modules (go list ./... stops at nested module boundaries and skips vendor).
GO_DIRS = $(shell go list -f '{{.Dir}}' ./...)

# Build from the vendored dependency tree: offline, reproducible, and
# auditable (every dependency's source lives in vendor/ and shows up in
# review diffs). Go auto-selects -mod=vendor when vendor/ is present; export
# it explicitly so a stray global GOFLAGS (e.g. -mod=mod) can't silently
# switch the build off the vendored tree. Do NOT use -mod=readonly here — it
# ignores vendor/ entirely.
export GOFLAGS := -mod=vendor

VENDOR_DIR ?= vendor

# Sibling modules this module locally replaces during development (see
# go.mod's replace block), matching the pattern in
# github.com/looprig/harness-permission-classifier's Makefile.
LOCAL_REPLACE_VENDOR_DIRS := \
	$(VENDOR_DIR)/github.com/looprig/core \
	$(VENDOR_DIR)/github.com/looprig/harness \
	$(VENDOR_DIR)/github.com/looprig/inference

RELEASE_MODFILE ?= go.release.mod

test:
	go test -race ./...

# Format the whole module in place.
fmt:
	gofmt -w $(GO_DIRS)

# Fail (non-zero exit) if any tracked Go file is not gofmt-clean.
fmt-check:
	@unformatted=$$(gofmt -l $(GO_DIRS)); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed (run 'make fmt'):"; echo "$$unformatted"; exit 1; \
	fi

# go.mod's tool block declares gosec/staticcheck/govulncheck (dev/tool-only,
# never compiled into this module's own packages) — these three targets
# mirror github.com/looprig/harness-permission-classifier's Makefile
# exactly so `make secure` is a consistent convention across every sibling
# module in this feature, not just Harness and CodeRig.
lint: fmt-check vendor-check
	go vet ./...
	go tool staticcheck ./...
	# gosec is NOT module-aware: its ./... is a filesystem walk that would
	# descend into sibling checkouts alongside this module rather than
	# stopping at module boundaries the way go vet and staticcheck do. Scope
	# it to THIS module's package dirs via GO_DIRS (the same go-list idiom
	# fmt/fmt-check use).
	go tool gosec $(GO_DIRS)

vuln:
	go mod verify
	go tool govulncheck ./...

secure: lint vuln

# Refresh the auditable dependency tree, then remove only VCS metadata
# donated by any declared local replace targets. A final whole-tree check
# catches metadata from any other source instead of broadening the scrub
# silently.
vendor:
	go mod vendor
	$(MAKE) vendor-scrub
	$(MAKE) vendor-check

vendor-scrub:
	@if [ -n "$(LOCAL_REPLACE_VENDOR_DIRS)" ]; then \
		rm -rf $(addsuffix /.git,$(LOCAL_REPLACE_VENDOR_DIRS)); \
	fi

vendor-check:
	@metadata=$$(find "$(VENDOR_DIR)" -name .git -print 2>/dev/null); \
	if [ -n "$$metadata" ]; then \
		echo "forbidden VCS metadata in $(VENDOR_DIR):"; echo "$$metadata"; exit 1; \
	fi

# Fail-closed guard for building a tagged release: refuse to proceed unless
# a prepared release modfile exists and contains no local filesystem
# replace directive, then build/test against exactly that modfile.
release-check:
	@test -f "$(RELEASE_MODFILE)" || (echo "$(RELEASE_MODFILE) is not prepared" >&2; exit 1)
	@sh scripts/check-release-modfile.sh "$(RELEASE_MODFILE)"
	$(GO) test -modfile="$(RELEASE_MODFILE)" -race ./...
