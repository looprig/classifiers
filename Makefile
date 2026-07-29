.PHONY: test fmt fmt-check vendor vendor-scrub vendor-check release-check

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
# go.mod). Empty until a later task adds a Harness dependency; kept defined
# here so `make vendor` stays correct as soon as one is added, matching the
# pattern in github.com/looprig/harness-permission-classifier's Makefile.
LOCAL_REPLACE_VENDOR_DIRS :=

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
