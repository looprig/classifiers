.PHONY: test fmt fmt-check lint vuln secure release-check

GO ?= go

# Module's own package dirs (go list ./... stops at nested module boundaries).
# GO_DIRS scopes gosec, which takes package dirs. Never hand GO_DIRS to gofmt:
# gofmt recurses into directory operands, and for a module with a root package
# GO_DIRS contains the module root, so gofmt would walk the entire tree —
# including the nested .worktrees/ checkouts, which are separate modules. Use
# GO_FILES for gofmt: it expands to each package dir's own .go files (including
# platform-specific ones go list omits for the host) without descending.
GO_DIRS := $(shell go list -f '{{.Dir}}' ./...)
GO_FILES := $(foreach dir,$(GO_DIRS),$(wildcard $(dir)/*.go))

# This module does not vendor. go.mod pins exact versions and go.sum verifies
# their content hashes, which is what makes a build reproducible; a vendor tree
# adds only offline builds and source-level dependency diffs. It also actively
# misleads: a stale vendor/ is ignored under a go.work but silently satisfies a
# GOWORK=off build, so standalone verification tests the vendored copy rather
# than the version go.mod actually pins — which is precisely what standalone
# verification exists to check.

RELEASE_MODFILE ?= go.release.mod

test:
	go test -race ./...

# Format this module's own Go files in place.
fmt:
	gofmt -w $(GO_FILES)

# Fail (non-zero exit) if any tracked Go file is not gofmt-clean.
fmt-check:
	@unformatted=$$(gofmt -l $(GO_FILES)); \
	if [ -n "$$unformatted" ]; then \
		echo "gofmt needed (run 'make fmt'):"; echo "$$unformatted"; exit 1; \
	fi

# go.mod's tool block declares gosec/staticcheck/govulncheck (dev/tool-only,
# never compiled into this module's own packages) — these three targets
# mirror github.com/looprig/harness-permission-classifier's Makefile
# exactly so `make secure` is a consistent convention across every sibling
# module in this feature, not just Harness and Carbon.
lint: fmt-check
	go vet ./...
	go tool staticcheck ./...
	# gosec is NOT module-aware: its ./... is a filesystem walk that would
	# descend into sibling checkouts alongside this module rather than
	# stopping at module boundaries the way go vet and staticcheck do. Scope
	# it to THIS module's package dirs via GO_DIRS.
	go tool gosec $(GO_DIRS)

vuln:
	go mod verify
	go tool govulncheck ./...

secure: lint vuln

# Fail-closed guard for building a tagged release: refuse to proceed unless
# a prepared release modfile exists and contains no local filesystem
# replace directive, then build/test against exactly that modfile.
release-check:
	@test -f "$(RELEASE_MODFILE)" || (echo "$(RELEASE_MODFILE) is not prepared" >&2; exit 1)
	@sh scripts/check-release-modfile.sh "$(RELEASE_MODFILE)"
	$(GO) test -modfile="$(RELEASE_MODFILE)" -race ./...
