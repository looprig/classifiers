# Contributing to looprig/classifiers

Thanks for considering a contribution. `classifiers` is the classifier
product for Harness's permission auto-review mechanism, part of a
multi-module Go ecosystem. This file is the short guide for working in
*this* repository.

## Before you write code

1. Read the design and implementation plan in the `harness` repository
   (`docs/plans/2026-07-27-permission-classifier-hustle-design.md` and its
   paired `-implementation.md`). This module implements the Phase 5 slice of
   that plan.
2. Open an issue for anything non-trivial so we can agree on direction
   before you spend the time.

## Structural rules this repository enforces

`internal/buildtest` runs as part of every test suite and asserts:

- the module root has **no** `.go` files;
- the module path is exactly `github.com/looprig/classifiers`;
- all Go source lives under `pkg/` (public construction API) or `internal/`
  (everything else — prompts, codecs, policy, evidence, corpus, fixtures);
- no package imports a Harness `internal/...` package (only Harness's public
  packages are importable);
- no module-internal import cycle; and
- `scripts/check-release-modfile.sh` rejects every local filesystem
  `replace` directive (relative path, absolute path, `file://` URL, or an
  unversioned bare target) in a simulated release modfile, so a tagged
  release build can never pick up a developer's local sibling checkout.

A change that violates any of these fails `make test` immediately; fix the
layout rather than the test.

## Design and security rules (the short version)

- **Classifier output is evidence, never authority.** This module never
  persists a rule, mints a grant, denies a tool call, closes a gate, or
  widens a security ceiling. Those are Harness's job.
- **Strict typing everywhere.** No `any`/`interface{}` except at explicit
  serialization boundaries, narrowed immediately. Named types over bare
  primitives when a value carries domain meaning.
- **All errors are typed.** Callers classify with `errors.As`, never by
  string matching. Never swallow an error with `_`.
- **Fail secure.** Missing evidence, an ambiguous result, or an unknown
  condition must never widen eligibility. On error or ambiguity, leave
  review to the human gate.
- **Prompts, policy text, and evidence stay internal.** Only the strict
  typed assessment and locally recomputed decision cross this module's
  public boundary; raw model input/output/reasoning is not durable product
  data.
- **Prefer stdlib.** External packages require explicit approval in the
  conversation that adds them before `go get` is run.

## Build, test, and secure

This module **vendors** its dependency tree.

```sh
make fmt         # gofmt the whole module in place
make fmt-check   # fail if any tracked Go file is not gofmt-clean
make test        # go test -race ./...            (always -race)
make vendor      # refresh vendor/, scrub local-replace VCS metadata, verify clean
make release-check RELEASE_MODFILE=go.release.mod  # guard + build against a tagged release modfile
```

Integration tests, once added, are tagged `//go:build integration` and run
explicitly: `go test -tags integration -race ./...`. Fuzz any parser of
external input: `go test -fuzz=FuzzXxx ./pkg -fuzztime=30s`.

## Tests

- **Test-driven development is mandatory**: write one focused failing test,
  watch it fail for the expected reason, implement the minimum to pass, then
  run the owning package suite.
- **Table-driven tests** when several cases share setup and assertion shape.
  Each subtest calls `t.Parallel()`. Cover the happy path, boundary values,
  error cases, and domain edge cases.
- A test that passes without `-race` but fails with it is **not passing**.

## Pull requests

- Branch from `main`, name the branch something descriptive.
- One logical change per PR.
- Write a clear description: what, why, and how you verified.
- Don't commit secrets, tokens, or credentials. Don't add a new external
  dependency without prior approval.

## License

By contributing, you agree that your contributions are licensed under the
Apache License 2.0, as described in [`LICENSE`](LICENSE).
