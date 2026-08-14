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
  widens a security ceiling. Those are Harness's job. Concretely: every
  outcome besides a validated `allowed` assessment (which Harness's own
  `gate.PermissionReviewPolicy` may then, separately, turn into a one-shot
  approval) leaves the ordinary human gate exactly as open as it always was.
- **A classifier's model must support tool use with structured output.**
  `commandsafety.New` requires `Caps.Tools`, `Caps.StructuredOutput`, and
  `Caps.StructuredOutputWithTools` together and fails construction
  (`ConstructionError{Field: FieldModelCapabilities}`) rather than silently
  degrading to a text-only prompt if a contributed model binding lacks one.
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
  data. This module produces no durable audit record itself — Harness's
  `PermissionReviewStarted`/`PermissionReviewCompleted` events are the audit
  trail, and they are internal-visibility and redacted by construction (see
  the harness `pkg/gate/README.md`'s "Audit and privacy" section).
- **A new or changed evidence tool declares its `Requirement.Kind`s through
  `internal/evidence.RequirementKinds`**, never a hand-copied string
  elsewhere — `pkg/commandsafety.RequiredEvidenceKinds()` is the one public
  pass-through a consumer's `rig.WithPermissionReviewEvidence` allowlist
  relies on staying in sync.
- **Prefer stdlib.** External packages require explicit approval in the
  conversation that adds them before `go get` is run.

## Contributing an evaluation corpus change

A new or changed corpus case, expected result, or Codex-parity record is
more than a typo fix and needs its own workflow — see
[`docs/evaluations/README.md`](docs/evaluations/README.md) ("Adding a new
case") for the full steps: pick or add a `corpus.DesignCategory`, write the
case in your own words (never copy Codex/Guardian source or fixture text),
fill in `expected`/`codex_parity`, run
`TestEvaluateCorpusMatchesRealPipeline` to prove `expected_eligible` matches
what the real pipeline computes, bump `corpus.Revision`, and record a new
`docs/evaluations/<revision>.md` report noting every changed result from the
previously accepted revision.

## Build, test, and secure

**Dependencies are pinned, not vendored.** `go.mod` pins exact versions and
`go.sum` verifies their content hashes, which is what makes a build
reproducible. This module deliberately has no `vendor/`: a vendor tree is
ignored under a `go.work` but silently satisfies a `GOWORK=off` build, so a
stale one lets standalone verification pass against the vendored copy rather
than the version `go.mod` actually pins — defeating the purpose of verifying
standalone. Run `GOWORK=off go test ./...` to check this module against its
real pinned dependencies.

```sh
make fmt         # gofmt the whole module in place
make fmt-check   # fail if any tracked Go file is not gofmt-clean
make test        # go test -race ./...            (always -race)
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
