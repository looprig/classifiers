# classifiers

`github.com/looprig/classifiers` is the classifier product for
[Harness](https://github.com/looprig/harness)'s permission auto-review
mechanism. It is a separate module from Harness by design: Harness owns the
neutral, mechanism-level permission-review contracts (`pkg/gate`), the
bounded evidence-tool loop (`pkg/hustle`), and the gate lifecycle that races
a classifier verdict against a human response; this module owns the actual
classifiers — their prompts, wire codecs, risk policy, evidence-tool
catalogs, and evaluation corpus.

Harness never imports this module. This module imports Harness's public
contracts. A consumer (for example, Carbon) imports both and explicitly
selects which classifiers to register; zero registered classifiers preserves
Harness's existing gate behavior exactly.

See
[`2026-07-27-permission-classifier-hustle-design.md`](https://github.com/looprig/harness/blob/main/docs/plans/2026-07-27-permission-classifier-hustle-design.md)
(§2, §6.2, §19) for the full design. In short: a classifier result is
evidence, never authority. Only trusted Harness code can turn an eligible
assessment into an ordinary one-shot gate approval; every ambiguous,
invalid, missing, stale, or unknown condition leaves the human gate open.

## Status

The `gate.command-safety` classifier (`pkg/commandsafety`) is built and
covered by a versioned evaluation corpus: it applies to permission gates
whose prepared request contains a command-execution requirement (a later
increment extends applicability to the fuller command-triggered
filesystem/network combination). Construct it with `commandsafety.New`,
register it with a consuming rig via `rig.WithPermissionClassifiers`
(`github.com/looprig/harness/pkg/rig`) — see
[`github.com/looprig/carbon`'s `internal/app/permission_review.go`](https://github.com/looprig/carbon/blob/main/internal/app/permission_review.go)
for a complete, real composition. `pkg/catalog` is an optional convenience
catalog over the classifiers this module defines; it never performs implicit
global registration.

### Enable/disable

This module never enables itself. A classifier only ever reviews a gate once
a consumer explicitly constructs it and registers it via
`rig.WithPermissionClassifiers` — zero registered classifiers preserves
Harness's plain gate behavior exactly. There is no model-facing toggle and no
global registry.

### Model capability requirements

`commandsafety.New` requires a structurally valid `model.Model` that
additionally advertises `Caps.Tools`, `Caps.StructuredOutput`, and
`Caps.StructuredOutputWithTools` all true (design §12.3) — the classifier's
own evidence-gathering tool-use loop needs all three. `New` rejects
construction with a typed `*commandsafety.ConstructionError{Field:
commandsafety.FieldModelCapabilities}` rather than degrading to a text-only
prompt.

### Evidence boundaries

`commandsafety.StandardEvidence(ReadEvidencePolicy{...})` builds this
classifier's complete read-only evidence-tool catalog (canonical path
resolution, metadata, bounded directory listing/file reading/glob/grep, and
Git repository/status/remote evidence — design §13.2). The classifier itself
never decides what access or containment those tools get at runtime: that
authorization boundary is entirely consumer-supplied, via Harness's
`rig.WithPermissionReviewEvidence(access, containment, allowedKinds)`. This
module's job ends at declaring which `tool.Requirement.Kind` values its
evidence tools use — `commandsafety.RequiredEvidenceKinds()` reports them
so a consumer's `allowedKinds` allowlist never has to be hand-copied out of
sync.

### Human fallback

A command-safety review can only ever produce one of: an eligible `allowed`
assessment (which Harness may turn into a single one-shot gate approval,
subject to the consumer's own `gate.PermissionReviewPolicy`), or
`needs_human`. This module never denies a tool call, never persists a rule,
and never widens a security ceiling — every non-eligible result, evidence
failure, capability mismatch, or classifier error leaves Harness's ordinary
human gate exactly as open as it would be with no classifier registered at
all.

### Audit and privacy

This module never sees or produces a durable audit record — `pkg/event`'s
`PermissionReviewStarted`/`PermissionReviewCompleted` are Harness's own,
secret-free, internal-visibility events (see
[`harness/pkg/gate/README.md#permission-review`](https://github.com/looprig/harness/blob/main/pkg/gate/README.md#permission-review)).
Internally, prompts, wire input/output, and rationale never cross this
module's public boundary: `ValidateResult` returns only a strict
`gate.PermissionAssessment` (risk, authorization, categories, recommendation,
a bounded rationale meant only for an ephemeral diagnostic, never durable
storage).

### Policy tuning

`commandsafety.DefaultPolicy()` is this classifier's own deterministic
risk/authorization/category taxonomy (`internal/policy`), reconciled against
a decoded model assessment before it ever leaves this module
(`policy.Reconcile` — see `ValidateResult`'s doc comment: reconciliation only
ever tightens, never loosens, a reported result). This is a separate tuning
axis from Harness's own consumer-owned `gate.PermissionReviewPolicy`
(`rig.WithPermissionReviewPolicy`): this module's policy governs what a
single classifier internally reconciles its own output to; Harness's policy
governs whether a validated assessment is allowed to become an auto-approval
at all. Carbon's `permissionReviewPolicyFor` is a real example of composing
a stricter Harness-side policy on top of this classifier's own default.

### Restore behavior

This module holds no session state and is never itself restored — Harness
owns restore semantics entirely (rig/gate fingerprint, the
disabled→enabled `DriftWarn` rule, and hustle-not-restored behavior). See
[`harness/pkg/gate/README.md#restore-behavior`](https://github.com/looprig/harness/blob/main/pkg/gate/README.md#restore-behavior).
A classifier's own identity (name, revision, definition descriptor) is what
Harness folds into that fingerprint, so changing this module's prompt,
policy, or evidence catalog is what makes a restore see this classifier as a
different one.

### Evaluation workflow

See [`docs/evaluations/`](docs/evaluations/) for the corpus format, coverage
requirements, and evaluation-report shape (design §22.6/§22.7); it documents
`commandsafety.Evaluate`, the deterministic evaluation runner, in detail and
should be extended, not duplicated, when this classifier's corpus or policy
changes.

## Layout

```text
classifiers/
    go.mod
    LICENSE
    README.md
    CONTRIBUTING.md
    docs/
        plans/
        evaluations/
    pkg/
        commandsafety/   # public construction API for gate.command-safety
        catalog/         # optional convenience catalog, no implicit registration
    internal/
        prompt/          # immutable classifier prompt
        wire/             # strict JSON codecs for classifier input/output
        policy/          # deterministic risk/authorization policy
        corpus/          # versioned evaluation corpus
        testmodel/       # fake inference client for tests
```

Only `pkg/` is public API. Everything else, including prompts, codecs,
policy tables, and fixtures, is `internal/`. The module root has no Go
source files; `internal/buildtest` enforces this and related structural
invariants (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).

## Build and test

This module vendors its dependency tree.

```sh
make test      # go test -race ./...
make vendor    # refresh vendor/, scrub local-replace VCS metadata, verify clean
```
