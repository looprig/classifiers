# Command-safety evaluation corpus and runner

This directory documents the `gate.command-safety` classifier's Codex-parity
evaluation corpus (`internal/corpus`) and its deterministic evaluation runner
(`pkg/commandsafety` — `Evaluate`, `EvaluationCase`, `Report`), per design
§22.6 ("Classifier corpus") and §22.7 ("Evaluation reports").

## What the corpus is

`internal/corpus` holds a versioned set of independently worded synthetic
scenarios (`internal/corpus/testdata/*.json`), one JSON array per theme file.
Each case (`corpus.Case`) carries:

- a synthetic, self-contained scenario (`request` + `context_entries`),
  built into a real, digest-stamped `gate.PermissionReviewSubject` by
  `Case.Subject()` — always through Harness's own
  `gate.BuildReviewContext`/`gate.NewPermissionReviewSubject`, never a
  hand-rolled reimplementation of their invariants;
- the assessment a **correct** classifier should produce for that scenario
  (`expected`: risk, authorization, categories, recommendation, rationale);
- the end-to-end auto-approval eligibility that assessment implies
  (`expected_eligible`), which is not hand-asserted: `evaluation_test.go`'s
  `TestEvaluateCorpusMatchesRealPipeline` recomputes it by actually running
  the case through the classifier's real `MarshalInput`/`ValidateResult`
  pipeline and Harness's real `gate.EvaluatePermissionAssessment`, and fails
  the build if the fixture's `expected_eligible` disagrees;
- a Codex parity record (`codex_parity`): which Guardian scenario or category
  the case corresponds to (in the corpus author's own words — Codex source
  and fixture text are never copied verbatim), and whether this classifier's
  expected result is `equal` to or `stricter` than that Guardian scenario.
  **There is no "looser" value** — `corpus.CodexParityComparison` is a closed
  two-member type, so an undocumented looser result is unrepresentable, not
  merely disallowed by convention.

Coverage is enforced, not aspirational: `internal/corpus/corpus_test.go`
fails the build unless the loaded corpus contains at least one case for
every design §22.6 category (`corpus.AllDesignCategories()`), every
`gate.ReviewRisk` value, every `gate.ReviewAuthorization` value, every one of
the 14 `gate.ReviewRiskCategory` values, every category in the classifier's
own `policy.DefaultPolicy().AbsoluteHumanCategories` (read live from
`internal/policy`, not duplicated), an evidence-failure case, a
truncated-material-context case (one that actually forces Harness's own
`gate.BuildReviewContext` truncation path, verified by inspecting the built
subject's `Context.Truncation.Material`), and all five prompt-injection
subtypes (in a file, in a tool result, in repository instructions, in
command arguments, and in fetched content).

"Basis mismatch" is exercised at the runner boundary instead
(`pkg/commandsafety/evaluation_test.go`'s `TestEvaluateRejectsMismatchedBasis`):
a model response echoing a different subject's basis than the one under
review must be rejected by the real classifier pipeline and reported as a
bounded per-case failure, never silently scored as eligible or ineligible.

## What the runner is

`commandsafety.Evaluate` is deterministic: it never calls a real model. Each
`EvaluationCase` carries its own `Respond` (`ModelResponder`) — a function
returning a pre-baked structured-output payload for its subject, typically
built with `commandsafety.EncodeAssessmentAsModelOutput`. `Evaluate` runs
every case through the classifier's real `MarshalInput` → `Respond` →
`ValidateResult` → `gate.EvaluatePermissionAssessment` pipeline (exercising
`internal/wire`'s codecs and `internal/policy.Reconcile` for real, exactly as
a live review would) and aggregates a `Report`:

- a confusion matrix over auto-approval eligibility (`TrueAllow`/`TrueHuman`/
  `FalseAllow`/`FalseHuman`);
- breakdowns by risk and by authorization;
- `CriticalFalseAllows` and `HighRiskFalseAllows`, called out from the
  confusion matrix specifically because they are safety-relevant;
- `BenignSentToHuman` (a design-smell signal, not a safety failure);
- `Mismatches` (cases whose fixture `expected_eligible` disagreed with the
  real pipeline) and `Failures` (cases that could not be evaluated at all —
  a bounded reason only, never raw error text, so a corrupted or hostile
  fixture/response can never leak content through a report);
- classifier/model identity and the corpus revision under evaluation;
- `ToolEvidenceUsage`/`LatencyTokenUsage`, always reported as "not
  applicable" today: this mode never runs the evidence-tool loop or a live
  model call. A future live-evaluation mode (a `ModelResponder` backed by a
  real classifier connection instead of a synthetic closure) would populate
  these for real without changing `Report`'s shape.

`Report` never carries scenario description or rationale text in its
aggregate fields — only case IDs, risk/authorization buckets, and booleans —
so a report stays safe to share even though every fixture in this corpus is
already synthetic and non-sensitive by construction.

## Running the evaluation

```bash
GOCACHE=/private/tmp/looprig-classifiers-go-cache GOFLAGS=-mod=vendor \
  go test -race ./internal/corpus/... ./pkg/commandsafety/...
```

This runs both the corpus completeness tests and the deterministic
evaluation tests, including the two hard gates below. There is currently no
separate CLI entry point for producing a report outside of a test; the
`TestEvaluateCorpusMatchesRealPipeline`/`TestEvaluateReportsClassifierIdentity`
tests in `pkg/commandsafety/evaluation_test.go` show the exact call shape
(`commandsafety.Evaluate(classifier, cases, commandsafety.EvaluationOptions{...})`)
a future report-generation command would reuse unchanged.

## Adding a new case

1. Pick (or add, if genuinely missing) a `corpus.DesignCategory` in
   `internal/corpus/case.go`.
2. Add a case object to the most relevant `testdata/*.json` file (or a new
   file — the loader globs `testdata/*.json`). Write the scenario, command,
   and context in your own words; do not copy Codex source or fixture text.
3. Fill in `expected` with what a *correct* classifier should produce, and
   `codex_parity` with the corresponding Guardian scenario/category in your
   own words plus `equal` or `stricter` (never claim looser — the type does
   not allow it).
4. Run the test commands above. `TestEvaluateCorpusMatchesRealPipeline` will
   fail if `expected_eligible` does not match what the real pipeline
   computes from `expected`; fix the mismatch by correcting either the case
   or (if it reveals an actual bug) the underlying policy/wire code.
5. If the change is more than a typo fix — a new case, a changed expected
   result, or a changed parity record — bump `corpus.Revision` in
   `internal/corpus/case.go` and record the change in a new
   `docs/evaluations/<revision>.md` report (see `baseline.md` for the
   shape), noting every changed result from the previously accepted
   revision (design §22.7's last bullet).

## Why "stricter" is recorded, and why looser is never accepted silently

Design §5's premise is that Harness matches or exceeds Codex Guardian's
behavioral and safety coverage. Most cases in this corpus are `equal`: the
classifier's expected result matches a straightforward reading of the
corresponding Guardian scenario. A smaller set of cases are `stricter` —
where a *structural* Harness rule (critical risk is always absolute-human
regardless of authorization; `data_exfiltration` and `prompt_injection` are
absolute-human categories no authorization level can override; material
context truncation always blocks auto-approval regardless of the model's own
risk judgment) produces a result a narrower, more situational Guardian rule
might not force in every instance. Each `stricter` case documents, in its own
`justification` field, *why* it is stricter — never asserting specifics about
Guardian's actual implementation beyond general policy-taxonomy knowledge.

There is no `looser` value in `corpus.CodexParityComparison`, so a case
cannot even be authored claiming one. `TestCorpusHasNoUndocumentedLooserResult`
additionally fails the build if any case's `codex_parity.comparison` is
anything other than `equal`/`stricter`, if a `stricter` case has no
justification, or if the corpus contains *zero* stricter cases at all (per
the reasoning above, that absence would itself be suspicious, not
reassuring).
