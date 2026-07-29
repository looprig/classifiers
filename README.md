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
contracts. A consumer (for example, CodeRig) imports both and explicitly
selects which classifiers to register; zero registered classifiers preserves
Harness's existing gate behavior exactly.

See
[`2026-07-27-permission-classifier-hustle-design.md`](https://github.com/looprig/harness/blob/main/docs/plans/2026-07-27-permission-classifier-hustle-design.md)
(§2, §6.2, §19) for the full design. In short: a classifier result is
evidence, never authority. Only trusted Harness code can turn an eligible
assessment into an ordinary one-shot gate approval; every ambiguous,
invalid, missing, stale, or unknown condition leaves the human gate open.

## Status

This repository is a scaffold. The initial product is the
`gate.command-safety` classifier in `pkg/commandsafety`, which will apply to
permission gates whose prepared request contains command execution or a
command-triggered combination of filesystem and network requirements.
`pkg/catalog` will be an optional convenience catalog over the classifiers
this module defines; it never performs implicit global registration.

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
