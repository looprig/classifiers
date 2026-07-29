// Package commandsafety provides the public construction API for the
// initial gate.command-safety permission classifier described in
// docs/plans/2026-07-27-permission-classifier-hustle-design.md §19.
//
// The classifier reviews permission gates whose prepared request contains
// command execution or a command-triggered combination of filesystem and
// network requirements. It owns the classifier's prompt, wire codecs, risk
// policy, and evidence-tool catalog, and New returns a value that satisfies
// Harness's public gate.PermissionClassifier contract. A classifier result
// is evidence, never authority: only trusted Harness code can turn an
// eligible assessment into an ordinary gate approval.
//
// Today Policy and StandardEvidence's applicability predicate and risk
// matrix are minimal placeholders (a stable revision label and one
// read-only no-op evidence tool, respectively); a later task fills in the
// deterministic Codex-parity policy and the real filesystem/repository
// evidence-tool catalog without changing this package's construction
// shape.
package commandsafety
