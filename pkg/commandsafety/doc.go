// Package commandsafety will provide the public construction API for the
// initial gate.command-safety permission classifier described in
// docs/plans/2026-07-27-permission-classifier-hustle-design.md §19.
//
// The classifier reviews permission gates whose prepared request contains
// command execution or a command-triggered combination of filesystem and
// network requirements. It owns the classifier's prompt, wire codecs, risk
// policy, and evidence-tool catalog, and returns a value that satisfies
// Harness's public gate.PermissionClassifier contract. A classifier result
// is evidence, never authority: only trusted Harness code can turn an
// eligible assessment into an ordinary gate approval.
//
// This package is currently a scaffold with no exported API. A later task
// adds the Options type, the New constructor, the default policy, and the
// evidence-tool catalog.
package commandsafety
