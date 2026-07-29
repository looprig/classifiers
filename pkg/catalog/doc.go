// Package catalog will provide an optional convenience catalog of the
// classifiers defined in this module, as described in
// docs/plans/2026-07-27-permission-classifier-hustle-design.md §6.2.
//
// The catalog never performs implicit global registration: a consumer must
// explicitly select and construct every classifier it registers with its
// Harness rig. This package exists only to make discovering and
// constructing the available classifiers together more convenient when a
// consumer wants that convenience.
//
// This package is currently a scaffold with no exported API. A later task
// adds catalog construction helpers once pkg/commandsafety has a
// constructible classifier.
package catalog
