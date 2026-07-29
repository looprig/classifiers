package commandsafety_test

import (
	"testing"

	"github.com/looprig/classifiers/pkg/commandsafety"
)

// wantRequiredEvidenceKinds independently enumerates internal/evidence's six
// declared Requirement.Kind string VALUES (not the exported Go constants —
// this test deliberately hard-codes the literal strings so it also catches
// a value being silently changed, not just a constant being removed). This
// is the one place a manual list is acceptable: it asserts the production
// code's derived list is complete, not the other way around.
func wantRequiredEvidenceKinds() []string {
	return []string{
		"evidence.filesystem.stat",
		"evidence.filesystem.list",
		"evidence.filesystem.read",
		"evidence.filesystem.glob",
		"evidence.filesystem.grep",
		"evidence.git.read",
	}
}

// TestBehavior_RequiredEvidenceKinds_MatchesEvidencePackageKinds proves
// RequiredEvidenceKinds() returns exactly the set of Requirement.Kind
// values internal/evidence's evidence tools declare, by set equality (order
// is not guaranteed).
func TestBehavior_RequiredEvidenceKinds_MatchesEvidencePackageKinds(t *testing.T) {
	t.Parallel()
	got := commandsafety.RequiredEvidenceKinds()
	want := wantRequiredEvidenceKinds()

	if len(got) != len(want) {
		t.Fatalf("RequiredEvidenceKinds() = %v, want %v", got, want)
	}
	wantSet := make(map[string]struct{}, len(want))
	for _, k := range want {
		wantSet[k] = struct{}{}
	}
	for _, k := range got {
		if _, ok := wantSet[k]; !ok {
			t.Fatalf("RequiredEvidenceKinds() = %v, want %v", got, want)
		}
	}
}

// TestBehavior_RequiredEvidenceKinds_ReturnsDefensiveCopy proves mutating
// one call's returned slice cannot affect a later call's result.
func TestBehavior_RequiredEvidenceKinds_ReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()
	first := commandsafety.RequiredEvidenceKinds()
	for i := range first {
		first[i] = "mutated"
	}
	second := commandsafety.RequiredEvidenceKinds()
	for _, kind := range second {
		if kind == "mutated" {
			t.Fatalf("RequiredEvidenceKinds() second call = %v, want unaffected by mutation of first call's result", second)
		}
	}
}
