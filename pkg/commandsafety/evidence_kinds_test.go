package commandsafety_test

import (
	"testing"

	"github.com/looprig/classifiers/pkg/commandsafety"
	"github.com/looprig/harness/pkg/tool"
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

// TestBehavior_ClassifierEvidenceDefinitions_SatisfyHarnessEvidenceKindDeclarer
// proves the evidence-tool definitions bound to the classifier commandsafety.New
// returns genuinely satisfy Harness's optional tool.EvidenceKindDeclarer
// capability, and that each one's declared kinds match
// RequiredEvidenceKinds() by set equality — not merely that
// RequiredEvidenceKinds() itself is derived correctly (already covered
// above), but that the construction-time fail-fast check Harness's
// internal/hustleruntime.validateEvidenceAllowedKinds performs against a
// registered classifier's evidence-tool definitions is not a silent no-op
// for the one real classifier definition this module builds.
func TestBehavior_ClassifierEvidenceDefinitions_SatisfyHarnessEvidenceKindDeclarer(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	policy, enabled := classifier.Definition().EvidenceToolPolicy()
	if !enabled {
		t.Fatal("Definition().EvidenceToolPolicy() enabled = false, want true")
	}
	if len(policy.Definitions) == 0 {
		t.Fatal("Definition().EvidenceToolPolicy() Definitions is empty")
	}

	want := commandsafety.RequiredEvidenceKinds()
	for _, def := range policy.Definitions {
		declarer, ok := def.(tool.EvidenceKindDeclarer)
		if !ok {
			t.Fatalf("%s: evidence-tool definition does not implement tool.EvidenceKindDeclarer", def.Name())
		}
		got := declarer.EvidenceRequirementKinds()
		if len(got) != len(want) {
			t.Fatalf("%s: EvidenceRequirementKinds() = %v, want %v", def.Name(), got, want)
		}
		wantSet := make(map[string]struct{}, len(want))
		for _, k := range want {
			wantSet[k] = struct{}{}
		}
		for _, k := range got {
			if _, ok := wantSet[k]; !ok {
				t.Fatalf("%s: EvidenceRequirementKinds() = %v, want %v", def.Name(), got, want)
			}
		}
	}
}
