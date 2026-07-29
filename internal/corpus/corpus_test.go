package corpus_test

import (
	"sort"
	"testing"

	"github.com/looprig/classifiers/internal/corpus"
	"github.com/looprig/classifiers/internal/policy"
	"github.com/looprig/harness/pkg/gate"
)

// allReviewRisks and allReviewAuthorizations are the closed gate.ReviewRisk
// and gate.ReviewAuthorization domains, enumerated directly (rather than
// derived) so this test does not silently pass if Harness ever adds a new
// value this corpus has not been extended to cover.
var allReviewRisks = []gate.ReviewRisk{
	gate.ReviewRiskLow, gate.ReviewRiskMedium, gate.ReviewRiskHigh, gate.ReviewRiskCritical,
}

var allReviewAuthorizations = []gate.ReviewAuthorization{
	gate.ReviewAuthorizationUnknown, gate.ReviewAuthorizationLow, gate.ReviewAuthorizationMedium, gate.ReviewAuthorizationHigh,
}

// allReviewRiskCategories is the closed 14-member gate.ReviewRiskCategory
// domain (gate.MaxReviewCategories), enumerated directly for the same
// reason.
var allReviewRiskCategories = []gate.ReviewRiskCategory{
	gate.ReviewCategoryDataExfiltration,
	gate.ReviewCategoryCredentialAccess,
	gate.ReviewCategoryCredentialProbing,
	gate.ReviewCategoryDestructiveLocal,
	gate.ReviewCategoryDestructiveShared,
	gate.ReviewCategoryPersistentSecurityWeakening,
	gate.ReviewCategoryProductionMutation,
	gate.ReviewCategoryProtectedSourceControl,
	gate.ReviewCategoryUntrustedCodeExecution,
	gate.ReviewCategoryMutableNetwork,
	gate.ReviewCategoryPromptInjection,
	gate.ReviewCategoryAuthorizationConflict,
	gate.ReviewCategoryTargetAmbiguity,
	gate.ReviewCategoryInsufficientEvidence,
}

func TestAllReviewRiskCategoriesTableIsComplete(t *testing.T) {
	t.Parallel()
	if len(allReviewRiskCategories) != gate.MaxReviewCategories {
		t.Fatalf("allReviewRiskCategories has %d entries, want gate.MaxReviewCategories = %d (this test file's own table is out of date)",
			len(allReviewRiskCategories), gate.MaxReviewCategories)
	}
}

func loadCorpus(t *testing.T) []corpus.Case {
	t.Helper()
	cases, err := corpus.Load()
	if err != nil {
		t.Fatalf("corpus.Load() error = %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("corpus.Load() returned zero cases")
	}
	return cases
}

func TestLoadReturnsOnlyValidatedCases(t *testing.T) {
	t.Parallel()
	cases := loadCorpus(t)
	for _, c := range cases {
		if err := c.Validate(); err != nil {
			t.Errorf("case %q failed Validate() after Load(): %v", c.ID, err)
		}
	}
}

// TestCorpusCoversEveryDesignCategory is the completeness test Task 22 Step 1
// requires: every design §22.6 scenario category must appear on at least one
// case's DesignCategories.
func TestCorpusCoversEveryDesignCategory(t *testing.T) {
	t.Parallel()
	cases := loadCorpus(t)

	seen := make(map[corpus.DesignCategory][]string, len(corpus.AllDesignCategories()))
	for _, c := range cases {
		for _, category := range c.DesignCategories {
			seen[category] = append(seen[category], c.ID)
		}
	}

	var missing []corpus.DesignCategory
	for _, category := range corpus.AllDesignCategories() {
		if len(seen[category]) == 0 {
			missing = append(missing, category)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("corpus is missing design categories: %v", missing)
	}
}

func TestCorpusCoversEveryReviewRisk(t *testing.T) {
	t.Parallel()
	cases := loadCorpus(t)

	seen := make(map[gate.ReviewRisk]int, len(allReviewRisks))
	for _, c := range cases {
		expected, err := c.ParseExpected()
		if err != nil {
			t.Fatalf("case %q: ParseExpected() error = %v", c.ID, err)
		}
		seen[expected.Risk]++
	}
	for _, risk := range allReviewRisks {
		if seen[risk] == 0 {
			t.Errorf("corpus has no case with expected risk %q", risk)
		}
	}
}

func TestCorpusCoversEveryReviewAuthorization(t *testing.T) {
	t.Parallel()
	cases := loadCorpus(t)

	seen := make(map[gate.ReviewAuthorization]int, len(allReviewAuthorizations))
	for _, c := range cases {
		expected, err := c.ParseExpected()
		if err != nil {
			t.Fatalf("case %q: ParseExpected() error = %v", c.ID, err)
		}
		seen[expected.Authorization]++
	}
	for _, authorization := range allReviewAuthorizations {
		if seen[authorization] == 0 {
			t.Errorf("corpus has no case with expected authorization %q", authorization)
		}
	}
}

func TestCorpusCoversEveryReviewRiskCategory(t *testing.T) {
	t.Parallel()
	cases := loadCorpus(t)

	seen := make(map[gate.ReviewRiskCategory]int, len(allReviewRiskCategories))
	for _, c := range cases {
		expected, err := c.ParseExpected()
		if err != nil {
			t.Fatalf("case %q: ParseExpected() error = %v", c.ID, err)
		}
		for _, category := range expected.Categories {
			seen[category]++
		}
	}
	for _, category := range allReviewRiskCategories {
		if seen[category] == 0 {
			t.Errorf("corpus has no case whose expected categories include %q", category)
		}
	}
}

// TestCorpusCoversEveryAbsoluteHumanCategory reads the classifier's own live
// policy.DefaultPolicy rather than a hardcoded copy, so this test cannot
// silently drift from Task 20's actual taxonomy.
func TestCorpusCoversEveryAbsoluteHumanCategory(t *testing.T) {
	t.Parallel()
	cases := loadCorpus(t)

	absolute := policy.DefaultPolicy().AbsoluteHumanCategories
	if len(absolute) == 0 {
		t.Fatal("policy.DefaultPolicy().AbsoluteHumanCategories is empty (nothing to cover)")
	}

	seen := make(map[gate.ReviewRiskCategory]int, len(absolute))
	for _, c := range cases {
		expected, err := c.ParseExpected()
		if err != nil {
			t.Fatalf("case %q: ParseExpected() error = %v", c.ID, err)
		}
		for _, category := range expected.Categories {
			seen[category]++
		}
	}
	for category := range absolute {
		if seen[category] == 0 {
			t.Errorf("corpus has no case whose expected categories include the absolute-human category %q", category)
		}
	}
}

func TestCorpusCoversEvidenceFailure(t *testing.T) {
	t.Parallel()
	requireDesignCategory(t, loadCorpus(t), corpus.DesignEvidenceFailure)
}

func TestCorpusCoversTruncatedMaterialContext(t *testing.T) {
	t.Parallel()
	cases := loadCorpus(t)
	requireDesignCategory(t, cases, corpus.DesignTruncatedMaterialContext)

	// The truncation case must actually force Harness's own
	// gate.BuildReviewContext truncation path, not just carry the design
	// tag, so the resulting subject truly exercises the material-truncation
	// ceiling.
	found := false
	for _, c := range cases {
		if !hasDesignCategory(c, corpus.DesignTruncatedMaterialContext) {
			continue
		}
		if !c.Truncation.Force {
			t.Errorf("case %q is tagged %q but does not set truncation.force", c.ID, corpus.DesignTruncatedMaterialContext)
			continue
		}
		subject, err := c.Subject()
		if err != nil {
			t.Fatalf("case %q: Subject() error = %v", c.ID, err)
		}
		if subject.Context.Truncation.Material == 0 {
			t.Errorf("case %q sets truncation.force but the built subject carries no material truncation", c.ID)
		}
		found = true
	}
	if !found {
		t.Fatal("no case tagged truncated_material_context was found")
	}
}

func TestCorpusCoversEveryInjectionSubtype(t *testing.T) {
	t.Parallel()
	cases := loadCorpus(t)
	for _, category := range []corpus.DesignCategory{
		corpus.DesignInjectionInFile,
		corpus.DesignInjectionInToolResult,
		corpus.DesignInjectionInRepoInstructions,
		corpus.DesignInjectionInCommandArguments,
		corpus.DesignInjectionInFetchedContent,
	} {
		requireDesignCategory(t, cases, category)
	}
}

// TestCorpusCaseIDsAreUnique guards against a silent ID collision across
// testdata files, which corpus.Load already rejects; this test re-derives
// the same invariant from the loaded, sorted result as a second signal.
func TestCorpusCaseIDsAreUnique(t *testing.T) {
	t.Parallel()
	cases := loadCorpus(t)
	ids := make([]string, len(cases))
	for i, c := range cases {
		ids[i] = c.ID
	}
	sorted := append([]string(nil), ids...)
	sort.Strings(sorted)
	for i := 1; i < len(sorted); i++ {
		if sorted[i] == sorted[i-1] {
			t.Fatalf("duplicate corpus case id %q", sorted[i])
		}
	}
}

// TestCorpusHasNoUndocumentedLooserResult enforces Task 22 Step 5's second
// hard gate: every case's Codex parity comparison is one of the two closed
// values (equal or stricter — the type itself has no "looser" value), every
// "stricter" case documents why, and at least one case is genuinely
// stricter than a literal Guardian reading (design §5's match-or-exceed
// premise: if the corpus contained none, that would itself be suspicious).
func TestCorpusHasNoUndocumentedLooserResult(t *testing.T) {
	t.Parallel()
	cases := loadCorpus(t)

	stricterCount := 0
	for _, c := range cases {
		switch c.Parity.Comparison {
		case corpus.ParityEqual:
		case corpus.ParityStricter:
			if c.Parity.Justification == "" {
				t.Errorf("case %q claims %q parity with no justification", c.ID, corpus.ParityStricter)
			}
			stricterCount++
		default:
			t.Errorf("case %q has unsupported codex_parity.comparison %q", c.ID, c.Parity.Comparison)
		}
	}
	if stricterCount == 0 {
		t.Fatal("no corpus case documents a stricter-than-Guardian result; design §5 expects Harness to match or exceed Guardian coverage, so this is suspicious rather than reassuring")
	}
}

func requireDesignCategory(t *testing.T, cases []corpus.Case, category corpus.DesignCategory) {
	t.Helper()
	for _, c := range cases {
		if hasDesignCategory(c, category) {
			return
		}
	}
	t.Errorf("no corpus case is tagged with design category %q", category)
}

func hasDesignCategory(c corpus.Case, category corpus.DesignCategory) bool {
	for _, tagged := range c.DesignCategories {
		if tagged == category {
			return true
		}
	}
	return false
}
