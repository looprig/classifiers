package policy_test

import (
	"testing"

	"github.com/looprig/classifiers/internal/policy"
	"github.com/looprig/harness/pkg/gate"
)

// FuzzReconcile covers design §22.5's "policy matrices": Reconcile is this
// classifier's own deterministic taxonomy matrix (risk floors, absolute
// human categories, minimum authorization by risk), applied to an already
// strictly-decoded gate.PermissionAssessment (as internal/wire produces
// it). It never touches raw JSON, so this fuzzes the closed enum/category
// space directly rather than bytes, checking the invariants Reconcile's own
// doc comment promises: it never lowers risk, never raises authorization,
// never invents or drops a category, and only ever tightens an existing
// allow recommendation to needs_human (never the reverse).
func FuzzReconcile(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint8(0), uint16(0), "")
	f.Add(uint8(3), uint8(3), uint8(0), uint16(0xFFFF), "high risk, high auth, every category")
	f.Add(uint8(2), uint8(0), uint8(0), uint16(1), "medium risk, unknown auth, first category")
	f.Add(uint8(0), uint8(0), uint8(1), uint16(0), "already needs_human, low risk")
	f.Add(uint8(9), uint8(9), uint8(9), uint16(0x2000), "out-of-range enum indices")

	f.Fuzz(func(t *testing.T, riskRaw, authRaw, recommendationRaw uint8, categoryMask uint16, rationale string) {
		subject := newSubject(t)

		risk := allReconcileFuzzRisks[int(riskRaw)%len(allReconcileFuzzRisks)]
		authorization := allReconcileFuzzAuthorizations[int(authRaw)%len(allReconcileFuzzAuthorizations)]
		recommendation := allReconcileFuzzRecommendations[int(recommendationRaw)%len(allReconcileFuzzRecommendations)]

		var categories []gate.ReviewRiskCategory
		for i, category := range allKnownReviewCategories {
			if categoryMask&(1<<uint(i)) != 0 {
				categories = append(categories, category)
			}
		}

		assessment := gate.PermissionAssessment{
			Basis:          subject.Basis,
			Risk:           risk,
			Authorization:  authorization,
			Categories:     categories,
			Recommendation: recommendation,
			Rationale:      rationale,
		}

		got := policy.Reconcile(policy.DefaultPolicy(), assessment)

		if got.Basis != assessment.Basis {
			t.Fatalf("Reconcile() changed Basis: got %#v, want %#v", got.Basis, assessment.Basis)
		}
		if got.Risk != assessment.Risk {
			t.Fatalf("Reconcile() changed Risk: got %q, want %q", got.Risk, assessment.Risk)
		}
		if got.Authorization != assessment.Authorization {
			t.Fatalf("Reconcile() changed Authorization: got %q, want %q", got.Authorization, assessment.Authorization)
		}
		if got.Rationale != assessment.Rationale {
			t.Fatalf("Reconcile() changed Rationale")
		}
		if len(got.Categories) != len(assessment.Categories) {
			t.Fatalf("Reconcile() changed the category set: got %v, want %v", got.Categories, assessment.Categories)
		}
		for i := range got.Categories {
			if got.Categories[i] != assessment.Categories[i] {
				t.Fatalf("Reconcile() reordered or altered categories: got %v, want %v", got.Categories, assessment.Categories)
			}
		}

		if assessment.Recommendation != gate.ReviewAllow {
			if got.Recommendation != assessment.Recommendation {
				t.Fatalf("Reconcile() changed a non-allow recommendation from %q to %q", assessment.Recommendation, got.Recommendation)
			}
			return
		}
		if got.Recommendation != gate.ReviewAllow && got.Recommendation != gate.ReviewNeedsHuman {
			t.Fatalf("Reconcile() produced an unknown recommendation %q", got.Recommendation)
		}
	})
}

var allReconcileFuzzRisks = []gate.ReviewRisk{
	gate.ReviewRiskLow, gate.ReviewRiskMedium, gate.ReviewRiskHigh, gate.ReviewRiskCritical,
}

var allReconcileFuzzAuthorizations = []gate.ReviewAuthorization{
	gate.ReviewAuthorizationUnknown, gate.ReviewAuthorizationLow, gate.ReviewAuthorizationMedium, gate.ReviewAuthorizationHigh,
}

var allReconcileFuzzRecommendations = []gate.ReviewRecommendation{
	gate.ReviewAllow, gate.ReviewNeedsHuman,
}
