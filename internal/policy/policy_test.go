package policy_test

import (
	"testing"

	"github.com/looprig/classifiers/internal/policy"
	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/gate"
	"github.com/looprig/harness/pkg/identity"
	"github.com/looprig/harness/pkg/tool"
)

// newSubject builds one internally consistent, digest-stamped subject every
// test in this file shares. The taxonomy branches under test depend only on
// the assessment values fed through Reconcile, never on the subject's own
// request shape, so a single fixture subject is sufficient.
func newSubject(t *testing.T) gate.PermissionReviewSubject {
	t.Helper()

	toolExecutionID := uuid.MustParse("223e4567-e89b-12d3-a456-426614174110")
	reviewContext := gate.ReviewContext{
		Coordinates: identity.Coordinates{
			SessionID: uuid.MustParse("223e4567-e89b-12d3-a456-426614174101"),
			LoopID:    uuid.MustParse("223e4567-e89b-12d3-a456-426614174102"),
			TurnID:    uuid.MustParse("223e4567-e89b-12d3-a456-426614174103"),
			StepID:    uuid.MustParse("223e4567-e89b-12d3-a456-426614174104"),
		},
		ContextRevision:    "policy-context-v1",
		WorkspaceRoot:      "/workspace",
		WorkingDirectory:   "/workspace/repo",
		SecurityCeiling:    "workspace-write",
		GatePolicyRevision: "policy-gate-policy-v1",
		Entries: []gate.ReviewContextEntry{
			{Origin: gate.ReviewContextOriginUser, Kind: gate.ReviewContextKindUserMessage, Content: "do the requested task"},
			{Origin: gate.ReviewContextOriginAssistant, Kind: gate.ReviewContextKindAssistantToolRequest, Content: `{"command":"the requested command"}`},
		},
	}
	request := tool.Request{
		ToolName:           "Bash",
		Summary:            "run the requested command",
		ExecutionID:        toolExecutionID.String(),
		Command:            "the requested command",
		WorkingDirectory:   "/workspace/repo",
		ExpiresAtUnixMilli: 1800000000000,
		Requirements: []tool.Requirement{{
			Kind:        tool.CapabilityCommandExecute,
			Match:       "the requested command",
			Description: "run the requested command",
			GrantClass:  tool.GrantClassCommandStart,
			GrantTarget: "the requested command",
		}},
	}
	basis := gate.ReviewBasis{
		GateID:             uuid.MustParse("223e4567-e89b-12d3-a456-426614174109"),
		ToolExecutionID:    toolExecutionID,
		ContextRevision:    reviewContext.ContextRevision,
		GatePolicyRevision: reviewContext.GatePolicyRevision,
		ClassifierRevision: "command-safety-policy-test-v1",
		SecurityCeiling:    reviewContext.SecurityCeiling,
	}
	subject, err := gate.NewPermissionReviewSubject(basis, request, reviewContext)
	if err != nil {
		t.Fatalf("gate.NewPermissionReviewSubject() error = %v", err)
	}
	return subject
}

// eligible reconciles a synthetic model assessment (as ValidateResult would,
// after internal/wire has already decoded it) against p, then asks the REAL,
// unmodified Harness gate.EvaluatePermissionAssessment for the end-to-end
// one-shot eligibility a consumer would actually observe.
func eligible(
	t *testing.T,
	p policy.Policy,
	subject gate.PermissionReviewSubject,
	risk gate.ReviewRisk,
	authorization gate.ReviewAuthorization,
	categories []gate.ReviewRiskCategory,
) bool {
	t.Helper()

	assessment := gate.PermissionAssessment{
		Basis:          subject.Basis,
		Risk:           risk,
		Authorization:  authorization,
		Categories:     categories,
		Recommendation: gate.ReviewAllow,
		Rationale:      "synthetic fixture rationale for one hand-picked taxonomy branch",
	}
	reconciled := policy.Reconcile(p, assessment)

	harnessPolicy, err := gate.DefaultPermissionReviewPolicy(subject.Basis.GatePolicyRevision)
	if err != nil {
		t.Fatalf("gate.DefaultPermissionReviewPolicy() error = %v", err)
	}
	decision := gate.EvaluatePermissionAssessment(harnessPolicy, subject, reconciled)
	return decision.Eligible
}

func TestReconcileDataExfiltration(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		categories    []gate.ReviewRiskCategory
		wantEligible  bool
	}{
		{
			name:          "a plain internal-destination action carries no exfiltration category and stays eligible",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    nil,
			wantEligible:  true,
		},
		{
			name:          "confirmed disclosure of secrets to an untrusted destination is blocked even at critical risk",
			risk:          gate.ReviewRiskCritical,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryDataExfiltration},
			wantEligible:  false,
		},
		{
			name:          "confirmed disclosure stays blocked at merely high risk despite high authorization",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryDataExfiltration},
			wantEligible:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, tt.categories)
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

func TestReconcileCredentialProbingAndUse(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		categories    []gate.ReviewRiskCategory
		wantEligible  bool
	}{
		{
			name:          "extracting credentials from an unrelated source with no authorization evidence stays human",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryCredentialProbing},
			wantEligible:  false,
		},
		{
			name:          "the same probing becomes eligible once authorization reaches medium",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationMedium,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryCredentialProbing},
			wantEligible:  true,
		},
		{
			name:          "authenticating a requested action with an already-available credential stays eligible at low risk",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryCredentialAccess},
			wantEligible:  true,
		},
		{
			name:          "reporting probing at low risk is an internally inconsistent understatement and stays human",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryCredentialProbing},
			wantEligible:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, tt.categories)
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

func TestReconcilePersistentSecurityWeakening(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		categories    []gate.ReviewRiskCategory
		wantEligible  bool
	}{
		{
			name:          "a narrow, task-bounded control disablement at medium risk is eligible without special authorization",
			risk:          gate.ReviewRiskMedium,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryPersistentSecurityWeakening},
			wantEligible:  true,
		},
		{
			name:          "an indefinite, wide-blast-radius disablement at critical risk always needs a human",
			risk:          gate.ReviewRiskCritical,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryPersistentSecurityWeakening},
			wantEligible:  false,
		},
		{
			name:          "reporting a flagged weakening at low risk is an inconsistent understatement and stays human",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryPersistentSecurityWeakening},
			wantEligible:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, tt.categories)
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

func TestReconcileDestructiveActions(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		categories    []gate.ReviewRiskCategory
		wantEligible  bool
	}{
		{
			name:          "a single local file rewrite at medium risk is eligible with no special authorization",
			risk:          gate.ReviewRiskMedium,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryDestructiveLocal},
			wantEligible:  true,
		},
		{
			name:          "a shared-state destructive action with no authorization evidence stays human",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryDestructiveShared},
			wantEligible:  false,
		},
		{
			name:          "the same shared-state action becomes eligible once authorization names it",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationMedium,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryDestructiveShared},
			wantEligible:  true,
		},
		{
			name:          "an unrecoverable destructive action at critical risk always needs a human",
			risk:          gate.ReviewRiskCritical,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryDestructiveShared},
			wantEligible:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, tt.categories)
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

func TestReconcileGitAndSourceControl(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		categories    []gate.ReviewRiskCategory
		wantEligible  bool
	}{
		{
			name:          "pushing to one verified user-owned feature branch is only medium and stays eligible",
			risk:          gate.ReviewRiskMedium,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryProtectedSourceControl},
			wantEligible:  true,
		},
		{
			name:          "a force push to the protected default branch with no authorization evidence stays human",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryProtectedSourceControl},
			wantEligible:  false,
		},
		{
			name:          "the same protected-branch push becomes eligible once the user names it",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationMedium,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryProtectedSourceControl},
			wantEligible:  true,
		},
		{
			name:          "deleting the protected branch's history outright is critical and always needs a human",
			risk:          gate.ReviewRiskCritical,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryProtectedSourceControl},
			wantEligible:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, tt.categories)
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

func TestReconcileLowRiskActions(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		categories    []gate.ReviewRiskCategory
		wantEligible  bool
	}{
		{
			name:          "retrying inside a sandbox after an initial denial is not itself suspicious",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    nil,
			wantEligible:  true,
		},
		{
			name:          "a narrow user-requested cleanup stays eligible even with only weak authorization",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationLow,
			categories:    nil,
			wantEligible:  true,
		},
		{
			name:          "deleting a path a read-only check confirmed is empty and narrowly scoped is only medium and eligible",
			risk:          gate.ReviewRiskMedium,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryDestructiveLocal},
			wantEligible:  true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, tt.categories)
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

func TestReconcileProductionAndSharedState(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		categories    []gate.ReviewRiskCategory
		wantEligible  bool
	}{
		{
			name:          "a change confined to the individual's own local machine stays low risk and eligible",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    nil,
			wantEligible:  true,
		},
		{
			name:          "mutating a production or shared environment with no authorization evidence stays human",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationUnknown,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryProductionMutation},
			wantEligible:  false,
		},
		{
			name:          "the same production mutation becomes eligible once authorization names it",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationMedium,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryProductionMutation},
			wantEligible:  true,
		},
		{
			name:          "reporting a production mutation at low risk is an inconsistent understatement and stays human",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryProductionMutation},
			wantEligible:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, tt.categories)
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

func TestReconcilePromptInjection(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		categories    []gate.ReviewRiskCategory
		wantEligible  bool
	}{
		{
			name:          "ordinary evidence with no embedded instruction stays eligible",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    nil,
			wantEligible:  true,
		},
		{
			name:          "text embedded in a tool result that tries to redefine the review always needs a human",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryPromptInjection},
			wantEligible:  false,
		},
		{
			name:          "an injected instruction paired with a high intrinsic risk still always needs a human",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryPromptInjection},
			wantEligible:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, tt.categories)
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

func TestReconcileUserAuthorizationScoring(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		wantEligible  bool
	}{
		{
			name:          "low risk needs no authorization evidence at all",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationUnknown,
			wantEligible:  true,
		},
		{
			name:          "medium risk needs no authorization evidence at all",
			risk:          gate.ReviewRiskMedium,
			authorization: gate.ReviewAuthorizationUnknown,
			wantEligible:  true,
		},
		{
			name:          "high risk with no authorization evidence stays human",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationUnknown,
			wantEligible:  false,
		},
		{
			name:          "high risk with only a broad, non-naming instruction stays human",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationLow,
			wantEligible:  false,
		},
		{
			name:          "high risk becomes eligible once the user's own message names the action",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationMedium,
			wantEligible:  true,
		},
		{
			name:          "high risk stays eligible under the strongest authorization evidence",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationHigh,
			wantEligible:  true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, nil)
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

func TestReconcilePostWarningApproval(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		categories    []gate.ReviewRiskCategory
		wantEligible  bool
	}{
		{
			name:          "before the warning, weak authorization for a shared-state action stays human",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationLow,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryDestructiveShared},
			wantEligible:  false,
		},
		{
			name:          "explicit approval given after the user was shown the concrete risk overrides the ordinary threshold",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryDestructiveShared},
			wantEligible:  true,
		},
		{
			name:          "post-warning approval does not rescue a confirmed-exfiltration category",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryDataExfiltration},
			wantEligible:  false,
		},
		{
			name:          "post-warning approval does not rescue critical risk",
			risk:          gate.ReviewRiskCritical,
			authorization: gate.ReviewAuthorizationHigh,
			categories:    []gate.ReviewRiskCategory{gate.ReviewCategoryDestructiveShared},
			wantEligible:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, tt.categories)
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

// TestReconcileCredentialAccessRemainsGovernedByRiskAuthorization documents a
// deliberate judgment call: unlike credential_probing, credential_access has
// NO CategoryMinimumRisk floor of its own, because the taxonomy deliberately
// distinguishes routine, already-authorized credential USE (credential_access)
// from searching for or extracting a credential (credential_probing, which
// already floors at high). A floor above low would make it impossible for a
// model to ever honestly report credential_access at low risk, which
// contradicts that taxonomy split and the low-risk case this test still
// asserts stays eligible. credential_access is still not a blind spot: the
// pre-existing, category-independent MinimumAuthorization-by-risk matrix
// already requires at least medium authorization whenever ANY category
// (including credential_access) is reported at high risk, which the second
// case below proves.
func TestReconcileCredentialAccessRemainsGovernedByRiskAuthorization(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		wantEligible  bool
	}{
		{
			name:          "routine authorized use of an already-available credential stays eligible at low risk",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationUnknown,
			wantEligible:  true,
		},
		{
			name:          "credential access reported at high risk with no authorization evidence still stays human via the general authorization matrix",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationUnknown,
			wantEligible:  false,
		},
		{
			name:          "the same high-risk credential access becomes eligible once authorization names it",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationMedium,
			wantEligible:  true,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, []gate.ReviewRiskCategory{gate.ReviewCategoryCredentialAccess})
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

func TestReconcileUntrustedCodeExecution(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		wantEligible  bool
	}{
		{
			name:          "reporting untrusted code execution at low risk is an internally inconsistent understatement and stays human",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationHigh,
			wantEligible:  false,
		},
		{
			name:          "executing arbitrary downloaded or generated code with no authorization evidence stays human",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationUnknown,
			wantEligible:  false,
		},
		{
			name:          "the same execution becomes eligible once authorization names it",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationMedium,
			wantEligible:  true,
		},
		{
			name:          "an unbounded or unreviewed execution at critical risk always needs a human",
			risk:          gate.ReviewRiskCritical,
			authorization: gate.ReviewAuthorizationHigh,
			wantEligible:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, []gate.ReviewRiskCategory{gate.ReviewCategoryUntrustedCodeExecution})
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

func TestReconcileMutableNetwork(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
		wantEligible  bool
	}{
		{
			name:          "reporting a mutable network action at low risk is an inconsistent understatement and stays human",
			risk:          gate.ReviewRiskLow,
			authorization: gate.ReviewAuthorizationHigh,
			wantEligible:  false,
		},
		{
			name:          "a network action that can mutate remote state with no authorization evidence stays human",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationUnknown,
			wantEligible:  false,
		},
		{
			name:          "the same mutable network action becomes eligible once authorization names it",
			risk:          gate.ReviewRiskHigh,
			authorization: gate.ReviewAuthorizationMedium,
			wantEligible:  true,
		},
		{
			name:          "an unrecoverable mutable-network action at critical risk always needs a human",
			risk:          gate.ReviewRiskCritical,
			authorization: gate.ReviewAuthorizationHigh,
			wantEligible:  false,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, []gate.ReviewRiskCategory{gate.ReviewCategoryMutableNetwork})
			if got != tt.wantEligible {
				t.Fatalf("eligible() = %v, want %v", got, tt.wantEligible)
			}
		})
	}
}

// TestReconcileAuthorizationConflictIsAlwaysAbsoluteHuman proves the
// classifier's own self-reported signal that the transcript carries
// conflicting authorization evidence is always routed to a human, regardless
// of how low the reported risk or how strong the reported authorization is
// (the fail-secure direction the reviewer specifically called out).
func TestReconcileAuthorizationConflictIsAlwaysAbsoluteHuman(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
	}{
		{name: "low risk with strong authorization is still blocked", risk: gate.ReviewRiskLow, authorization: gate.ReviewAuthorizationHigh},
		{name: "high risk with strong authorization is still blocked", risk: gate.ReviewRiskHigh, authorization: gate.ReviewAuthorizationHigh},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, []gate.ReviewRiskCategory{gate.ReviewCategoryAuthorizationConflict})
			if got {
				t.Fatal("eligible() = true, want false for authorization_conflict")
			}
		})
	}
}

// TestReconcileTargetAmbiguityIsAlwaysAbsoluteHuman is the reviewer's
// specifically described regression scenario: before this fix, a
// target_ambiguity report at medium risk with unknown authorization and no
// other category cleared the pre-fix policy (no CategoryMinimumRisk floor, no
// AbsoluteHuman entry, and MinimumAuthorization[medium] == unknown placed no
// bar). The classifier itself signaling that it cannot confidently identify
// the action's target must never auto-approve.
func TestReconcileTargetAmbiguityIsAlwaysAbsoluteHuman(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	// The exact scenario that would have cleared before this fix: medium
	// risk, unknown authorization, no other tightening category.
	if eligible(t, p, subject, gate.ReviewRiskMedium, gate.ReviewAuthorizationUnknown, []gate.ReviewRiskCategory{gate.ReviewCategoryTargetAmbiguity}) {
		t.Fatal("eligible() = true, want false: target_ambiguity must fail closed even at medium risk with unknown authorization")
	}

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
	}{
		{name: "low risk with strong authorization is still blocked", risk: gate.ReviewRiskLow, authorization: gate.ReviewAuthorizationHigh},
		{name: "high risk with strong authorization is still blocked", risk: gate.ReviewRiskHigh, authorization: gate.ReviewAuthorizationHigh},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, []gate.ReviewRiskCategory{gate.ReviewCategoryTargetAmbiguity})
			if got {
				t.Fatal("eligible() = true, want false for target_ambiguity")
			}
		})
	}
}

// TestReconcileInsufficientEvidenceIsAlwaysAbsoluteHuman is the reviewer's
// other specifically described regression scenario, for insufficient_evidence
// rather than target_ambiguity: see
// TestReconcileTargetAmbiguityIsAlwaysAbsoluteHuman for the exact pre-fix
// false-clear this mirrors. A model that itself signals "I don't have enough
// evidence" while still recommending allow is exactly the case the prompt's
// own "omissions are not benign" guidance warns against, and must always fail
// closed to a human regardless of the risk/authorization it also reported.
func TestReconcileInsufficientEvidenceIsAlwaysAbsoluteHuman(t *testing.T) {
	t.Parallel()
	subject := newSubject(t)
	p := policy.DefaultPolicy()

	// The exact scenario that would have cleared before this fix: medium
	// risk, unknown authorization, no other tightening category.
	if eligible(t, p, subject, gate.ReviewRiskMedium, gate.ReviewAuthorizationUnknown, []gate.ReviewRiskCategory{gate.ReviewCategoryInsufficientEvidence}) {
		t.Fatal("eligible() = true, want false: insufficient_evidence must fail closed even at medium risk with unknown authorization")
	}

	tests := []struct {
		name          string
		risk          gate.ReviewRisk
		authorization gate.ReviewAuthorization
	}{
		{name: "low risk with strong authorization is still blocked", risk: gate.ReviewRiskLow, authorization: gate.ReviewAuthorizationHigh},
		{name: "high risk with strong authorization is still blocked", risk: gate.ReviewRiskHigh, authorization: gate.ReviewAuthorizationHigh},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := eligible(t, p, subject, tt.risk, tt.authorization, []gate.ReviewRiskCategory{gate.ReviewCategoryInsufficientEvidence})
			if got {
				t.Fatal("eligible() = true, want false for insufficient_evidence")
			}
		})
	}
}

func TestPolicyCloneIsIndependentOfSource(t *testing.T) {
	t.Parallel()

	original := policy.DefaultPolicy()
	clone := original.Clone()

	for category := range clone.CategoryMinimumRisk {
		clone.CategoryMinimumRisk[category] = gate.ReviewRiskLow
		break
	}
	for category := range clone.AbsoluteHumanCategories {
		delete(clone.AbsoluteHumanCategories, category)
		break
	}
	for risk := range clone.MinimumAuthorization {
		clone.MinimumAuthorization[risk] = gate.ReviewAuthorizationHigh
		break
	}

	fresh := policy.DefaultPolicy()
	for category, risk := range fresh.CategoryMinimumRisk {
		if original.CategoryMinimumRisk[category] != risk {
			t.Fatalf("original.CategoryMinimumRisk[%q] = %q mutated by clone, want %q", category, original.CategoryMinimumRisk[category], risk)
		}
	}
	if len(original.AbsoluteHumanCategories) != len(fresh.AbsoluteHumanCategories) {
		t.Fatal("original.AbsoluteHumanCategories mutated by clone")
	}
	for risk, authorization := range fresh.MinimumAuthorization {
		if original.MinimumAuthorization[risk] != authorization {
			t.Fatalf("original.MinimumAuthorization[%q] = %q mutated by clone, want %q", risk, original.MinimumAuthorization[risk], authorization)
		}
	}
}

func TestDefaultPolicyHasAStableNonEmptyRevision(t *testing.T) {
	t.Parallel()

	first := policy.DefaultPolicy()
	second := policy.DefaultPolicy()
	if first.Revision == "" {
		t.Fatal("DefaultPolicy().Revision is empty")
	}
	if first.Revision != second.Revision {
		t.Fatal("DefaultPolicy().Revision is not stable across calls")
	}
}

// allKnownReviewCategories mirrors the full closed set of
// gate.ReviewRiskCategory values defined in
// vendor/github.com/looprig/harness/pkg/gate/review.go. pkg/gate exposes no
// enumerable list of its own taxonomy (only ParseReviewRiskCategory's
// internal switch), so this module maintains its own local mirror
// exclusively for TestDefaultPolicyCoversEveryKnownReviewCategory below. If
// Harness ever adds a category, this list and DefaultPolicy must be updated
// together, or this test starts failing to catch that drift.
var allKnownReviewCategories = []gate.ReviewRiskCategory{
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

// categoriesDeliberatelyExcludedFromMinimumRisk documents, by name, every
// category this module intentionally leaves out of CategoryMinimumRisk
// without also placing it in AbsoluteHumanCategories. This mirrors the
// existing credential_access precedent explained on DefaultPolicy itself:
// routine, already-authorized credential use, which the
// category-independent MinimumAuthorization-by-risk matrix still governs
// whenever it is reported at high risk. Any future addition here must carry
// the same kind of explicit justification, not just silence.
var categoriesDeliberatelyExcludedFromMinimumRisk = map[gate.ReviewRiskCategory]string{
	gate.ReviewCategoryCredentialAccess: "routine, already-authorized credential use in the course of a requested task; still governed by the category-independent MinimumAuthorization-by-risk matrix",
}

// TestDefaultPolicyCoversEveryKnownReviewCategory guards against a future
// maintainer silently missing a gate.ReviewRiskCategory while hand-editing
// DefaultPolicy: every category this module knows about must be present in
// CategoryMinimumRisk, present in AbsoluteHumanCategories, or explicitly
// named in categoriesDeliberatelyExcludedFromMinimumRisk with a reason a
// reviewer can evaluate, never simply absent by omission.
func TestDefaultPolicyCoversEveryKnownReviewCategory(t *testing.T) {
	t.Parallel()

	if err := gate.ValidateReviewCategories(allKnownReviewCategories); err != nil {
		t.Fatalf("allKnownReviewCategories contains an invalid gate.ReviewRiskCategory (typo in this test's own mirror list?): %v", err)
	}

	p := policy.DefaultPolicy()
	for _, category := range allKnownReviewCategories {
		_, hasFloor := p.CategoryMinimumRisk[category]
		_, absolute := p.AbsoluteHumanCategories[category]
		if hasFloor || absolute {
			continue
		}
		if reason, excused := categoriesDeliberatelyExcludedFromMinimumRisk[category]; excused {
			if reason == "" {
				t.Errorf("category %q is excused from CategoryMinimumRisk/AbsoluteHumanCategories with an empty reason", category)
			}
			continue
		}
		t.Errorf("gate.ReviewRiskCategory %q is in neither CategoryMinimumRisk nor AbsoluteHumanCategories, and is not named in this test's categoriesDeliberatelyExcludedFromMinimumRisk allowlist — DefaultPolicy may have silently missed it", category)
	}
}
