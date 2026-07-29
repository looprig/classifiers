// Package corpus holds the command-safety classifier's versioned Codex-parity
// evaluation corpus: independently worded synthetic scenarios, each paired
// with the assessment a correct classifier should produce and the resulting
// end-to-end eligibility, plus a short record of how the case compares to
// the corresponding Codex Guardian scenario (design §22.6/§22.7).
//
// This package builds real github.com/looprig/harness/pkg/gate values from
// each fixture (a fully digest-stamped gate.PermissionReviewSubject) so the
// deterministic evaluation runner in pkg/commandsafety can exercise the
// classifier's actual MarshalInput/ValidateResult pipeline and Harness's own
// unmodified gate.EvaluatePermissionAssessment, never a reimplementation of
// either.
package corpus

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/gate"
	"github.com/looprig/harness/pkg/identity"
	"github.com/looprig/harness/pkg/tool"
)

// Revision is the corpus's own content revision label, independent of the
// classifier's prompt/policy/schema/wire revisions (design §19.2). Bump it
// whenever a case's scenario, expected assessment, or parity record changes
// meaning, per docs/evaluations/README.md.
const Revision = "command-safety-corpus/v1"

// DesignCategory is one closed scenario category from design §22.6 the
// corpus is required to cover at least once. Values are deliberately
// granular (e.g. deletion_narrow and deletion_broad are distinct) so
// completeness checking is genuinely load-bearing rather than a coarse
// per-bullet checklist.
type DesignCategory string

const (
	DesignRoutineBuild                DesignCategory = "routine_build"
	DesignRoutineTest                 DesignCategory = "routine_test"
	DesignRoutineFormat               DesignCategory = "routine_format"
	DesignRoutineLint                 DesignCategory = "routine_lint"
	DesignPackageInstallation         DesignCategory = "package_installation"
	DesignToolInstallation            DesignCategory = "tool_installation"
	DesignSandboxRetry                DesignCategory = "sandbox_retry"
	DesignSandboxEscalation           DesignCategory = "sandbox_escalation"
	DesignDeletionNarrow              DesignCategory = "deletion_narrow"
	DesignDeletionBroad               DesignCategory = "deletion_broad"
	DesignDeletionTargetMissing       DesignCategory = "deletion_target_missing"
	DesignDeletionTargetEmpty         DesignCategory = "deletion_target_empty"
	DesignDeletionTargetSymlinked     DesignCategory = "deletion_target_symlinked"
	DesignDeletionTargetChanged       DesignCategory = "deletion_target_changed"
	DesignGitStatus                   DesignCategory = "git_status"
	DesignGitCheckout                 DesignCategory = "git_checkout"
	DesignGitReset                    DesignCategory = "git_reset"
	DesignGitClean                    DesignCategory = "git_clean"
	DesignGitForcePush                DesignCategory = "git_force_push"
	DesignGitBranchDeletion           DesignCategory = "git_branch_deletion"
	DesignGitProtectedBranch          DesignCategory = "git_protected_branch"
	DesignCredentialUse               DesignCategory = "credential_use"          // #nosec G101 -- Closed taxonomy label, not a credential.
	DesignCredentialReading           DesignCategory = "credential_reading"      // #nosec G101 -- Closed taxonomy label, not a credential.
	DesignCredentialExfiltration      DesignCategory = "credential_exfiltration" // #nosec G101 -- Closed taxonomy label, not a credential.
	DesignRemotePublic                DesignCategory = "remote_public"
	DesignRemotePrivate               DesignCategory = "remote_private"
	DesignRemoteInternal              DesignCategory = "remote_internal"
	DesignRemoteUnknown               DesignCategory = "remote_unknown"
	DesignUploadDataMovement          DesignCategory = "upload_data_movement"
	DesignProductionMutation          DesignCategory = "production_mutation"
	DesignSharedEnvironmentMutation   DesignCategory = "shared_environment_mutation"
	DesignSecurityControlChange       DesignCategory = "security_control_change"
	DesignArbitraryCodeExecution      DesignCategory = "arbitrary_code_execution"
	DesignAuthorizationExplicit       DesignCategory = "authorization_explicit"
	DesignAuthorizationImplied        DesignCategory = "authorization_implied"
	DesignAuthorizationAbsent         DesignCategory = "authorization_absent"
	DesignAuthorizationConflicting    DesignCategory = "authorization_conflicting"
	DesignAuthorizationPostWarning    DesignCategory = "authorization_post_warning"
	DesignInjectionInFile             DesignCategory = "injection_in_file"
	DesignInjectionInToolResult       DesignCategory = "injection_in_tool_result"
	DesignInjectionInRepoInstructions DesignCategory = "injection_in_repo_instructions"
	DesignInjectionInCommandArguments DesignCategory = "injection_in_command_arguments"
	DesignInjectionInFetchedContent   DesignCategory = "injection_in_fetched_content"
	DesignTruncatedMaterialContext    DesignCategory = "truncated_material_context"
	DesignEvidenceFailure             DesignCategory = "evidence_failure"
)

// allDesignCategories is the closed, complete §22.6 coverage domain in a
// stable order. AllDesignCategories returns an independent copy.
var allDesignCategories = []DesignCategory{
	DesignRoutineBuild, DesignRoutineTest, DesignRoutineFormat, DesignRoutineLint,
	DesignPackageInstallation, DesignToolInstallation,
	DesignSandboxRetry, DesignSandboxEscalation,
	DesignDeletionNarrow, DesignDeletionBroad,
	DesignDeletionTargetMissing, DesignDeletionTargetEmpty, DesignDeletionTargetSymlinked, DesignDeletionTargetChanged,
	DesignGitStatus, DesignGitCheckout, DesignGitReset, DesignGitClean, DesignGitForcePush, DesignGitBranchDeletion, DesignGitProtectedBranch,
	DesignCredentialUse, DesignCredentialReading, DesignCredentialExfiltration,
	DesignRemotePublic, DesignRemotePrivate, DesignRemoteInternal, DesignRemoteUnknown,
	DesignUploadDataMovement,
	DesignProductionMutation, DesignSharedEnvironmentMutation,
	DesignSecurityControlChange,
	DesignArbitraryCodeExecution,
	DesignAuthorizationExplicit, DesignAuthorizationImplied, DesignAuthorizationAbsent, DesignAuthorizationConflicting, DesignAuthorizationPostWarning,
	DesignInjectionInFile, DesignInjectionInToolResult, DesignInjectionInRepoInstructions, DesignInjectionInCommandArguments, DesignInjectionInFetchedContent,
	DesignTruncatedMaterialContext,
	DesignEvidenceFailure,
}

// AllDesignCategories returns the closed, complete design §22.6 coverage
// domain the corpus completeness test requires at least one case for.
func AllDesignCategories() []DesignCategory {
	return append([]DesignCategory(nil), allDesignCategories...)
}

// ValidDesignCategory reports whether category belongs to the closed §22.6
// domain.
func ValidDesignCategory(category DesignCategory) bool {
	for _, known := range allDesignCategories {
		if known == category {
			return true
		}
	}
	return false
}

// CodexParityComparison is the closed comparison between this classifier's
// expected result for a case and the corresponding Guardian scenario. There
// is deliberately no "looser" value: the type system makes an undocumented
// looser result unrepresentable, and a case whose comparison is neither of
// these two values fails Case.Validate.
type CodexParityComparison string

const (
	ParityEqual    CodexParityComparison = "equal"
	ParityStricter CodexParityComparison = "stricter"
)

// CodexParity records, in the corpus author's own words, which Guardian
// scenario or category a case corresponds to and whether this classifier's
// expected result is equal to or stricter than what that Guardian scenario
// would produce.
type CodexParity struct {
	GuardianScenario string                `json:"guardian_scenario"`
	Comparison       CodexParityComparison `json:"comparison"`
	Justification    string                `json:"justification"`
}

// RequestFixture is the synthetic prepared-command shape a case reviews. Its
// single command.execute requirement is derived automatically by
// Case.Subject; a fixture never lists requirements directly, so the
// requirement can never drift out of sync with Command (see
// tool.ValidateRequest's command-grant invariant).
type RequestFixture struct {
	ToolName         string `json:"tool_name"`
	Summary          string `json:"summary"`
	Command          string `json:"command"`
	WorkingDirectory string `json:"working_directory"`
}

// ContextEntryFixture is one live review-context entry. Origin and Kind must
// form one of gate's closed pairs (e.g. "user"/"user_message",
// "tool"/"tool_result").
type ContextEntryFixture struct {
	Origin  string `json:"origin"`
	Kind    string `json:"kind"`
	Content string `json:"content"`
}

// TruncationFixture, when Force is true, asks Case.Subject to build the
// review context under a deliberately tightened per-kind byte budget
// (TargetKind/LimitBytes) instead of the generous default policy, through
// Harness's own gate.BuildReviewContext, so the resulting material
// truncation is genuinely computed by Harness rather than hand-asserted.
type TruncationFixture struct {
	Force      bool   `json:"force"`
	TargetKind string `json:"target_kind"`
	LimitBytes int    `json:"limit_bytes"`
}

// ExpectedAssessmentFixture is the assessment a correct classifier should
// produce for the case, in the wire string form of gate's closed enums.
type ExpectedAssessmentFixture struct {
	Risk           string   `json:"risk"`
	Authorization  string   `json:"authorization"`
	Categories     []string `json:"categories"`
	Recommendation string   `json:"recommendation"`
	Rationale      string   `json:"rationale"`
}

// Case is one versioned, independently worded corpus fixture.
type Case struct {
	ID               string                    `json:"id"`
	DesignCategories []DesignCategory          `json:"design_categories"`
	Description      string                    `json:"description"`
	Request          RequestFixture            `json:"request"`
	ContextEntries   []ContextEntryFixture     `json:"context_entries"`
	Truncation       TruncationFixture         `json:"truncation"`
	Expected         ExpectedAssessmentFixture `json:"expected"`
	ExpectedEligible bool                      `json:"expected_eligible"`
	Parity           CodexParity               `json:"codex_parity"`
}

// ParsedExpectation is Case.Expected decoded into gate's closed types.
type ParsedExpectation struct {
	Risk           gate.ReviewRisk
	Authorization  gate.ReviewAuthorization
	Categories     []gate.ReviewRiskCategory
	Recommendation gate.ReviewRecommendation
	Rationale      string
}

// Validate checks a case's own structural invariants: required text fields,
// a closed and non-empty DesignCategories list, a parseable Expected
// assessment, and a parity record whose Comparison is one of the two closed
// values with a non-empty Justification whenever it claims "stricter".
func (c Case) Validate() error {
	if strings.TrimSpace(c.ID) == "" {
		return fmt.Errorf("corpus: case has an empty id")
	}
	if strings.TrimSpace(c.Description) == "" {
		return fmt.Errorf("corpus: case %q has an empty description", c.ID)
	}
	if len(c.DesignCategories) == 0 {
		return fmt.Errorf("corpus: case %q has no design_categories", c.ID)
	}
	for _, category := range c.DesignCategories {
		if !ValidDesignCategory(category) {
			return fmt.Errorf("corpus: case %q has unknown design category %q", c.ID, category)
		}
	}
	if _, err := c.ParseExpected(); err != nil {
		return fmt.Errorf("corpus: case %q: %w", c.ID, err)
	}
	if strings.TrimSpace(c.Parity.GuardianScenario) == "" {
		return fmt.Errorf("corpus: case %q has an empty codex_parity.guardian_scenario", c.ID)
	}
	switch c.Parity.Comparison {
	case ParityEqual:
	case ParityStricter:
		if strings.TrimSpace(c.Parity.Justification) == "" {
			return fmt.Errorf("corpus: case %q claims parity %q with no justification", c.ID, ParityStricter)
		}
	default:
		return fmt.Errorf("corpus: case %q has unsupported codex_parity.comparison %q", c.ID, c.Parity.Comparison)
	}
	if _, err := c.Subject(); err != nil {
		return fmt.Errorf("corpus: case %q: %w", c.ID, err)
	}
	return nil
}

// ParseExpected decodes Expected into gate's closed types, rejecting any
// unsupported enum value or invalid category list.
func (c Case) ParseExpected() (ParsedExpectation, error) {
	risk, ok := gate.ParseReviewRisk(c.Expected.Risk)
	if !ok {
		return ParsedExpectation{}, fmt.Errorf("unsupported expected.risk %q", c.Expected.Risk)
	}
	authorization, ok := gate.ParseReviewAuthorization(c.Expected.Authorization)
	if !ok {
		return ParsedExpectation{}, fmt.Errorf("unsupported expected.authorization %q", c.Expected.Authorization)
	}
	recommendation, ok := gate.ParseReviewRecommendation(c.Expected.Recommendation)
	if !ok {
		return ParsedExpectation{}, fmt.Errorf("unsupported expected.recommendation %q", c.Expected.Recommendation)
	}
	categories := make([]gate.ReviewRiskCategory, len(c.Expected.Categories))
	for i, value := range c.Expected.Categories {
		categories[i] = gate.ReviewRiskCategory(value)
	}
	if err := gate.ValidateReviewCategories(categories); err != nil {
		return ParsedExpectation{}, fmt.Errorf("invalid expected.categories: %w", err)
	}
	return ParsedExpectation{
		Risk:           risk,
		Authorization:  authorization,
		Categories:     categories,
		Recommendation: recommendation,
		Rationale:      c.Expected.Rationale,
	}, nil
}

// Subject builds the real, digest-stamped gate.PermissionReviewSubject this
// case reviews. The review context is always built through Harness's own
// gate.BuildReviewContext: ordinary cases use a generous policy under which
// nothing truncates, while a case with Truncation.Force uses a deliberately
// tightened one so any resulting material truncation is genuinely computed
// by Harness, never hand-asserted.
func (c Case) Subject() (gate.PermissionReviewSubject, error) {
	workingDirectory := c.Request.WorkingDirectory
	if workingDirectory == "" {
		workingDirectory = "/workspace/repo"
	}

	entries := make([]gate.ReviewContextEntry, len(c.ContextEntries))
	for i, entry := range c.ContextEntries {
		origin, ok := gate.ParseReviewContextOrigin(entry.Origin)
		if !ok {
			return gate.PermissionReviewSubject{}, fmt.Errorf("corpus: case %q: context_entries[%d]: unsupported origin %q", c.ID, i, entry.Origin)
		}
		kind, ok := gate.ParseReviewContextKind(entry.Kind)
		if !ok {
			return gate.PermissionReviewSubject{}, fmt.Errorf("corpus: case %q: context_entries[%d]: unsupported kind %q", c.ID, i, entry.Kind)
		}
		entries[i] = gate.ReviewContextEntry{Origin: origin, Kind: kind, Content: entry.Content}
	}

	input := gate.ReviewContext{
		Coordinates: identity.Coordinates{
			SessionID: deterministicUUID(c.ID, "session"),
			LoopID:    deterministicUUID(c.ID, "loop"),
			TurnID:    deterministicUUID(c.ID, "turn"),
			StepID:    deterministicUUID(c.ID, "step"),
		},
		ContextRevision:    "command-safety-corpus-context/v1",
		WorkspaceRoot:      "/workspace",
		WorkingDirectory:   workingDirectory,
		SecurityCeiling:    "workspace-write",
		GatePolicyRevision: "command-safety-corpus-gate-policy/v1",
		Entries:            entries,
	}

	contextPolicy := roomyContextPolicy()
	if c.Truncation.Force {
		contextPolicy = tightenContextPolicy(contextPolicy, c.Truncation.TargetKind, c.Truncation.LimitBytes)
	}
	builtContext, err := gate.BuildReviewContext(input, contextPolicy)
	if err != nil {
		return gate.PermissionReviewSubject{}, fmt.Errorf("corpus: case %q: gate.BuildReviewContext: %w", c.ID, err)
	}

	toolExecutionID := deterministicUUID(c.ID, "tool-execution")
	request := tool.Request{
		ToolName:           c.Request.ToolName,
		Summary:            c.Request.Summary,
		ExecutionID:        toolExecutionID.String(),
		Command:            c.Request.Command,
		WorkingDirectory:   workingDirectory,
		ExpiresAtUnixMilli: 1800000000000,
		Requirements: []tool.Requirement{{
			Kind:        tool.CapabilityCommandExecute,
			Match:       c.Request.Command,
			Description: c.Request.Summary,
			GrantClass:  tool.GrantClassCommandStart,
			GrantTarget: c.Request.Command,
		}},
	}

	basis := gate.ReviewBasis{
		GateID:             deterministicUUID(c.ID, "gate"),
		ToolExecutionID:    toolExecutionID,
		ContextRevision:    builtContext.ContextRevision,
		GatePolicyRevision: builtContext.GatePolicyRevision,
		ClassifierRevision: "command-safety-corpus-classifier/v1",
		SecurityCeiling:    builtContext.SecurityCeiling,
	}

	subject, err := gate.NewPermissionReviewSubject(basis, request, builtContext)
	if err != nil {
		return gate.PermissionReviewSubject{}, fmt.Errorf("corpus: case %q: gate.NewPermissionReviewSubject: %w", c.ID, err)
	}
	return subject, nil
}

// roomyContextPolicy is a generous review-context policy under which none of
// this package's own fixture content truncates, mirroring the bounds
// pkg/gate's own tests use for an "everything fits" policy.
func roomyContextPolicy() gate.ReviewContextPolicy {
	return gate.ReviewContextPolicy{
		Revision:             "command-safety-corpus-context-policy/v1",
		MaxBytes:             gate.MaxPermissionReviewSubjectWireBytes,
		MaxEstimatedTokens:   gate.MaxReviewContextInputBytes / 4,
		MaxEntries:           gate.MaxReviewContextInputEntries,
		MaxUserEntryBytes:    gate.MaxReviewContextEntryInputBytes,
		MaxAgentEntryBytes:   gate.MaxReviewContextEntryInputBytes,
		MaxToolEntryBytes:    gate.MaxReviewContextEntryInputBytes,
		MaxBlockBytes:        gate.MaxReviewContextEntryInputBytes,
		MaxActiveActionBytes: gate.MaxReviewContextEntryInputBytes,
	}
}

// tightenContextPolicy lowers the one per-kind byte budget matching
// targetKind to limitBytes, so gate.BuildReviewContext genuinely truncates a
// matching entry instead of the fixture hand-asserting a truncated shape.
func tightenContextPolicy(policy gate.ReviewContextPolicy, targetKind string, limitBytes int) gate.ReviewContextPolicy {
	switch gate.ReviewContextKind(targetKind) {
	case gate.ReviewContextKindUserMessage:
		policy.MaxUserEntryBytes = limitBytes
	case gate.ReviewContextKindAssistantMessage, gate.ReviewContextKindAssistantToolRequest:
		policy.MaxAgentEntryBytes = limitBytes
	case gate.ReviewContextKindToolResult:
		policy.MaxToolEntryBytes = limitBytes
	default:
		policy.MaxBlockBytes = limitBytes
	}
	return policy
}

// deterministicUUID derives a stable, non-random UUID from parts so every
// corpus case's subject digest-stamps identically across runs without
// depending on crypto/rand. It is a fixture-identity derivation only, never
// used for anything security-sensitive.
func deterministicUUID(parts ...string) uuid.UUID {
	digest := sha256.Sum256([]byte(strings.Join(parts, "\x00")))
	var raw [16]byte
	copy(raw[:], digest[:16])
	return uuid.UUID(raw)
}
