package commandsafety_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/looprig/classifiers/internal/prompt"
	"github.com/looprig/classifiers/pkg/commandsafety"
	"github.com/looprig/core/content"
	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/gate"
	"github.com/looprig/harness/pkg/hustle"
	"github.com/looprig/harness/pkg/identity"
	"github.com/looprig/harness/pkg/tool"
	"github.com/looprig/inference"
	model "github.com/looprig/inference/model"
	stream "github.com/looprig/inference/stream"
)

type fakeInferenceClient struct{}

func (*fakeInferenceClient) Invoke(context.Context, inference.Request) (*inference.Response, error) {
	return nil, nil
}

func (*fakeInferenceClient) Stream(context.Context, inference.Request) (*stream.StreamReader[content.Chunk], error) {
	return nil, nil
}

func validModel() model.Model {
	return model.CustomModel(
		"test-provider", "test-format", "https://model.example.invalid", "test-model",
		model.WithStructuredOutputWithTools(),
	)
}

func validOptions() commandsafety.Options {
	return commandsafety.Options{
		Inference: &fakeInferenceClient{},
		Model:     validModel(),
		Policy:    commandsafety.DefaultPolicy(),
		Evidence:  commandsafety.StandardEvidence(commandsafety.ReadEvidencePolicy{}),
	}
}

// validSubject builds one internally consistent, digest-stamped subject
// carrying a command.execute requirement.
func validSubject(t *testing.T) gate.PermissionReviewSubject {
	t.Helper()

	toolExecutionID := uuid.MustParse("123e4567-e89b-12d3-a456-426614174110")
	context := gate.ReviewContext{
		Coordinates: identity.Coordinates{
			SessionID: uuid.MustParse("123e4567-e89b-12d3-a456-426614174101"),
			LoopID:    uuid.MustParse("123e4567-e89b-12d3-a456-426614174102"),
			TurnID:    uuid.MustParse("123e4567-e89b-12d3-a456-426614174103"),
			StepID:    uuid.MustParse("123e4567-e89b-12d3-a456-426614174104"),
		},
		ContextRevision:    "context-v1",
		WorkspaceRoot:      "/workspace",
		WorkingDirectory:   "/workspace/repo",
		SecurityCeiling:    "workspace-write",
		GatePolicyRevision: "gate-policy-v1",
		Entries: []gate.ReviewContextEntry{
			{Origin: gate.ReviewContextOriginUser, Kind: gate.ReviewContextKindUserMessage, Content: "run git status"},
			{Origin: gate.ReviewContextOriginAssistant, Kind: gate.ReviewContextKindAssistantToolRequest, Content: `{"command":"git status"}`},
		},
	}
	request := tool.Request{
		ToolName:           "Bash",
		Summary:            "run git status",
		ExecutionID:        toolExecutionID.String(),
		Command:            "git status",
		WorkingDirectory:   "/workspace/repo",
		ExpiresAtUnixMilli: 1800000000000,
		Requirements: []tool.Requirement{{
			Kind:        tool.CapabilityCommandExecute,
			Match:       "git status",
			Description: "run git status",
			GrantClass:  tool.GrantClassCommandStart,
			GrantTarget: "git status",
		}},
	}
	basis := gate.ReviewBasis{
		GateID:             uuid.MustParse("123e4567-e89b-12d3-a456-426614174109"),
		ToolExecutionID:    toolExecutionID,
		ContextRevision:    context.ContextRevision,
		GatePolicyRevision: context.GatePolicyRevision,
		ClassifierRevision: "command-safety-v1",
		SecurityCeiling:    context.SecurityCeiling,
	}
	subject, err := gate.NewPermissionReviewSubject(basis, request, context)
	if err != nil {
		t.Fatalf("gate.NewPermissionReviewSubject() error = %v", err)
	}
	return subject
}

func TestNewConstructsAValidClassifier(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if classifier.Name() != commandsafety.Name {
		t.Fatalf("Name() = %q, want %q", classifier.Name(), commandsafety.Name)
	}
	if classifier.Revision() != commandsafety.DefaultPolicy().Revision {
		t.Fatalf("Revision() = %q, want %q", classifier.Revision(), commandsafety.DefaultPolicy().Revision)
	}

	descriptor := classifier.Definition().Descriptor()
	if descriptor.Name != commandsafety.Name {
		t.Fatalf("Descriptor().Name = %q, want %q", descriptor.Name, commandsafety.Name)
	}
	if descriptor.Participation != hustle.ParticipationBlocking {
		t.Fatal("Descriptor().Participation != ParticipationBlocking")
	}
	if descriptor.ModelSource != hustle.ModelSourceNamed {
		t.Fatal("Descriptor().ModelSource != ModelSourceNamed")
	}
	if descriptor.OutputSchemaName == "" || descriptor.OutputSchemaSHA256 == ([32]byte{}) {
		t.Fatal("Descriptor() output schema identity is empty")
	}
	if !descriptor.StructuredOutputWithTools {
		t.Fatal("Descriptor().StructuredOutputWithTools = false, want true")
	}
	if descriptor.EvidenceToolPolicyRevision == "" ||
		descriptor.EvidenceToolDefinitionsSHA256 == ([32]byte{}) ||
		descriptor.EvidenceProducedToolNamesSHA256 == ([32]byte{}) ||
		descriptor.EvidenceToolDefinitionCount == 0 {
		t.Fatal("Descriptor() evidence-tool identity is empty")
	}
	if descriptor.PolicyRevision != commandsafety.DefaultPolicy().Revision {
		t.Fatalf("Descriptor().PolicyRevision = %q, want %q", descriptor.PolicyRevision, commandsafety.DefaultPolicy().Revision)
	}
}

func TestNewFoldsExactPromptBytesIntoDescriptorIdentity(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	descriptor := classifier.Definition().Descriptor()

	wantSHA256 := sha256.Sum256([]byte(prompt.CommandSafety()))
	if descriptor.PromptSHA256 != wantSHA256 {
		t.Fatal("Descriptor().PromptSHA256 does not hash internal/prompt's exact command-safety text")
	}
	if descriptor.PromptRevision != prompt.CommandSafetyRevision {
		t.Fatalf("Descriptor().PromptRevision = %q, want %q", descriptor.PromptRevision, prompt.CommandSafetyRevision)
	}
}

func TestNewDescriptorIdentityChangesWithPolicyRevision(t *testing.T) {
	t.Parallel()

	first, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	options := validOptions()
	options.Policy = commandsafety.Policy{Revision: "command-safety-policy/v2-test"}
	second, err := commandsafety.New(options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if first.Definition().PolicyRevision() == second.Definition().PolicyRevision() {
		t.Fatal("PolicyRevision() unchanged after Policy.Revision changed")
	}
	if first.Definition().Descriptor().PolicyRevision == second.Definition().Descriptor().PolicyRevision {
		t.Fatal("Descriptor().PolicyRevision unchanged after Policy.Revision changed")
	}
}

func TestNewRejectsNilInferenceClient(t *testing.T) {
	t.Parallel()

	options := validOptions()
	options.Inference = nil
	_, err := commandsafety.New(options)
	assertConstructionError(t, err, commandsafety.FieldInference)
}

func TestNewRejectsTypedNilInferenceClient(t *testing.T) {
	t.Parallel()

	var typedNil *fakeInferenceClient
	options := validOptions()
	options.Inference = typedNil
	_, err := commandsafety.New(options)
	assertConstructionError(t, err, commandsafety.FieldInference)
}

func TestNewRejectsInvalidModel(t *testing.T) {
	t.Parallel()

	options := validOptions()
	options.Model = model.Model{}
	_, err := commandsafety.New(options)
	assertConstructionError(t, err, commandsafety.FieldModel)
}

func TestNewRejectsModelCapabilityMismatch(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		model model.Model
	}{
		{name: "no capabilities at all", model: model.CustomModel("p", "f", "https://model.example.invalid", "m")},
		{name: "tools only", model: model.CustomModel("p", "f", "https://model.example.invalid", "m", model.WithTools())},
		{name: "structured output only", model: model.CustomModel("p", "f", "https://model.example.invalid", "m", model.WithStructuredOutput())},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			options := validOptions()
			options.Model = tt.model
			_, err := commandsafety.New(options)
			assertConstructionError(t, err, commandsafety.FieldModelCapabilities)
		})
	}
}

func TestNewRejectsEmptyPolicyRevision(t *testing.T) {
	t.Parallel()

	options := validOptions()
	options.Policy = commandsafety.Policy{Revision: "   "}
	_, err := commandsafety.New(options)
	assertConstructionError(t, err, commandsafety.FieldPolicy)
}

func TestNewRejectsEmptyEvidencePolicy(t *testing.T) {
	t.Parallel()

	options := validOptions()
	options.Evidence = hustle.EvidenceToolPolicy{}
	_, err := commandsafety.New(options)
	assertConstructionError(t, err, commandsafety.FieldEvidence)
}

func TestNewRejectsMalformedNonEmptyEvidencePolicy(t *testing.T) {
	t.Parallel()

	options := validOptions()
	// Non-empty Definitions but an invalid (unversioned) policy revision:
	// this must reach hustle.Define's own validation, not the earlier
	// empty-evidence guard.
	options.Evidence.Revision = ""
	_, err := commandsafety.New(options)
	assertConstructionError(t, err, commandsafety.FieldDefinition)
}

func assertConstructionError(t *testing.T, err error, field commandsafety.ConstructionField) {
	t.Helper()
	if err == nil {
		t.Fatal("New() error = nil, want error")
	}
	var constructionErr *commandsafety.ConstructionError
	if !errors.As(err, &constructionErr) {
		t.Fatalf("error = %T, want *commandsafety.ConstructionError", err)
	}
	if constructionErr.Field != field {
		t.Fatalf("ConstructionError.Field = %q, want %q", constructionErr.Field, field)
	}
}

func TestNewDoesNotAliasMutableOptionsAfterConstruction(t *testing.T) {
	t.Parallel()

	options := validOptions()
	classifier, err := commandsafety.New(options)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	before := classifier.Definition().Descriptor()

	// Mutate the caller's copies after construction; none of this may alter
	// the already-constructed classifier's identity.
	options.Model.Name = "mutated-after-construction"
	options.Evidence.Definitions[0] = nil
	options.Policy.Revision = "mutated-after-construction"

	after := classifier.Definition().Descriptor()
	if before != after {
		t.Fatal("Definition().Descriptor() changed after mutating the caller's Options")
	}
}

func TestClassifierAppliesToCommandExecuteRequirementOnly(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	commandSubject := validSubject(t)
	if !classifier.Applies(commandSubject) {
		t.Fatal("Applies() = false for a subject with a command.execute requirement")
	}

	otherSubject := commandSubject.Clone()
	otherSubject.Request.Requirements = []tool.Requirement{{
		Kind:        "filesystem.read",
		Match:       "/workspace/repo/file.txt",
		Description: "read a file",
	}}
	if classifier.Applies(otherSubject) {
		t.Fatal("Applies() = true for a subject with no command.execute requirement")
	}

	emptySubject := commandSubject.Clone()
	emptySubject.Request.Requirements = nil
	if classifier.Applies(emptySubject) {
		t.Fatal("Applies() = true for a subject with no requirements")
	}
}

// TestClassifierAppliesToCommandTriggeredCombination proves applicability is
// decided purely from the set of typed tool.Requirement.Kind values present
// on the request, never from tool.Request.ToolName or Summary: a request
// that carries a command.execute requirement ALONGSIDE other,
// command-triggered requirement kinds (a plausible filesystem/network
// combination a command spawn might also require) remains applicable, while
// a request carrying those same other kinds WITHOUT any command.execute
// requirement at all remains not applicable (design §19.1: a later
// gate.general-safety classifier owns that case, not gate.command-safety).
func TestClassifierAppliesToCommandTriggeredCombination(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	commandSubject := validSubject(t)

	combinedSubject := commandSubject.Clone()
	combinedSubject.Request.Requirements = []tool.Requirement{
		{
			Kind:        tool.CapabilityCommandExecute,
			Match:       "git status",
			Description: "run git status",
			GrantClass:  tool.GrantClassCommandStart,
			GrantTarget: "git status",
		},
		{
			Kind:        "filesystem.write",
			Match:       "/workspace/repo",
			Description: "the command may write inside the workspace",
		},
		{
			Kind:        "network.outbound",
			Match:       "example.invalid",
			Description: "the command may reach an outbound host",
		},
	}
	if !classifier.Applies(combinedSubject) {
		t.Fatal("Applies() = false for a subject with a command.execute requirement plus other requirement kinds")
	}

	// Confirm ToolName/Summary genuinely play no role: a command-shaped
	// ToolName/Summary with no command.execute requirement at all is still
	// not applicable, and a deliberately misleading, non-command-shaped
	// ToolName/Summary paired with a real command.execute requirement is
	// still applicable.
	nonCommandToolNameSubject := commandSubject.Clone()
	nonCommandToolNameSubject.Request.Requirements = []tool.Requirement{
		{Kind: "filesystem.write", Match: "/workspace/repo", Description: "write inside the workspace"},
		{Kind: "network.outbound", Match: "example.invalid", Description: "reach an outbound host"},
	}
	nonCommandToolNameSubject.Request.ToolName = "Bash"
	nonCommandToolNameSubject.Request.Summary = "run a shell command"
	if classifier.Applies(nonCommandToolNameSubject) {
		t.Fatal("Applies() = true for a command-shaped ToolName/Summary with no command.execute requirement")
	}

	misleadingToolNameSubject := commandSubject.Clone()
	misleadingToolNameSubject.Request.ToolName = "ReadFile"
	misleadingToolNameSubject.Request.Summary = "read a file"
	if !classifier.Applies(misleadingToolNameSubject) {
		t.Fatal("Applies() = false for a command.execute requirement under a non-command-shaped ToolName/Summary")
	}
}

func TestClassifierMarshalInputAndValidateResultRoundTrip(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	subject := validSubject(t)

	raw, err := classifier.MarshalInput(subject)
	if err != nil {
		t.Fatalf("MarshalInput() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(MarshalInput() output) error = %v", err)
	}
	basis, ok := decoded["basis"].(map[string]any)
	if !ok || basis["gate_id"] != subject.Basis.GateID.String() {
		t.Fatalf("MarshalInput() basis = %#v, want echo of subject.Basis", decoded["basis"])
	}

	output := map[string]any{
		"version":        "command_safety_output.v1",
		"basis":          basis,
		"risk":           "low",
		"authorization":  "unknown",
		"categories":     []string{},
		"recommendation": "allow",
		"rationale":      "",
	}
	outputRaw, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	assessment, err := classifier.ValidateResult(subject, hustle.Result{Output: outputRaw})
	if err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
	if assessment.Basis != subject.Basis {
		t.Fatal("ValidateResult() assessment.Basis != subject.Basis")
	}
	if assessment.Risk != gate.ReviewRiskLow || assessment.Recommendation != gate.ReviewAllow {
		t.Fatalf("ValidateResult() assessment = %#v, unexpected fields", assessment)
	}
}

// TestClassifierValidateResultAppliesDeterministicPolicyReconciliation
// proves ValidateResult does not hand a model's raw, unreconciled
// recommendation straight back to Harness: a model that reports the
// data_exfiltration category yet still recommends allow is internally
// inconsistent with this classifier's own default policy
// (internal/policy.DefaultPolicy's AbsoluteHumanCategories), and
// ValidateResult must tighten that recommendation to needs_human before it
// ever crosses this module's public boundary.
func TestClassifierValidateResultAppliesDeterministicPolicyReconciliation(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	subject := validSubject(t)

	raw, err := classifier.MarshalInput(subject)
	if err != nil {
		t.Fatalf("MarshalInput() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(MarshalInput() output) error = %v", err)
	}
	basis := decoded["basis"]

	output := map[string]any{
		"version":        "command_safety_output.v1",
		"basis":          basis,
		"risk":           "high",
		"authorization":  "high",
		"categories":     []string{"data_exfiltration"},
		"recommendation": "allow",
		"rationale":      "the model incorrectly judged this disclosure safe to auto-approve",
	}
	outputRaw, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	assessment, err := classifier.ValidateResult(subject, hustle.Result{Output: outputRaw})
	if err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
	if assessment.Recommendation != gate.ReviewNeedsHuman {
		t.Fatalf("ValidateResult() assessment.Recommendation = %q, want %q (deterministic policy reconciliation was not applied)",
			assessment.Recommendation, gate.ReviewNeedsHuman)
	}
	// The model's own reported risk and authorization are never rewritten by
	// reconciliation: only the recommendation may tighten.
	if assessment.Risk != gate.ReviewRiskHigh || assessment.Authorization != gate.ReviewAuthorizationHigh {
		t.Fatalf("ValidateResult() assessment = %#v, want risk/authorization preserved verbatim", assessment)
	}
}

func TestClassifierSatisfiesGatePermissionClassifier(t *testing.T) {
	t.Parallel()
	var _ gate.PermissionClassifier = (*commandsafety.Classifier)(nil)
}

// TestNewDefinitionUsesClassifiedOnceRetryPolicy proves the hustle definition
// New builds opts into design §12.6's one bounded retry for a classified
// transient inference failure or recoverable malformed terminal output,
// rather than the historical single-attempt default (hustle.RetryPolicyNone).
func TestNewDefinitionUsesClassifiedOnceRetryPolicy(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if classifier.Definition().RetryPolicy() != hustle.RetryPolicyClassifiedOnce {
		t.Fatalf("Definition().RetryPolicy() = %v, want %v", classifier.Definition().RetryPolicy(), hustle.RetryPolicyClassifiedOnce)
	}
	if classifier.Definition().Descriptor().RetryPolicy != hustle.RetryPolicyClassifiedOnce {
		t.Fatalf("Descriptor().RetryPolicy = %v, want %v", classifier.Definition().Descriptor().RetryPolicy, hustle.RetryPolicyClassifiedOnce)
	}
}

// TestClassifierValidateResultMarksPureShapeFailuresRetryable proves
// ValidateResult returns hustle's sealed recoverable-terminal-validation
// marker (design §12.6: "duplicate, unknown, missing, or otherwise invalid
// terminal wire fields may use it") for genuinely malformed model output that
// is a pure wire-shape problem, never a domain/semantic one.
func TestClassifierValidateResultMarksPureShapeFailuresRetryable(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	subject := validSubject(t)
	raw, err := classifier.MarshalInput(subject)
	if err != nil {
		t.Fatalf("MarshalInput() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(MarshalInput() output) error = %v", err)
	}
	basis := decoded["basis"]

	validOutput := func(mutate func(map[string]any)) []byte {
		object := map[string]any{
			"version":        "command_safety_output.v1",
			"basis":          basis,
			"risk":           "low",
			"authorization":  "unknown",
			"categories":     []string{},
			"recommendation": "allow",
			"rationale":      "",
		}
		if mutate != nil {
			mutate(object)
		}
		out, err := json.Marshal(object)
		if err != nil {
			t.Fatalf("json.Marshal() error = %v", err)
		}
		return out
	}

	tests := []struct {
		name string
		raw  []byte
	}{
		{
			name: "null required field",
			raw:  validOutput(func(o map[string]any) { o["recommendation"] = nil }),
		},
		{
			name: "duplicate top-level JSON key",
			raw: []byte(strings.Replace(
				string(validOutput(nil)),
				`"version":"command_safety_output.v1"`,
				`"version":"command_safety_output.v1","version":"command_safety_output.v1"`,
				1,
			)),
		},
		{
			name: "unknown enum value",
			raw:  validOutput(func(o map[string]any) { o["risk"] = "extreme" }),
		},
		{
			name: "unsupported wire version",
			raw:  validOutput(func(o map[string]any) { o["version"] = "command_safety_output.v2" }),
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := classifier.ValidateResult(subject, hustle.Result{Output: tt.raw})
			if err == nil {
				t.Fatal("ValidateResult() error = nil, want error")
			}
			if !hustle.IsRecoverableTerminalValidationError(err) {
				t.Fatalf("ValidateResult() error = %v (%T), want the sealed recoverable-terminal-validation marker", err, err)
			}
		})
	}
}

// TestClassifierValidateResultDoesNotMarkBasisMismatchRetryable is the
// safety-critical direction of design §12.6: "A basis mismatch, needs_human,
// deny/unsafe semantic result, arbitrary validator error, callback panic, or
// any other domain or operational failure must not use it." A false positive
// here would let a single bad decision get a free retry it should not have.
func TestClassifierValidateResultDoesNotMarkBasisMismatchRetryable(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	subject := validSubject(t)
	raw, err := classifier.MarshalInput(subject)
	if err != nil {
		t.Fatalf("MarshalInput() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal(MarshalInput() output) error = %v", err)
	}
	basis, ok := decoded["basis"].(map[string]any)
	if !ok {
		t.Fatalf("MarshalInput() basis = %#v, want object", decoded["basis"])
	}
	basis["gate_id"] = "00000000-0000-0000-0000-000000000000"

	output := map[string]any{
		"version":        "command_safety_output.v1",
		"basis":          basis,
		"risk":           "low",
		"authorization":  "unknown",
		"categories":     []string{},
		"recommendation": "allow",
		"rationale":      "",
	}
	outputRaw, err := json.Marshal(output)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	_, err = classifier.ValidateResult(subject, hustle.Result{Output: outputRaw})
	if err == nil {
		t.Fatal("ValidateResult() error = nil, want error")
	}
	if hustle.IsRecoverableTerminalValidationError(err) {
		t.Fatal("ValidateResult() marked a basis mismatch retryable, want a non-retryable error")
	}
}
