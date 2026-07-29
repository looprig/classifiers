package wire_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/looprig/classifiers/internal/wire"
	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/gate"
	"github.com/looprig/harness/pkg/identity"
	"github.com/looprig/harness/pkg/tool"
)

// validSubject builds one internally consistent, digest-stamped
// PermissionReviewSubject that Applies to command-safety (it carries a
// command.execute requirement) and satisfies gate's own construction
// invariants (exactly one user message and one active assistant tool
// request entry, absolute workspace paths, etc).
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

// validOutputJSON returns the raw model output that echoes subject's basis
// verbatim and carries the given risk/rationale, a valid low-risk default
// unless overridden by the caller.
func validOutputJSON(t *testing.T, subject gate.PermissionReviewSubject, mutate func(map[string]any)) []byte {
	t.Helper()

	basis := map[string]any{
		"gate_id":              subject.Basis.GateID.String(),
		"tool_execution_id":    subject.Basis.ToolExecutionID.String(),
		"subject_digest":       hex.EncodeToString(subject.Basis.SubjectDigest[:]),
		"context_revision":     subject.Basis.ContextRevision,
		"gate_policy_revision": subject.Basis.GatePolicyRevision,
		"classifier_revision":  subject.Basis.ClassifierRevision,
		"security_ceiling":     subject.Basis.SecurityCeiling,
	}
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
	data, err := json.Marshal(object)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return data
}

func TestDecodeOutputAcceptsValidPayload(t *testing.T) {
	t.Parallel()

	subject := validSubject(t)
	raw := validOutputJSON(t, subject, func(o map[string]any) {
		o["risk"] = "high"
		o["authorization"] = "medium"
		o["categories"] = []string{"destructive_local"}
		o["recommendation"] = "needs_human"
		o["rationale"] = "deletes files outside the workspace"
	})

	assessment, err := wire.DecodeOutput(subject, raw)
	if err != nil {
		t.Fatalf("DecodeOutput() error = %v", err)
	}
	if assessment.Basis != subject.Basis {
		t.Fatal("DecodeOutput() did not set Basis to the trusted subject basis")
	}
	if assessment.Risk != gate.ReviewRiskHigh ||
		assessment.Authorization != gate.ReviewAuthorizationMedium ||
		assessment.Recommendation != gate.ReviewNeedsHuman ||
		len(assessment.Categories) != 1 || assessment.Categories[0] != gate.ReviewCategoryDestructiveLocal ||
		assessment.Rationale != "deletes files outside the workspace" {
		t.Fatalf("DecodeOutput() assessment = %#v, unexpected fields", assessment)
	}
}

func TestDecodeOutputRejectsInvalidPayloads(t *testing.T) {
	t.Parallel()

	longRationale := strings.Repeat("r", gate.MaxPermissionReviewRationaleBytes+1)

	tests := []struct {
		name string
		raw  func(t *testing.T, subject gate.PermissionReviewSubject) []byte
	}{
		{
			name: "empty payload",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return []byte(``)
			},
		},
		{
			name: "explicit null",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return []byte(`null`)
			},
		},
		{
			name: "unknown top-level field",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) { o["extra"] = "surprise" })
			},
		},
		{
			name: "unknown basis field",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) {
					basis := o["basis"].(map[string]any)
					basis["extra"] = "surprise"
				})
			},
		},
		{
			name: "missing required field",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) { delete(o, "recommendation") })
			},
		},
		{
			name: "null risk",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) { o["risk"] = nil })
			},
		},
		{
			name: "null categories array",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) { o["categories"] = nil })
			},
		},
		{
			name: "null category element",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) { o["categories"] = []any{nil} })
			},
		},
		{
			name: "null rationale",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) { o["rationale"] = nil })
			},
		},
		{
			name: "duplicate top-level key",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				valid := validOutputJSON(t, subject, nil)
				return []byte(strings.Replace(
					string(valid),
					`"version":"command_safety_output.v1"`,
					`"version":"command_safety_output.v1","version":"command_safety_output.v1"`,
					1,
				))
			},
		},
		{
			name: "trailing content",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				valid := validOutputJSON(t, subject, nil)
				return append(valid, []byte(`{}`)...)
			},
		},
		{
			name: "oversized payload",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) {
					o["rationale"] = strings.Repeat("x", wire.MaxOutputWireBytes+1)
				})
			},
		},
		{
			name: "oversized rationale",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) {
					o["risk"] = "low"
					o["rationale"] = longRationale
				})
			},
		},
		{
			name: "missing rationale for non-low risk",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) {
					o["risk"] = "high"
					o["rationale"] = "   "
				})
			},
		},
		{
			name: "unknown enum value",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) { o["risk"] = "extreme" })
			},
		},
		{
			name: "unknown category",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) { o["categories"] = []string{"made_up"} })
			},
		},
		{
			name: "duplicate category",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) {
					o["categories"] = []string{"destructive_local", "destructive_local"}
				})
			},
		},
		{
			name: "basis mismatch",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) {
					basis := o["basis"].(map[string]any)
					basis["gate_id"] = "00000000-0000-0000-0000-000000000000"
				})
			},
		},
		{
			name: "unsupported wire version",
			raw: func(t *testing.T, subject gate.PermissionReviewSubject) []byte {
				return validOutputJSON(t, subject, func(o map[string]any) { o["version"] = "command_safety_output.v2" })
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			subject := validSubject(t)
			_, err := wire.DecodeOutput(subject, tt.raw(t, subject))
			if err == nil {
				t.Fatal("DecodeOutput() error = nil, want error")
			}
			var validationErr *wire.OutputValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("error = %T, want *wire.OutputValidationError", err)
			}
		})
	}
}

func TestDecodeOutputErrorNeverContainsRationale(t *testing.T) {
	t.Parallel()

	subject := validSubject(t)
	secretRationale := "SECRET-RATIONALE-MARKER-should-never-leak"
	raw := validOutputJSON(t, subject, func(o map[string]any) {
		o["risk"] = "high"
		o["rationale"] = secretRationale + strings.Repeat("x", gate.MaxPermissionReviewRationaleBytes)
	})

	_, err := wire.DecodeOutput(subject, raw)
	if err == nil {
		t.Fatal("DecodeOutput() error = nil, want error")
	}
	if strings.Contains(err.Error(), secretRationale) {
		t.Fatalf("DecodeOutput() error leaked rationale content: %v", err)
	}
}

func TestOutputSchemaIsStableAndIndependent(t *testing.T) {
	t.Parallel()

	first := wire.OutputSchema()
	first.Schema[0] = '!'
	second := wire.OutputSchema()
	if len(second.Schema) == 0 || second.Schema[0] == '!' {
		t.Fatal("OutputSchema() shares backing storage across calls")
	}
	if second.Name != wire.OutputSchemaName || !second.Strict {
		t.Fatalf("OutputSchema() = %#v, unexpected name/strict", second)
	}
}
