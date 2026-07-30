package wire_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/looprig/classifiers/internal/wire"
	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/gate"
	"github.com/looprig/harness/pkg/identity"
	"github.com/looprig/harness/pkg/tool"
)

// FuzzMarshalInput fuzzes MarshalInput's projection side of design §22.5's
// "classifier input and output codecs": arbitrary string content flowing
// into an otherwise-valid PermissionReviewSubject must never panic, must
// stay within MaxInputWireBytes, and must marshal deterministically. Subject
// CONSTRUCTION itself (gate.NewPermissionReviewSubject's own invariants) is
// Harness's fuzzed surface, not this package's — a fuzzed input that gate
// itself rejects at construction time is simply skipped here.
func FuzzMarshalInput(f *testing.F) {
	f.Add("run git status", `{"command":"git status"}`, "git status", "run git status")
	f.Add("", "", "", "")
	f.Add("αβγδ current intent", `{"command":"rg TODO"}`, "rg TODO", "search for TODO")
	f.Add(string([]byte{0xff, 0xfe}), "tool evidence", "cmd", "summary")

	f.Fuzz(func(t *testing.T, userContent, actionContent, command, summary string) {
		subject, err := fuzzSubject(userContent, actionContent, command, summary)
		if err != nil {
			return
		}

		first, err := wire.MarshalInput(subject)
		if err != nil {
			var validationErr *wire.InputValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("MarshalInput() error = %T, want *wire.InputValidationError", err)
			}
			if len(err.Error()) > 128 {
				t.Fatalf("MarshalInput() error length = %d, want bounded (no payload echo): %q", len(err.Error()), err.Error())
			}
			if first != nil {
				t.Fatalf("MarshalInput() returned non-nil payload alongside error: %s", first)
			}
			return
		}

		if len(first) > wire.MaxInputWireBytes {
			t.Fatalf("MarshalInput() len = %d, want <= %d", len(first), wire.MaxInputWireBytes)
		}
		if !json.Valid(first) {
			t.Fatalf("MarshalInput() produced invalid JSON: %s", first)
		}
		second, err := wire.MarshalInput(subject)
		if err != nil || string(first) != string(second) {
			t.Fatalf("MarshalInput() is not deterministic for the same subject: err=%v", err)
		}
	})
}

func fuzzSubject(userContent, actionContent, command, summary string) (gate.PermissionReviewSubject, error) {
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
			{Origin: gate.ReviewContextOriginUser, Kind: gate.ReviewContextKindUserMessage, Content: userContent},
			{Origin: gate.ReviewContextOriginAssistant, Kind: gate.ReviewContextKindAssistantToolRequest, Content: actionContent},
		},
	}
	request := tool.Request{
		ToolName:           "Bash",
		Summary:            summary,
		ExecutionID:        toolExecutionID.String(),
		Command:            command,
		WorkingDirectory:   "/workspace/repo",
		ExpiresAtUnixMilli: 1800000000000,
		Requirements: []tool.Requirement{{
			Kind:        tool.CapabilityCommandExecute,
			Match:       command,
			Description: summary,
			GrantClass:  tool.GrantClassCommandStart,
			GrantTarget: command,
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
	return gate.NewPermissionReviewSubject(basis, request, context)
}
