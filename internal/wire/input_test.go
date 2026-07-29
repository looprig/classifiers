package wire_test

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/looprig/classifiers/internal/wire"
	"github.com/looprig/harness/pkg/gate"
	"github.com/looprig/harness/pkg/tool"
)

func TestMarshalInputProducesDeterministicVersionedPayload(t *testing.T) {
	t.Parallel()

	subject := validSubject(t)
	first, err := wire.MarshalInput(subject)
	if err != nil {
		t.Fatalf("MarshalInput() error = %v", err)
	}
	second, err := wire.MarshalInput(subject)
	if err != nil {
		t.Fatalf("MarshalInput() error = %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("MarshalInput() is not deterministic for the same subject")
	}

	var decoded map[string]any
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if decoded["version"] != wire.InputWireVersion {
		t.Fatalf("MarshalInput() version = %v, want %v", decoded["version"], wire.InputWireVersion)
	}
	basis, ok := decoded["basis"].(map[string]any)
	if !ok {
		t.Fatal("MarshalInput() basis is not an object")
	}
	if basis["gate_id"] != subject.Basis.GateID.String() {
		t.Fatalf("MarshalInput() basis.gate_id = %v, want %v", basis["gate_id"], subject.Basis.GateID.String())
	}
	request, ok := decoded["request"].(map[string]any)
	if !ok || request["command"] != subject.Request.Command {
		t.Fatalf("MarshalInput() request.command = %#v, want %q", request, subject.Request.Command)
	}
}

func TestMarshalInputRejectsInvalidSubject(t *testing.T) {
	t.Parallel()

	_, err := wire.MarshalInput(gate.PermissionReviewSubject{})
	if err == nil {
		t.Fatal("MarshalInput() error = nil, want error for zero-value subject")
	}
	var validationErr *wire.InputValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T, want *wire.InputValidationError", err)
	}
}

func TestMarshalInputRejectsBasisDigestMismatch(t *testing.T) {
	t.Parallel()

	subject := validSubject(t)
	subject.Basis.SubjectDigest[0] ^= 0xFF

	_, err := wire.MarshalInput(subject)
	if err == nil {
		t.Fatal("MarshalInput() error = nil, want error for a tampered subject digest")
	}
	var validationErr *wire.InputValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("error = %T, want *wire.InputValidationError", err)
	}
}

func TestMarshalInputCarriesCommandExecuteRequirement(t *testing.T) {
	t.Parallel()

	subject := validSubject(t)
	raw, err := wire.MarshalInput(subject)
	if err != nil {
		t.Fatalf("MarshalInput() error = %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	request := decoded["request"].(map[string]any)
	requirements, ok := request["requirements"].([]any)
	if !ok || len(requirements) != 1 {
		t.Fatalf("MarshalInput() request.requirements = %#v, want one requirement", request["requirements"])
	}
	first := requirements[0].(map[string]any)
	if first["kind"] != tool.CapabilityCommandExecute {
		t.Fatalf("MarshalInput() requirements[0].kind = %v, want %v", first["kind"], tool.CapabilityCommandExecute)
	}
}
