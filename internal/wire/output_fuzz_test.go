package wire_test

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/looprig/classifiers/internal/wire"
)

// FuzzDecodeOutput fuzzes the untrusted boundary this classifier accepts
// from the model: the raw structured-output JSON payload DecodeOutput
// strictly decodes and validates against a fixed, trusted subject. This is
// design §22.5's "classifier input and output codecs" and "duplicate JSON
// fields" target for internal/wire, the classifier's strict JSON decoder
// package. subject itself is not fuzzed here — it is Harness-internal,
// trusted data already covered by pkg/gate's own subject-digest and basis
// fuzzing; only the model-controlled raw bytes are the untrusted input this
// package is responsible for.
func FuzzDecodeOutput(f *testing.F) {
	subject := validSubject(f)

	valid := validOutputJSON(f, subject, func(o map[string]any) {
		o["risk"] = "high"
		o["authorization"] = "medium"
		o["categories"] = []string{"destructive_local"}
		o["recommendation"] = "needs_human"
		o["rationale"] = "deletes files outside the workspace"
	})
	f.Add(valid)
	f.Add([]byte(``))
	f.Add([]byte(`null`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`not json`))
	f.Add(append(append([]byte{}, valid...), []byte(`{}`)...)) // trailing content
	f.Add([]byte(strings.Replace(
		string(valid),
		`"version":"command_safety_output.v1"`,
		`"version":"command_safety_output.v1","version":"command_safety_output.v1"`,
		1,
	))) // duplicate top-level key
	f.Add([]byte(strings.Replace(string(valid), `"gate_id"`, `"gate_id","gate_id"`, 1))) // malformed duplicate inside basis
	f.Add([]byte(strings.Replace(string(valid), `"risk":"high"`, `"risk":null`, 1)))     // null masquerading as omitted
	f.Add([]byte(strings.Replace(string(valid), `"categories":["destructive_local"]`, `"categories":null`, 1)))
	f.Add([]byte(strings.Replace(string(valid), `"categories":["destructive_local"]`, `"categories":["destructive_local","destructive_local"]`, 1)))
	f.Add([]byte(strings.Replace(string(valid), `destructive_local`, `made_up_category`, 1)))
	f.Add([]byte(strings.Replace(string(valid), `"risk":"high"`, `"risk":"extreme"`, 1)))
	f.Add([]byte(strings.Repeat(`{"a":`, 20000) + `0` + strings.Repeat(`}`, 20000)))
	f.Add([]byte(`{"version":"command_safety_output.v1","basis":{"gate_id":"` +
		subject.Basis.GateID.String() + `","tool_execution_id":"` + subject.Basis.ToolExecutionID.String() +
		`","subject_digest":"` + hex.EncodeToString(subject.Basis.SubjectDigest[:]) +
		`","context_revision":"context-v1","gate_policy_revision":"gate-policy-v1","classifier_revision":"command-safety-v1",` +
		`"security_ceiling":"workspace-write"},"risk":"low","authorization":"unknown","categories":[],` +
		`"recommendation":"allow","rationale":"` + strings.Repeat("SECRET-RATIONALE-MARKER-x", 500) + `"}`))

	f.Fuzz(func(t *testing.T, raw []byte) {
		subject := validSubject(t)

		assessment, err := wire.DecodeOutput(subject, raw)
		if err != nil {
			var validationErr *wire.OutputValidationError
			if !errors.As(err, &validationErr) {
				t.Fatalf("DecodeOutput() error = %T, want *wire.OutputValidationError", err)
			}
			// The error must never echo the raw fuzz payload: its Error()
			// string is built purely from the small closed Field/Reason
			// enum pair, so its length is always tightly bounded regardless
			// of how large or attacker-crafted raw is.
			if len(err.Error()) > 128 {
				t.Fatalf("DecodeOutput() error length = %d, want bounded (no payload echo): %q", len(err.Error()), err.Error())
			}
			if assessment.Risk != "" || assessment.Authorization != "" || assessment.Recommendation != "" ||
				assessment.Categories != nil || assessment.Rationale != "" {
				t.Fatalf("DecodeOutput() returned non-zero assessment alongside error: %#v", assessment)
			}
			return
		}

		// A successfully decoded assessment must always carry the trusted
		// subject's own basis verbatim, never anything echoed from raw.
		if assessment.Basis != subject.Basis {
			t.Fatalf("DecodeOutput() assessment.Basis = %#v, want subject.Basis %#v", assessment.Basis, subject.Basis)
		}
		if !json.Valid(raw) {
			t.Fatalf("DecodeOutput() accepted non-JSON input")
		}
	})
}
