package commandsafety_test

import (
	"encoding/json"
	"testing"

	"github.com/looprig/classifiers/internal/corpus"
	"github.com/looprig/classifiers/pkg/commandsafety"
	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/gate"
	"github.com/looprig/harness/pkg/hustle"
)

// evaluationCasesFromCorpus builds one commandsafety.EvaluationCase per
// loaded corpus case, wiring each case's Respond function to synthetically
// echo back exactly that case's own Expected assessment (via
// commandsafety.EncodeAssessmentAsModelOutput) — the "fake/client binding"
// Task 22 calls for: no live model is ever consulted.
func evaluationCasesFromCorpus(t *testing.T) []commandsafety.EvaluationCase {
	t.Helper()

	cases, err := corpus.Load()
	if err != nil {
		t.Fatalf("corpus.Load() error = %v", err)
	}

	out := make([]commandsafety.EvaluationCase, len(cases))
	for i, c := range cases {
		c := c
		subject, err := c.Subject()
		if err != nil {
			t.Fatalf("case %q: Subject() error = %v", c.ID, err)
		}
		expected, err := c.ParseExpected()
		if err != nil {
			t.Fatalf("case %q: ParseExpected() error = %v", c.ID, err)
		}
		out[i] = commandsafety.EvaluationCase{
			ID:      c.ID,
			Subject: subject,
			Respond: func(s gate.PermissionReviewSubject) (json.RawMessage, error) {
				return commandsafety.EncodeAssessmentAsModelOutput(
					s, expected.Risk, expected.Authorization, expected.Categories,
					expected.Recommendation, expected.Rationale,
				)
			},
			ExpectedEligible: c.ExpectedEligible,
		}
	}
	return out
}

func TestEncodeAssessmentAsModelOutputRoundTripsThroughValidateResult(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	subject := validSubject(t)

	raw, err := commandsafety.EncodeAssessmentAsModelOutput(
		subject, gate.ReviewRiskLow, gate.ReviewAuthorizationUnknown, nil, gate.ReviewAllow, "",
	)
	if err != nil {
		t.Fatalf("EncodeAssessmentAsModelOutput() error = %v", err)
	}
	assessment, err := classifier.ValidateResult(subject, hustle.Result{Output: raw})
	if err != nil {
		t.Fatalf("ValidateResult() error = %v", err)
	}
	if assessment.Risk != gate.ReviewRiskLow || assessment.Recommendation != gate.ReviewAllow {
		t.Fatalf("ValidateResult() assessment = %#v, want the encoded fields echoed back", assessment)
	}
}

// TestEvaluateCorpusMatchesRealPipeline is Task 22 Step 4/5's core GREEN
// test: it runs the whole corpus through the classifier's real
// MarshalInput/ValidateResult pipeline (which itself invokes internal/wire
// and internal/policy) and Harness's real gate.EvaluatePermissionAssessment,
// and requires the resulting eligibility to match every case's own
// expected_eligible fixture field exactly — proving that field was not
// hand-asserted but is consistent with an actual run of the real pipeline.
func TestEvaluateCorpusMatchesRealPipeline(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	evalCases := evaluationCasesFromCorpus(t)
	report, err := commandsafety.Evaluate(classifier, evalCases, commandsafety.EvaluationOptions{
		CorpusRevision: corpus.Revision,
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(report.Failures) != 0 {
		t.Fatalf("Evaluate() report.Failures = %#v, want none", report.Failures)
	}
	if len(report.Mismatches) != 0 {
		t.Fatalf("Evaluate() report.Mismatches = %#v, want none (every case's expected_eligible must match the real pipeline's result)", report.Mismatches)
	}
	if report.ConfusionMatrix.FalseAllow != 0 {
		t.Fatalf("Evaluate() report.ConfusionMatrix.FalseAllow = %d, want 0", report.ConfusionMatrix.FalseAllow)
	}
	if report.ConfusionMatrix.FalseHuman != 0 {
		t.Fatalf("Evaluate() report.ConfusionMatrix.FalseHuman = %d, want 0", report.ConfusionMatrix.FalseHuman)
	}
	if report.TotalCases != len(evalCases) {
		t.Fatalf("Evaluate() report.TotalCases = %d, want %d", report.TotalCases, len(evalCases))
	}
}

// TestEvaluateCorpusHasNoCriticalFalseAllows is Task 22 Step 5's first hard
// gate, enforced as a real assertion rather than a report field a human
// might not notice.
func TestEvaluateCorpusHasNoCriticalFalseAllows(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	report, err := commandsafety.Evaluate(classifier, evaluationCasesFromCorpus(t), commandsafety.EvaluationOptions{
		CorpusRevision: corpus.Revision,
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if report.CriticalFalseAllows != 0 {
		t.Fatalf("Evaluate() report.CriticalFalseAllows = %d, want 0", report.CriticalFalseAllows)
	}
	if report.HighRiskFalseAllows != 0 {
		t.Fatalf("Evaluate() report.HighRiskFalseAllows = %d, want 0", report.HighRiskFalseAllows)
	}
}

func TestEvaluateReportsClassifierIdentity(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	report, err := commandsafety.Evaluate(classifier, evaluationCasesFromCorpus(t), commandsafety.EvaluationOptions{
		CorpusRevision: corpus.Revision,
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if report.ClassifierName != string(classifier.Name()) {
		t.Fatalf("report.ClassifierName = %q, want %q", report.ClassifierName, classifier.Name())
	}
	if report.ClassifierRevision != classifier.Revision() {
		t.Fatalf("report.ClassifierRevision = %q, want %q", report.ClassifierRevision, classifier.Revision())
	}
	if report.CorpusRevision != corpus.Revision {
		t.Fatalf("report.CorpusRevision = %q, want %q", report.CorpusRevision, corpus.Revision)
	}
	if report.ModelIdentity == "" {
		t.Fatal("report.ModelIdentity is empty")
	}
}

// TestEvaluateRejectsMismatchedBasis covers the "basis mismatch" completeness
// requirement directly against the runner: a model response whose echoed
// basis does not match the subject it was generated for must be rejected by
// the real classifier pipeline and surfaced as a bounded per-case failure,
// never silently treated as an eligible or ineligible result.
func TestEvaluateRejectsMismatchedBasis(t *testing.T) {
	t.Parallel()

	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	subject := validSubject(t)
	other := subject.Clone()
	other.Basis.GateID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

	evalCase := commandsafety.EvaluationCase{
		ID:      "basis-mismatch-case",
		Subject: subject,
		Respond: func(s gate.PermissionReviewSubject) (json.RawMessage, error) {
			// Echo back a basis matching a DIFFERENT subject than the one
			// under review, simulating a corrupted or replayed model
			// response.
			return commandsafety.EncodeAssessmentAsModelOutput(
				other, gate.ReviewRiskLow, gate.ReviewAuthorizationUnknown, nil, gate.ReviewAllow, "",
			)
		},
		ExpectedEligible: true,
	}

	report, err := commandsafety.Evaluate(classifier, []commandsafety.EvaluationCase{evalCase}, commandsafety.EvaluationOptions{
		CorpusRevision: "basis-mismatch-test/v1",
	})
	if err != nil {
		t.Fatalf("Evaluate() error = %v", err)
	}
	if len(report.Failures) != 1 {
		t.Fatalf("report.Failures = %#v, want exactly one failure", report.Failures)
	}
	if report.Failures[0].ID != "basis-mismatch-case" {
		t.Fatalf("report.Failures[0].ID = %q, want %q", report.Failures[0].ID, "basis-mismatch-case")
	}
	if report.TotalCases != 1 {
		t.Fatalf("report.TotalCases = %d, want 1", report.TotalCases)
	}
	if report.ConfusionMatrix.TrueAllow+report.ConfusionMatrix.TrueHuman+
		report.ConfusionMatrix.FalseAllow+report.ConfusionMatrix.FalseHuman != 0 {
		t.Fatalf("report.ConfusionMatrix = %#v, want a failed case to contribute nothing", report.ConfusionMatrix)
	}
}

func TestEvaluateRejectsNilClassifier(t *testing.T) {
	t.Parallel()
	_, err := commandsafety.Evaluate(nil, nil, commandsafety.EvaluationOptions{CorpusRevision: "x"})
	if err == nil {
		t.Fatal("Evaluate(nil, ...) error = nil, want error")
	}
}

func TestEvaluateRejectsEmptyCases(t *testing.T) {
	t.Parallel()
	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = commandsafety.Evaluate(classifier, nil, commandsafety.EvaluationOptions{CorpusRevision: "x"})
	if err == nil {
		t.Fatal("Evaluate(classifier, nil, ...) error = nil, want error")
	}
}

func TestEvaluateRejectsEmptyCorpusRevision(t *testing.T) {
	t.Parallel()
	classifier, err := commandsafety.New(validOptions())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	_, err = commandsafety.Evaluate(classifier, evaluationCasesFromCorpus(t), commandsafety.EvaluationOptions{})
	if err == nil {
		t.Fatal("Evaluate() with an empty CorpusRevision error = nil, want error")
	}
}
