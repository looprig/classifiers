package commandsafety

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"time"

	"github.com/looprig/classifiers/internal/prompt"
	"github.com/looprig/classifiers/internal/wire"
	"github.com/looprig/harness/pkg/gate"
	"github.com/looprig/harness/pkg/hustle"
	"github.com/looprig/harness/pkg/tool"
	"github.com/looprig/inference"
	model "github.com/looprig/inference/model"
)

// Name is the stable registration name of the command-safety classifier.
const Name hustle.Name = "gate.command-safety"

const (
	// timeout bounds one invocation, including its evidence-tool loop.
	timeout = 90 * time.Second
	// inputBytes/outputBytes bound the serialized hustle request/response.
	// outputBytes intentionally matches wire.MaxOutputWireBytes: the model's
	// structured output can never legitimately exceed what the output codec
	// will accept.
	inputBytes  = 1 << 20
	outputBytes = wire.MaxOutputWireBytes

	evidenceRevision            = "command-safety-evidence/v1"
	placeholderEvidenceToolName = "command_safety_placeholder_evidence"
	placeholderEvidenceToolDesc = "Placeholder read-only evidence tool. It performs no investigation " +
		"and always reports that no real evidence is available; a later task replaces it with " +
		"filesystem and repository evidence tools."
)

// Policy is the consumer-tunable command-safety risk policy. Its shape is
// intentionally minimal for now: Revision alone participates in classifier
// identity (see Definition().Descriptor().PolicyRevision). A later task adds
// the deterministic risk/applicability matrix this type will carry; this
// task establishes only its construction shape, immutability, and cloning.
type Policy struct {
	Revision string
}

// Clone returns an independently owned copy. Policy is currently value-only
// (no reference fields), so Clone is a plain copy; it exists so callers and
// future fields (once Task 20 adds slice/map policy data) have a stable,
// forward-compatible defensive-copy contract.
func (p Policy) Clone() Policy {
	return p
}

// DefaultPolicy returns the initial command-safety policy revision. Its
// matrix content is filled in by a later task; today it establishes only a
// stable, non-empty revision label.
func DefaultPolicy() Policy {
	return Policy{Revision: "command-safety-policy/v1"}
}

// ReadEvidencePolicy configures the read-only evidence collection used by
// StandardEvidence. It carries no fields yet: this task establishes the
// stable construction shape a later task (filesystem and repository
// evidence tools) will extend.
type ReadEvidencePolicy struct{}

// StandardEvidence returns the command-safety classifier's evidence-tool
// policy. Today it carries exactly one placeholder, read-only,
// zero-requirement evidence tool — the minimal non-empty policy Harness's
// hustle definition machinery structurally requires for a tool-using
// structured classifier (see hustle.WithEvidenceTools /
// hustle.DefinitionDescriptor.StructuredOutputWithTools). A later task
// replaces this placeholder with real filesystem and repository evidence
// tools without changing this function's signature.
func StandardEvidence(_ ReadEvidencePolicy) hustle.EvidenceToolPolicy {
	return hustle.EvidenceToolPolicy{
		Revision: evidenceRevision,
		Limits: hustle.ToolLoopLimits{
			MaxRounds:        1,
			MaxCalls:         1,
			MaxCallsPerRound: 1,
			MaxResultBytes:   4096,
			MaxEvidenceBytes: 4096,
		},
		Definitions: []tool.Definition{tool.NewEvidenceDefinition(
			placeholderEvidenceToolName,
			0,
			[]tool.ToolInfo{{
				Name:   placeholderEvidenceToolName,
				Desc:   placeholderEvidenceToolDesc,
				Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
			}},
			func(context.Context, tool.EvidenceFactoryBindings) ([]tool.InvokableTool, error) {
				return []tool.InvokableTool{&placeholderEvidenceTool{}}, nil
			},
		)},
	}
}

type placeholderEvidenceTool struct{}

func (*placeholderEvidenceTool) Info(context.Context) (*tool.ToolInfo, error) {
	return &tool.ToolInfo{
		Name:   placeholderEvidenceToolName,
		Desc:   placeholderEvidenceToolDesc,
		Schema: json.RawMessage(`{"type":"object","additionalProperties":false}`),
	}, nil
}

func (*placeholderEvidenceTool) InvokableRun(context.Context, string) (*tool.ToolResult, error) {
	return tool.TextResult("no evidence tools are implemented yet"), nil
}

// Options configures New. Inference and Model together become the
// classifier's immutable named model binding; Policy and Evidence become
// its immutable local policy and evidence-tool catalog.
type Options struct {
	Inference inference.Client
	Model     model.Model
	Policy    Policy
	Evidence  hustle.EvidenceToolPolicy
}

// ConstructionField identifies the Options field a construction error
// concerns.
type ConstructionField string

const (
	FieldInference         ConstructionField = "inference"
	FieldModel             ConstructionField = "model"
	FieldModelCapabilities ConstructionField = "model_capabilities"
	FieldPolicy            ConstructionField = "policy"
	FieldEvidence          ConstructionField = "evidence"
	FieldDefinition        ConstructionField = "definition"
)

// ConstructionError reports why New rejected its Options. Cause, when
// present, is an already secret-free typed error from Harness's own
// construction machinery (hustle.DefinitionError, model.ValidationError):
// never raw request content.
type ConstructionError struct {
	Field ConstructionField
	Cause error
}

func (e *ConstructionError) Error() string {
	message := "commandsafety: invalid construction (" + string(e.Field) + ")"
	if e.Cause != nil {
		message += ": " + e.Cause.Error()
	}
	return message
}

func (e *ConstructionError) Unwrap() error { return e.Cause }

// Classifier is the command-safety gate.PermissionClassifier implementation.
// Its zero value is invalid; construct one with New.
type Classifier struct {
	definition hustle.Definition
	revision   string
}

// New validates options and returns an immutable command-safety classifier.
//
// It requires a non-nil (including non-typed-nil) inference client, a
// structurally valid model that additionally advertises Tools,
// StructuredOutput, and StructuredOutputWithTools (design §12.3: a
// tool-using structured Hustle requires all three), a non-empty policy
// revision, and an evidence-tool policy hustle.Define accepts. Every
// rejection is a typed *ConstructionError; no supplied value is echoed.
func New(options Options) (*Classifier, error) {
	if nilInferenceClient(options.Inference) {
		return nil, &ConstructionError{Field: FieldInference}
	}
	if err := options.Model.Validate(); err != nil {
		return nil, &ConstructionError{Field: FieldModel, Cause: err}
	}
	if !options.Model.Caps.Tools || !options.Model.Caps.StructuredOutput || !options.Model.Caps.StructuredOutputWithTools {
		return nil, &ConstructionError{Field: FieldModelCapabilities}
	}
	policyRevision := strings.TrimSpace(options.Policy.Revision)
	if policyRevision == "" {
		return nil, &ConstructionError{Field: FieldPolicy}
	}
	// A tool-using structured Hustle (design §12.3) requires at least one
	// evidence tool definition: hustle.EvidenceToolPolicy{} (the zero value)
	// is a structurally valid "evidence tools disabled" policy to
	// hustle.Define, but a disabled policy would silently build a
	// definition with StructuredOutputWithTools == false, which
	// gate.NewPermissionClassifierSet later rejects outright. Fail here,
	// at construction, with a typed and specific reason instead.
	if len(options.Evidence.Definitions) == 0 {
		return nil, &ConstructionError{Field: FieldEvidence}
	}

	definition, err := hustle.Define(
		hustle.WithName(Name),
		hustle.WithParticipation(hustle.ParticipationBlocking),
		hustle.WithTimeout(timeout),
		hustle.WithLimits(hustle.Limits{InputBytes: inputBytes, OutputBytes: outputBytes}),
		hustle.WithNamedInference(options.Inference, options.Model),
		hustle.WithSystemPrompt(prompt.CommandSafety(), prompt.CommandSafetyRevision),
		hustle.WithPolicyRevision(policyRevision),
		hustle.WithOutputSchema(wire.OutputSchema()),
		hustle.WithEvidenceTools(options.Evidence),
	)
	if err != nil {
		return nil, &ConstructionError{Field: FieldDefinition, Cause: err}
	}

	return &Classifier{definition: definition, revision: policyRevision}, nil
}

// Name returns the classifier's stable registration name.
func (c *Classifier) Name() hustle.Name { return Name }

// Revision returns the classifier's active policy revision.
func (c *Classifier) Revision() string { return c.revision }

// Definition returns the classifier's immutable hustle definition.
func (c *Classifier) Definition() hustle.Definition { return c.definition }

// Applies reports whether subject's prepared request contains a
// command-execution requirement. Applicability is based on the typed
// tool.CapabilityCommandExecute requirement kind, never a tool display
// name (design §19.1). A later task extends this to the fuller
// command-triggered filesystem/network combination.
func (c *Classifier) Applies(subject gate.PermissionReviewSubject) bool {
	for _, requirement := range subject.Request.Requirements {
		if requirement.Kind == tool.CapabilityCommandExecute {
			return true
		}
	}
	return false
}

// MarshalInput projects subject into the classifier's versioned model input.
func (c *Classifier) MarshalInput(subject gate.PermissionReviewSubject) (json.RawMessage, error) {
	return wire.MarshalInput(subject)
}

// ValidateResult strictly decodes and validates one hustle result against
// subject, returning the resulting PermissionAssessment. It never returns
// an assessment whose Basis differs from subject.Basis.
func (c *Classifier) ValidateResult(
	subject gate.PermissionReviewSubject,
	result hustle.Result,
) (gate.PermissionAssessment, error) {
	return wire.DecodeOutput(subject, result.Output)
}

// nilInferenceClient reports whether client is nil, including a typed nil
// concrete value boxed in the interface (a plain `client == nil` check
// misses that case).
func nilInferenceClient(client inference.Client) bool {
	if client == nil {
		return true
	}
	value := reflect.ValueOf(client)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

var _ gate.PermissionClassifier = (*Classifier)(nil)
