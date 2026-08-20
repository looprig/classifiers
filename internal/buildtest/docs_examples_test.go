package buildtest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const docsExamplesCommand = "GOWORK=off GOCACHE=/tmp/looprig-classifiers-docs-gocache go test ./examples/..."
const makeTestRaceCommand = "test:\n\tgo test -race ./..."

type docsExamplesManifest struct {
	SchemaVersion int    `json:"schemaVersion"`
	Repository    string `json:"repository"`
	ProofSources  []struct {
		ID     string `json:"id"`
		Type   string `json:"type"`
		Path   string `json:"path"`
		Symbol string `json:"symbol,omitempty"`
	} `json:"proofSources"`
	Examples []struct {
		ID             string            `json:"id"`
		Ecosystem      string            `json:"ecosystem"`
		Owner          string            `json:"owner"`
		SourcePath     string            `json:"sourcePath"`
		Availability   string            `json:"availability"`
		Versions       map[string]string `json:"versions"`
		OfflineCommand string            `json:"offlineCommand"`
		Assertion      string            `json:"assertion"`
		WorkflowPath   string            `json:"workflowPath"`
		JobID          string            `json:"jobId"`
		Cleanup        string            `json:"cleanup"`
		LiveGate       any               `json:"liveGate"`
		ProofIDs       []string          `json:"proofIds"`
	} `json:"examples"`
}

func TestDocsExamplesArtifacts(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	wantProofs := map[string]struct {
		typeName string
		path     string
		symbol   string
	}{
		"example-classifiers-command-safety-construction-fixture": {"executable-fixture", "examples/commandsafety/example_test.go", "Example_newClassifier"},
		"example-classifiers-typed-construction-error-fixture":    {"executable-fixture", "examples/commandsafety/example_test.go", "Example_typedConstructionError"},
		"example-classifiers-deterministic-evaluation-fixture":    {"executable-fixture", "examples/commandsafety/example_test.go", "Example_deterministicEvaluation"},
		"example-classifiers-manifest-contract-test":              {"test", "internal/buildtest/docs_examples_test.go", "TestDocsExamplesArtifacts"},
	}

	data, err := os.ReadFile(filepath.Join(root, "testdata", "docs", "examples.json"))
	if err != nil {
		t.Fatalf("read examples manifest: %v", err)
	}
	var manifest docsExamplesManifest
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("decode examples manifest: %v", err)
	}
	if manifest.SchemaVersion != 1 || manifest.Repository != "classifiers" {
		t.Fatalf("manifest identity = schema %d repository %q", manifest.SchemaVersion, manifest.Repository)
	}

	proofs := make(map[string]bool, len(manifest.ProofSources))
	for _, proof := range manifest.ProofSources {
		want, ok := wantProofs[proof.ID]
		if !ok {
			t.Errorf("unexpected proof source ID %q", proof.ID)
			continue
		}
		if proof.Type != want.typeName || proof.Path != want.path || proof.Symbol != want.symbol {
			t.Errorf("proof %q = type %q path %q symbol %q, want type %q path %q symbol %q", proof.ID, proof.Type, proof.Path, proof.Symbol, want.typeName, want.path, want.symbol)
		}
		if strings.Contains(proof.Path, "#") {
			t.Errorf("proof %q path contains a symbol fragment: %q", proof.ID, proof.Path)
		}
		if _, err := os.Stat(filepath.Join(root, proof.Path)); err != nil {
			t.Errorf("proof %q path does not resolve: %v", proof.ID, err)
		}
		if proofs[proof.ID] {
			t.Errorf("duplicate proof source ID %q", proof.ID)
		}
		proofs[proof.ID] = true
	}
	if len(manifest.ProofSources) != len(wantProofs) {
		t.Errorf("proof source count = %d, want %d", len(manifest.ProofSources), len(wantProofs))
	}
	for proofID := range wantProofs {
		if !proofs[proofID] {
			t.Errorf("missing proof source ID %q", proofID)
		}
	}
	if len(manifest.Examples) != 3 {
		t.Fatalf("manifest examples = %d, want 3", len(manifest.Examples))
	}

	seen := make(map[string]bool, len(manifest.Examples))
	for _, example := range manifest.Examples {
		if !strings.HasPrefix(example.ID, "example-classifiers-") || seen[example.ID] {
			t.Errorf("invalid or duplicate example ID %q", example.ID)
		}
		seen[example.ID] = true
		if example.Ecosystem != "go" || example.Owner != "classifiers" || example.Availability != "source-workspace" {
			t.Errorf("example %q classification is incorrect", example.ID)
		}
		if len(example.Versions) != 1 || example.Versions["github.com/looprig/classifiers"] != "source-workspace" {
			t.Errorf("example %q versions = %#v", example.ID, example.Versions)
		}
		if example.SourcePath != "examples/commandsafety/example_test.go" || example.OfflineCommand != docsExamplesCommand {
			t.Errorf("example %q source/command metadata is incorrect", example.ID)
		}
		if example.Assertion == "" || example.WorkflowPath != ".github/workflows/docs-examples.yml" || example.JobID != "docs-examples" || example.Cleanup == "" || example.LiveGate != nil {
			t.Errorf("example %q has incomplete execution metadata", example.ID)
		}
		if len(example.ProofIDs) < 2 {
			t.Errorf("example %q proofIds = %v, want source and test proofs", example.ID, example.ProofIDs)
		}
		for _, proofID := range example.ProofIDs {
			if !proofs[proofID] {
				t.Errorf("example %q references unknown proof %q", example.ID, proofID)
			}
		}
	}

	workflowData, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "docs-examples.yml"))
	if err != nil {
		t.Fatalf("read docs examples workflow: %v", err)
	}
	workflow := string(workflowData)
	for _, required := range []string{
		"docs-examples:",
		"run: " + docsExamplesCommand,
		"run: GOWORK=off GOCACHE=/tmp/looprig-classifiers-docs-gocache make test",
	} {
		if !strings.Contains(workflow, required) {
			t.Errorf("workflow does not contain %q", required)
		}
	}

	makefileData, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("read Makefile: %v", err)
	}
	if !strings.Contains(string(makefileData), makeTestRaceCommand) {
		t.Errorf("Makefile test target does not contain %q", makeTestRaceCommand)
	}
}
