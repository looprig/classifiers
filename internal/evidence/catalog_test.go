package evidence

import (
	"context"
	"testing"

	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/tool"
)

// ============================================================================
// SECURITY TESTS
// ============================================================================

// TestSecurity_Catalog_RequirementsAreWorkspaceReadOnly proves every
// definition this package hands to Harness declares ONLY
// tool.RequiresWorkspaceRead — never the generic, mutation-capable
// tool.RequiresWorkspace (design §12.2: "Generic mutation-capable
// RequiresWorkspace definitions are invalid in evidence policies").
func TestSecurity_Catalog_RequirementsAreWorkspaceReadOnly(t *testing.T) {
	t.Parallel()
	for _, def := range Definitions(DefaultLimits(), nil) {
		if def.Requirements() != tool.RequiresWorkspaceRead {
			t.Fatalf("%s: Requirements() = %v, want exactly tool.RequiresWorkspaceRead", def.Name(), def.Requirements())
		}
	}
}

// TestSecurity_Catalog_BuildRejectsMissingReadWorkspace proves a definition
// refuses to build any tool at all without an explicit ReadWorkspace
// binding — it must never fall back to some other ambient root.
func TestSecurity_Catalog_BuildRejectsMissingReadWorkspace(t *testing.T) {
	t.Parallel()
	for _, def := range Definitions(DefaultLimits(), nil) {
		id, err := uuid.New()
		if err != nil {
			t.Fatal(err)
		}
		_, err = def.Build(context.Background(), tool.Bindings{SessionID: id, LoopID: id})
		if err == nil {
			t.Fatalf("%s: Build without ReadWorkspace error = nil, want error", def.Name())
		}
	}
}

// TestSecurity_Catalog_LimitsNeverExceedHardCeilings proves an
// adversarially large (or negative) consumer-configured Limits value is
// clamped, never trusted verbatim — a misconfigured consumer must not be
// able to defeat this package's own source-level bounding.
func TestSecurity_Catalog_LimitsNeverExceedHardCeilings(t *testing.T) {
	t.Parallel()
	huge := Limits{
		MaxListEntries:   1 << 30,
		MaxReadBytes:     1 << 30,
		MaxGlobMatches:   1 << 30,
		MaxGrepMatches:   1 << 30,
		MaxGrepFileBytes: 1 << 30,
		MaxStatusBytes:   1 << 30,
		MaxDiffBytes:     1 << 30,
	}.normalize()
	if huge.MaxListEntries != hardMaxListEntries {
		t.Errorf("MaxListEntries = %d, want clamped to %d", huge.MaxListEntries, hardMaxListEntries)
	}
	if huge.MaxReadBytes != hardMaxReadBytes {
		t.Errorf("MaxReadBytes = %d, want clamped to %d", huge.MaxReadBytes, hardMaxReadBytes)
	}
	if huge.MaxGlobMatches != hardMaxGlobMatches {
		t.Errorf("MaxGlobMatches = %d, want clamped to %d", huge.MaxGlobMatches, hardMaxGlobMatches)
	}
	if huge.MaxGrepMatches != hardMaxGrepMatches {
		t.Errorf("MaxGrepMatches = %d, want clamped to %d", huge.MaxGrepMatches, hardMaxGrepMatches)
	}
	if huge.MaxGrepFileBytes != hardMaxGrepFileBytes {
		t.Errorf("MaxGrepFileBytes = %d, want clamped to %d", huge.MaxGrepFileBytes, hardMaxGrepFileBytes)
	}
	if huge.MaxStatusBytes != hardMaxGitOutputBytes {
		t.Errorf("MaxStatusBytes = %d, want clamped to %d", huge.MaxStatusBytes, hardMaxGitOutputBytes)
	}
	if huge.MaxDiffBytes != hardMaxGitOutputBytes {
		t.Errorf("MaxDiffBytes = %d, want clamped to %d", huge.MaxDiffBytes, hardMaxGitOutputBytes)
	}

	negative := Limits{MaxListEntries: -1, MaxReadBytes: -1}.normalize()
	def := DefaultLimits()
	if negative.MaxListEntries != def.MaxListEntries || negative.MaxReadBytes != def.MaxReadBytes {
		t.Errorf("negative Limits did not fall back to defaults: %+v", negative)
	}
}

// ============================================================================
// BEHAVIOR TESTS
// ============================================================================

func TestBehavior_Catalog_DefinitionsProduceExpectedToolNames(t *testing.T) {
	t.Parallel()
	defs := Definitions(DefaultLimits(), nil)
	if len(defs) != 2 {
		t.Fatalf("len(Definitions()) = %d, want 2", len(defs))
	}

	wantFilesystem := []string{
		toolNameFilesystemStat, toolNameFilesystemList, toolNameFilesystemRead,
		toolNameFilesystemGlob, toolNameFilesystemGrep,
	}
	wantGit := []string{
		toolNameGitRepositoryStatus, toolNameGitDiff, toolNameGitRemotes, toolNameGitBranch,
	}

	assertSameSet(t, defs[0].ProducedToolNames(), wantFilesystem)
	assertSameSet(t, defs[1].ProducedToolNames(), wantGit)
}

func assertSameSet(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	set := make(map[string]struct{}, len(want))
	for _, w := range want {
		set[w] = struct{}{}
	}
	for _, g := range got {
		if _, ok := set[g]; !ok {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestBehavior_Catalog_BuildProducesWorkingTools(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	id, err := uuid.New()
	if err != nil {
		t.Fatal(err)
	}
	bindings := tool.Bindings{SessionID: id, LoopID: id, ReadWorkspace: &tool.ReadWorkspaceBinding{Root: root}}

	for _, def := range Definitions(DefaultLimits(), nil) {
		built, err := def.Build(context.Background(), bindings)
		if err != nil {
			t.Fatalf("%s: Build() error = %v", def.Name(), err)
		}
		if len(built) != len(def.ProducedToolNames()) {
			t.Fatalf("%s: Build() produced %d tools, want %d", def.Name(), len(built), len(def.ProducedToolNames()))
		}
		for _, builtTool := range built {
			info, err := builtTool.Info(context.Background())
			if err != nil || info == nil || info.Name == "" {
				t.Fatalf("%s: built tool Info() = %v, %v", def.Name(), info, err)
			}
			if _, ok := builtTool.(tool.CallPreparer); !ok {
				t.Fatalf("%s: %s does not implement tool.CallPreparer (design §13.1 requires it)", def.Name(), info.Name)
			}
		}
	}
}

// TestBehavior_Catalog_RequirementKindsMatchesDeclaredConstants proves
// RequirementKinds() returns exactly the six Requirement.Kind constants this
// package's PrepareCall implementations declare (path.go's five filesystem
// kinds plus git.go's single shared git-read kind) — the introspection point
// pkg/commandsafety.RequiredEvidenceKinds derives its public answer from.
func TestBehavior_Catalog_RequirementKindsMatchesDeclaredConstants(t *testing.T) {
	t.Parallel()
	want := []string{
		KindFilesystemStat, KindFilesystemList, KindFilesystemRead,
		KindFilesystemGlob, KindFilesystemGrep, KindGitRead,
	}
	assertSameSet(t, RequirementKinds(), want)
}

// TestBehavior_Catalog_RequirementKindsReturnsDefensiveCopy proves mutating
// one call's returned slice cannot affect a later call's result.
func TestBehavior_Catalog_RequirementKindsReturnsDefensiveCopy(t *testing.T) {
	t.Parallel()
	first := RequirementKinds()
	for i := range first {
		first[i] = "mutated"
	}
	second := RequirementKinds()
	for _, kind := range second {
		if kind == "mutated" {
			t.Fatalf("RequirementKinds() second call = %v, want unaffected by mutation of first call's result", second)
		}
	}
}

// TestBehavior_Catalog_DefinitionsSatisfyEvidenceKindDeclarer proves every
// definition Definitions returns implements Harness's optional
// tool.EvidenceKindDeclarer capability (pkg/tool's EvidenceKindDeclarer),
// and that EvidenceRequirementKinds() reports exactly the same set as
// RequirementKinds() — the single source of truth this package's evidence
// tools declare their Requirement.Kind values from (see requirementKinds).
// Without this, Harness's construction-time
// internal/hustleruntime.validateEvidenceAllowedKinds fail-fast check
// silently skips every one of this package's evidence-tool definitions (its
// `declarer, ok := definition.(tool.EvidenceKindDeclarer); if !ok { continue }`
// probe), so a consumer AllowedKinds/Requirement.Kind mismatch would only
// ever surface later, deep inside a live evidence-tool call.
func TestBehavior_Catalog_DefinitionsSatisfyEvidenceKindDeclarer(t *testing.T) {
	t.Parallel()
	want := RequirementKinds()
	for _, def := range Definitions(DefaultLimits(), nil) {
		declarer, ok := def.(tool.EvidenceKindDeclarer)
		if !ok {
			t.Fatalf("%s: does not implement tool.EvidenceKindDeclarer", def.Name())
		}
		assertSameSet(t, declarer.EvidenceRequirementKinds(), want)
	}
}

func TestBehavior_Catalog_DefaultLimitsAreWithinHardCeilings(t *testing.T) {
	t.Parallel()
	d := DefaultLimits()
	if d.MaxListEntries <= 0 || d.MaxListEntries > hardMaxListEntries {
		t.Errorf("DefaultLimits().MaxListEntries = %d out of bounds", d.MaxListEntries)
	}
	if d.MaxReadBytes <= 0 || d.MaxReadBytes > hardMaxReadBytes {
		t.Errorf("DefaultLimits().MaxReadBytes = %d out of bounds", d.MaxReadBytes)
	}
	if d.MaxGlobMatches <= 0 || d.MaxGlobMatches > hardMaxGlobMatches {
		t.Errorf("DefaultLimits().MaxGlobMatches = %d out of bounds", d.MaxGlobMatches)
	}
	if d.MaxGrepMatches <= 0 || d.MaxGrepMatches > hardMaxGrepMatches {
		t.Errorf("DefaultLimits().MaxGrepMatches = %d out of bounds", d.MaxGrepMatches)
	}
}
