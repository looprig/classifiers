package evidence

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/looprig/harness/pkg/gate"
	"github.com/looprig/harness/pkg/tool"
)

// ---- evidence_filesystem_stat implements tool.EvidenceObservation --------

func TestPathStatToolImplementsEvidenceObservation(t *testing.T) {
	var _ tool.EvidenceObservation = (*pathStatTool)(nil)
}

func TestPathStatObservedRequirementRecordsValidObservationForExistingFile(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "hello")
	statTool := newPathStatTool(root)

	request, _, err := statTool.PrepareCall(context.Background(), mustExecID(t), `{"path":"a.txt"}`)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	result, err := statTool.InvokableRun(context.Background(), `{"path":"a.txt"}`)
	if err != nil {
		t.Fatalf("InvokableRun: %v", err)
	}

	target, token, ok := statTool.ObservedRequirement(request, result)
	if !ok {
		t.Fatalf("ObservedRequirement: ok = false, want true")
	}
	wantTarget := filepath.Join(root, "a.txt")
	if target != wantTarget {
		t.Errorf("target = %q, want %q", target, wantTarget)
	}
	requirement := gate.ObservationRequirement{Target: target, Token: token}
	if !requirement.Valid() {
		t.Errorf("ObservationRequirement{%q, %q} is not Valid()", target, token)
	}
}

func TestPathStatObservedRequirementRecordsValidObservationForAbsentFile(t *testing.T) {
	root := t.TempDir()
	statTool := newPathStatTool(root)

	request, _, err := statTool.PrepareCall(context.Background(), mustExecID(t), `{"path":"missing.txt"}`)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	result, err := statTool.InvokableRun(context.Background(), `{"path":"missing.txt"}`)
	if err != nil {
		t.Fatalf("InvokableRun: %v", err)
	}

	target, token, ok := statTool.ObservedRequirement(request, result)
	if !ok {
		t.Fatalf("ObservedRequirement: ok = false, want true")
	}
	requirement := gate.ObservationRequirement{Target: target, Token: token}
	if !requirement.Valid() {
		t.Errorf("ObservationRequirement{%q, %q} is not Valid()", target, token)
	}
}

func TestPathStatObservationTokenIsStableAcrossRepeatedCallsWithNoChange(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "hello")
	statTool := newPathStatTool(root)

	request, _, err := statTool.PrepareCall(context.Background(), mustExecID(t), `{"path":"a.txt"}`)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	result, err := statTool.InvokableRun(context.Background(), `{"path":"a.txt"}`)
	if err != nil {
		t.Fatalf("InvokableRun: %v", err)
	}

	_, token1, ok1 := statTool.ObservedRequirement(request, result)
	_, token2, ok2 := statTool.ObservedRequirement(request, result)
	if !ok1 || !ok2 {
		t.Fatalf("ObservedRequirement ok = %v, %v, want true, true", ok1, ok2)
	}
	if token1 != token2 {
		t.Errorf("token changed across repeated calls with no filesystem change: %q != %q", token1, token2)
	}
}

func TestPathStatObservationTokenChangesWhenMtimeChanges(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "hello")
	statTool := newPathStatTool(root)

	request, _, err := statTool.PrepareCall(context.Background(), mustExecID(t), `{"path":"a.txt"}`)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	result, err := statTool.InvokableRun(context.Background(), `{"path":"a.txt"}`)
	if err != nil {
		t.Fatalf("InvokableRun: %v", err)
	}
	_, tokenBefore, ok := statTool.ObservedRequirement(request, result)
	if !ok {
		t.Fatalf("ObservedRequirement: ok = false")
	}

	newTime := time.Now().Add(48 * time.Hour).Truncate(time.Second)
	if err := os.Chtimes(filepath.Join(root, "a.txt"), newTime, newTime); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	result2, err := statTool.InvokableRun(context.Background(), `{"path":"a.txt"}`)
	if err != nil {
		t.Fatalf("InvokableRun (2): %v", err)
	}
	_, tokenAfter, ok := statTool.ObservedRequirement(request, result2)
	if !ok {
		t.Fatalf("ObservedRequirement (2): ok = false")
	}

	if tokenBefore == tokenAfter {
		t.Errorf("token did not change after mtime changed: both %q", tokenBefore)
	}
}

func TestPathStatObservationTokenChangesWhenTargetSwappedForSymlink(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "hello")
	statTool := newPathStatTool(root)

	request, _, err := statTool.PrepareCall(context.Background(), mustExecID(t), `{"path":"a.txt"}`)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	result, err := statTool.InvokableRun(context.Background(), `{"path":"a.txt"}`)
	if err != nil {
		t.Fatalf("InvokableRun: %v", err)
	}
	_, tokenBefore, ok := statTool.ObservedRequirement(request, result)
	if !ok {
		t.Fatalf("ObservedRequirement: ok = false")
	}

	// classic TOCTOU: the real file is swapped for a symlink pointing
	// somewhere else, without the model-supplied path argument changing at
	// all.
	target := filepath.Join(root, "a.txt")
	if err := os.Remove(target); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	mustWrite(t, filepath.Join(root, "elsewhere.txt"), "different contents entirely")
	if err := os.Symlink(filepath.Join(root, "elsewhere.txt"), target); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	result2, err := statTool.InvokableRun(context.Background(), `{"path":"a.txt"}`)
	if err != nil {
		t.Fatalf("InvokableRun (2): %v", err)
	}
	_, tokenAfter, ok := statTool.ObservedRequirement(request, result2)
	if !ok {
		t.Fatalf("ObservedRequirement (2): ok = false")
	}

	if tokenBefore == tokenAfter {
		t.Errorf("token did not change after the real file was swapped for a symlink: both %q", tokenBefore)
	}
}

func TestPathStatObservedRequirementRejectsMismatchedRequirement(t *testing.T) {
	statTool := newPathStatTool(t.TempDir())
	badRequest := tool.Request{
		Requirements: []tool.Requirement{{Kind: KindFilesystemRead, Scope: "/x", Match: "a"}},
	}
	if _, _, ok := statTool.ObservedRequirement(badRequest, tool.TextResult("")); ok {
		t.Errorf("ObservedRequirement with mismatched Kind: ok = true, want false")
	}

	emptyRequest := tool.Request{}
	if _, _, ok := statTool.ObservedRequirement(emptyRequest, tool.TextResult("")); ok {
		t.Errorf("ObservedRequirement with no Requirements: ok = true, want false")
	}
}

// ---- evidence_filesystem_read implements tool.EvidenceObservation --------

func TestReadFileToolImplementsEvidenceObservation(t *testing.T) {
	var _ tool.EvidenceObservation = (*readFileTool)(nil)
}

func TestReadFileObservedRequirementRecordsValidObservation(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "hello world")
	readTool := newReadFileTool(root, 64<<10)

	request, _, err := readTool.PrepareCall(context.Background(), mustExecID(t), `{"path":"a.txt","offset":0,"limit":0}`)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	result, err := readTool.InvokableRun(context.Background(), `{"path":"a.txt","offset":0,"limit":0}`)
	if err != nil {
		t.Fatalf("InvokableRun: %v", err)
	}

	target, token, ok := readTool.ObservedRequirement(request, result)
	if !ok {
		t.Fatalf("ObservedRequirement: ok = false, want true")
	}
	wantTarget := filepath.Join(root, "a.txt")
	if target != wantTarget {
		t.Errorf("target = %q, want %q", target, wantTarget)
	}
	requirement := gate.ObservationRequirement{Target: target, Token: token}
	if !requirement.Valid() {
		t.Errorf("ObservationRequirement{%q, %q} is not Valid()", target, token)
	}
}

func TestReadFileObservationTokenChangesWhenTargetSwappedForSymlink(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.txt"), "hello world")
	readTool := newReadFileTool(root, 64<<10)

	request, _, err := readTool.PrepareCall(context.Background(), mustExecID(t), `{"path":"a.txt","offset":0,"limit":0}`)
	if err != nil {
		t.Fatalf("PrepareCall: %v", err)
	}
	result, err := readTool.InvokableRun(context.Background(), `{"path":"a.txt","offset":0,"limit":0}`)
	if err != nil {
		t.Fatalf("InvokableRun: %v", err)
	}
	_, tokenBefore, ok := readTool.ObservedRequirement(request, result)
	if !ok {
		t.Fatalf("ObservedRequirement: ok = false")
	}

	target := filepath.Join(root, "a.txt")
	if err := os.Remove(target); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	mustWrite(t, filepath.Join(root, "elsewhere.txt"), "hello world") // identical content, different identity
	if err := os.Symlink(filepath.Join(root, "elsewhere.txt"), target); err != nil {
		t.Fatalf("Symlink: %v", err)
	}

	result2, err := readTool.InvokableRun(context.Background(), `{"path":"a.txt","offset":0,"limit":0}`)
	if err != nil {
		t.Fatalf("InvokableRun (2): %v", err)
	}
	_, tokenAfter, ok := readTool.ObservedRequirement(request, result2)
	if !ok {
		t.Fatalf("ObservedRequirement (2): ok = false")
	}

	if tokenBefore == tokenAfter {
		t.Errorf("token did not change after the real file was swapped for a symlink: both %q", tokenBefore)
	}
}

func TestReadFileObservedRequirementRejectsWorkspaceRootTarget(t *testing.T) {
	// A read Requirement always names a specific file (PrepareCall already
	// rejects rel == "."), but ObservedRequirement defends independently
	// against ever reporting an observation for the workspace root itself.
	readTool := newReadFileTool(t.TempDir(), 64<<10)
	request := tool.Request{
		Requirements: []tool.Requirement{{Kind: KindFilesystemRead, Scope: readTool.root, Match: "."}},
	}
	if _, _, ok := readTool.ObservedRequirement(request, tool.TextResult("")); ok {
		t.Errorf("ObservedRequirement with Match \".\": ok = true, want false")
	}
}

// ---- multi-match / aggregate tools do NOT implement the capability -------

func TestMultiMatchAndAggregateToolsDoNotImplementEvidenceObservation(t *testing.T) {
	root := t.TempDir()
	tools := []tool.InvokableTool{
		newListDirectoryTool(root, 500),
		newGlobFilesTool(root, 200),
		newGrepFilesTool(root, 200, 256<<10),
		newGitRepositoryStatusTool(root, resolveGitBinary(), 64<<10),
		newGitDiffTool(root, resolveGitBinary(), 128<<10),
		newGitRemotesTool(root, resolveGitBinary(), nil),
		newGitBranchTool(root, resolveGitBinary()),
	}
	for _, tl := range tools {
		info, err := tl.Info(context.Background())
		if err != nil {
			t.Fatalf("Info: %v", err)
		}
		if _, ok := tl.(tool.EvidenceObservation); ok {
			t.Errorf("%s implements tool.EvidenceObservation, want it not to", info.Name)
		}
	}
}
