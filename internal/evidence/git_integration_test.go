//go:build integration

package evidence

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestIntegration_Git_SymlinkEscape proves a real symlink inside a real
// repository whose target escapes the workspace root is refused by
// evidence_git_diff's path argument, exactly like the filesystem pack.
func TestIntegration_Git_SymlinkEscape(t *testing.T) {
	fx := newGitFixture(t)
	outside := t.TempDir()
	mustWrite(t, filepath.Join(outside, "secret.txt"), "classified\n")
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(fx.root, "escape.txt")); err != nil {
		t.Fatal(err)
	}
	before := snapshotGit(t, fx.root)

	dt := newGitDiffTool(fx.root, fx.binary, 4096)
	_, prepErr, _, _ := prepareAndRun(context.Background(), t, dt, `{"path":"escape.txt","ref":"","staged":false}`)
	if prepErr == nil {
		t.Fatalf("diff on an escaping symlink: PrepareCall error = nil, want error")
	}
	assertNoGitMutation(t, fx.root, before)
}

// TestIntegration_Git_UnusualFileNames proves spaces, unicode, and a
// leading dash all work correctly through the real git subprocess path,
// exercising the "--" separator's real effect (not just validation logic).
func TestIntegration_Git_UnusualFileNames(t *testing.T) {
	fx := newGitFixture(t)
	names := []string{"has spaces.txt", "unicode-héllo-世界.txt", "-leading-dash-again.txt"}
	for _, name := range names {
		mustWrite(t, filepath.Join(fx.root, name), "v1\n")
		runTestGit(t, fx.root, "add", "--", name)
	}
	runTestGit(t, fx.root, "commit", "-m", "add unusual names")
	for _, name := range names {
		mustWrite(t, filepath.Join(fx.root, name), "v2\n")
	}

	dt := newGitDiffTool(fx.root, fx.binary, 4096)
	st := newGitRepositoryStatusTool(fx.root, fx.binary, 8192)

	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			_, prepErr, result, runErr := prepareAndRun(context.Background(), t, dt,
				`{"path":"`+jsonEscape(name)+`","ref":"","staged":false}`)
			if prepErr != nil || runErr != nil {
				t.Fatalf("diff(%q): prepErr=%v runErr=%v", name, prepErr, runErr)
			}
			if !strings.Contains(resultText(t, result), "v2") {
				t.Fatalf("diff(%q) = %q, want to see the change", name, resultText(t, result))
			}
		})
	}

	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, st, `{}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("status: prepErr=%v runErr=%v", prepErr, runErr)
	}
	for _, name := range names {
		if !strings.Contains(resultText(t, result), name) {
			t.Fatalf("status = %q, want to mention %q", resultText(t, result), name)
		}
	}
	runTestGit(t, fx.root, "checkout", "--", ".")
}

func jsonEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

// TestIntegration_Git_DetachedHead reproduces detached HEAD via a real
// checkout of a real commit sha (not a branch) and confirms every tool
// handles it without panicking.
func TestIntegration_Git_DetachedHead(t *testing.T) {
	fx := newGitFixture(t)
	mustWrite(t, filepath.Join(fx.root, "second.txt"), "x\n")
	runTestGit(t, fx.root, "add", "second.txt")
	runTestGit(t, fx.root, "commit", "-m", "second commit")
	first := strings.TrimSpace(runTestGit(t, fx.root, "rev-list", "--max-parents=0", "HEAD"))
	runTestGit(t, fx.root, "checkout", "--detach", first)
	t.Cleanup(func() { runTestGit(t, fx.root, "checkout", "main") })

	for _, et := range []evidenceTool{
		newGitRepositoryStatusTool(fx.root, fx.binary, 4096),
		newGitBranchTool(fx.root, fx.binary),
	} {
		_, prepErr, result, runErr := prepareAndRun(context.Background(), t, et, `{}`)
		if prepErr != nil || runErr != nil {
			t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
		}
		if !strings.Contains(resultText(t, result), "detached_head: true") {
			t.Fatalf("result = %q, want detached_head: true", resultText(t, result))
		}
	}
}

// TestIntegration_Git_EmptyRepository exercises a freshly `git init`ed
// repository with zero commits against every tool, proving none of them
// panic on "no HEAD" conditions.
func TestIntegration_Git_EmptyRepository(t *testing.T) {
	requireGit(t)
	root := t.TempDir()
	runTestGit(t, root, "-c", "init.defaultBranch=main", "init")
	gitPath, _ := exec.LookPath("git")
	binary := newGitBinary(gitPath, os.Getenv("PATH"))

	tools := map[string]struct {
		et   evidenceTool
		args string
	}{
		toolNameGitRepositoryStatus: {newGitRepositoryStatusTool(root, binary, 4096), `{}`},
		toolNameGitDiff:             {newGitDiffTool(root, binary, 4096), `{"path":".","ref":"","staged":false}`},
		toolNameGitRemotes:          {newGitRemotesTool(root, binary, nil), `{}`},
		toolNameGitBranch:           {newGitBranchTool(root, binary), `{}`},
	}
	for name, tc := range tools {
		name, tc := name, tc
		t.Run(name, func(t *testing.T) {
			_, prepErr, result, runErr := prepareAndRun(context.Background(), t, tc.et, tc.args)
			if prepErr != nil || runErr != nil {
				t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
			}
			if result == nil {
				t.Fatalf("nil result")
			}
		})
	}
}

// TestIntegration_Git_CancellationKillsSubprocess_NoLeakedProcesses proves
// that cancelling ctx genuinely kills the git child process rather than
// merely abandoning the Go-side wait: it fires many concurrent, immediately
// cancelled invocations and then confirms no `git` process remains alive
// whose working directory is this test's fixture (the strongest portable
// signal available without process-tree introspection).
func TestIntegration_Git_CancellationKillsSubprocess_NoLeakedProcesses(t *testing.T) {
	fx := newGitFixture(t)
	st := newGitRepositoryStatusTool(fx.root, fx.binary, 4096)

	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), time.Microsecond)
			defer cancel()
			_, _, _, _ = prepareAndRun(ctx, t, st, `{}`)
		}()
	}
	wg.Wait()

	// Give any (bugged) surviving child a moment to show up, then check the
	// process table for a git process whose argv references this test's
	// temp root.
	time.Sleep(200 * time.Millisecond)
	out, err := exec.Command("ps", "-eo", "pid,command").CombinedOutput()
	if err != nil {
		t.Skipf("cannot enumerate processes on this platform: %v", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.Contains(line, "git") && strings.Contains(line, fx.root) {
			t.Fatalf("leaked git subprocess after cancellation: %s", line)
		}
	}
}

// TestIntegration_Git_BeforeAfterSnapshot_FullPack drives every git tool
// over a realistic repository (multiple commits, a remote, an upstream) and
// asserts a byte-identical independent-oracle snapshot before and after.
func TestIntegration_Git_BeforeAfterSnapshot_FullPack(t *testing.T) {
	fx := newGitFixture(t)
	remote := t.TempDir()
	runTestGit(t, remote, "init", "--bare", "-b", "main")
	runTestGit(t, fx.root, "remote", "add", "origin", remote)
	runTestGit(t, fx.root, "push", "-u", "origin", "main")
	mustWrite(t, filepath.Join(fx.root, "tracked.txt"), "modified\n")
	mustWrite(t, filepath.Join(fx.root, "untracked.txt"), "scratch\n")

	before := snapshotGit(t, fx.root)

	for _, call := range []struct {
		et   evidenceTool
		args string
	}{
		{newGitRepositoryStatusTool(fx.root, fx.binary, 4096), `{}`},
		{newGitDiffTool(fx.root, fx.binary, 4096), `{"path":".","ref":"","staged":false}`},
		{newGitDiffTool(fx.root, fx.binary, 4096), `{"path":".","ref":"","staged":true}`},
		{newGitRemotesTool(fx.root, fx.binary, nil), `{}`},
		{newGitBranchTool(fx.root, fx.binary), `{}`},
	} {
		_, prepErr, _, runErr := prepareAndRun(context.Background(), t, call.et, call.args)
		if prepErr != nil || runErr != nil {
			t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
		}
	}
	assertNoGitMutation(t, fx.root, before)
}
