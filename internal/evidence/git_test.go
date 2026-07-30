package evidence

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func requireGit(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not available in this environment")
	}
	return path
}

// runTestGit runs git directly (NOT through this package's runGit) so tests
// have an authoritative, independent oracle for repository setup and for
// snapshotting state before/after a tool call.
func runTestGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		"GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0",
	)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out.String())
	}
	return out.String()
}

// newGitFixture creates a real repository with one commit and a real binary
// resolution, ready for every concrete git tool.
type gitFixture struct {
	root   string
	binary *gitBinary
}

func newGitFixture(t *testing.T) gitFixture {
	t.Helper()
	requireGit(t)
	root := t.TempDir()
	runTestGit(t, root, "-c", "init.defaultBranch=main", "init")
	mustWrite(t, filepath.Join(root, "tracked.txt"), "line one\n")
	runTestGit(t, root, "add", "tracked.txt")
	runTestGit(t, root, "commit", "-m", "initial commit")
	path, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	return gitFixture{root: root, binary: newGitBinary(path, os.Getenv("PATH"))}
}

// snapshotGit captures repository state (status, HEAD, log, refs) using the
// independent runTestGit oracle, for before/after no-mutation comparison.
type gitSnapshot struct {
	status string
	head   string
	log    string
	refs   string
}

func snapshotGit(t *testing.T, root string) gitSnapshot {
	t.Helper()
	return gitSnapshot{
		status: runTestGit(t, root, "status", "--porcelain=v2", "--branch"),
		head:   runTestGit(t, root, "rev-parse", "HEAD"),
		log:    runTestGit(t, root, "log", "--oneline", "--all"),
		refs:   runTestGit(t, root, "show-ref"),
	}
}

func assertNoGitMutation(t *testing.T, root string, before gitSnapshot) {
	t.Helper()
	after := snapshotGit(t, root)
	if before != after {
		t.Fatalf("git repository state mutated:\nbefore=%+v\nafter=%+v", before, after)
	}
}

// ============================================================================
// SECURITY TESTS
// ============================================================================

func TestSecurity_Git_MalformedArguments(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)

	malformedZeroArg := []string{``, `not json`, `[]`, `null`, `{"x":1}`, `{`}
	zeroArgTools := map[string]evidenceTool{
		toolNameGitRepositoryStatus: newGitRepositoryStatusTool(fx.root, fx.binary, 4096),
		toolNameGitRemotes:          newGitRemotesTool(fx.root, fx.binary, nil),
		toolNameGitBranch:           newGitBranchTool(fx.root, fx.binary),
	}
	for name, et := range zeroArgTools {
		for _, args := range malformedZeroArg {
			name, et, args := name, et, args
			t.Run(name+"/"+truncateForDisplay(args, 20), func(t *testing.T) {
				t.Parallel()
				before := snapshotGit(t, fx.root)
				_, prepErr, _, _ := prepareAndRun(context.Background(), t, et, args)
				if prepErr == nil {
					t.Fatalf("PrepareCall(%q) error = nil, want error", args)
				}
				assertNoGitMutation(t, fx.root, before)
			})
		}
	}

	diffMalformed := []string{
		``, `{"path":"a","ref":""}`, `{"path":"a","staged":false}`,
		`{"ref":"","staged":false}`, `{"path":null,"ref":"","staged":false}`,
		`{"path":"a","ref":"","staged":"no"}`, `{"path":"a","ref":"","staged":false,"extra":1}`,
	}
	dt := newGitDiffTool(fx.root, fx.binary, 4096)
	for _, args := range diffMalformed {
		args := args
		t.Run(toolNameGitDiff+"/"+truncateForDisplay(args, 30), func(t *testing.T) {
			t.Parallel()
			before := snapshotGit(t, fx.root)
			_, prepErr, _, _ := prepareAndRun(context.Background(), t, dt, args)
			if prepErr == nil {
				t.Fatalf("PrepareCall(%q) error = nil, want error", args)
			}
			assertNoGitMutation(t, fx.root, before)
		})
	}
}

func TestSecurity_Git_RefFlagInjectionRejected(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	dt := newGitDiffTool(fx.root, fx.binary, 4096)

	dangerous := []string{
		"--upload-pack=/bin/sh",
		"-oProxyCommand=touch /tmp/pwned",
		"--output=/tmp/pwned",
		"-", "--", "- leading space then dash",
		"a..b", "a...b",
	}
	for _, ref := range dangerous {
		ref := ref
		t.Run(ref, func(t *testing.T) {
			t.Parallel()
			before := snapshotGit(t, fx.root)
			args := fmt.Sprintf(`{"path":".","ref":%q,"staged":false}`, ref)
			_, prepErr, _, _ := prepareAndRun(context.Background(), t, dt, args)
			if prepErr == nil {
				t.Fatalf("PrepareCall(ref=%q) error = nil, want a validation error", ref)
			}
			assertNoGitMutation(t, fx.root, before)
		})
	}
}

func TestSecurity_Git_LeadingDashFilenameIsNotAFlag(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	weird := "-rf-looks-like-a-flag.txt"
	mustWrite(t, filepath.Join(fx.root, weird), "v1\n")
	runTestGit(t, fx.root, "add", "--", weird)
	runTestGit(t, fx.root, "commit", "-m", "add weird file")
	mustWrite(t, filepath.Join(fx.root, weird), "v2\n")

	dt := newGitDiffTool(fx.root, fx.binary, 4096)
	before := snapshotGit(t, fx.root)
	args := fmt.Sprintf(`{"path":%q,"ref":"","staged":false}`, weird)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, dt, args)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "v1") || !strings.Contains(text, "v2") {
		t.Fatalf("diff on leading-dash filename = %q, want to see the actual line change, not a flag error", text)
	}
	assertNoGitMutation(t, fx.root, before)
}

func TestSecurity_Git_Containment(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	requireGit(t)
	root := filepath.Join(base, "workspace")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, root, "-c", "init.defaultBranch=main", "init")
	mustWrite(t, filepath.Join(root, "f.txt"), "x\n")
	runTestGit(t, root, "add", "f.txt")
	runTestGit(t, root, "commit", "-m", "init")

	gitPath, _ := exec.LookPath("git")
	binary := newGitBinary(gitPath, os.Getenv("PATH"))
	dt := newGitDiffTool(root, binary, 4096)

	escaping := []string{"../outside/x", "/etc/passwd", ".."}
	for _, path := range escaping {
		path := path
		t.Run(path, func(t *testing.T) {
			t.Parallel()
			args := fmt.Sprintf(`{"path":%q,"ref":"","staged":false}`, path)
			_, prepErr, _, _ := prepareAndRun(context.Background(), t, dt, args)
			if prepErr == nil {
				t.Fatalf("PrepareCall(path=%q) error = nil, want a containment error", path)
			}
		})
	}
}

func TestSecurity_Git_SanitizedEnvironment(t *testing.T) {
	t.Setenv("SUPER_SECRET_TOKEN", "should-never-appear")
	env := sanitizedGitEnv("/usr/bin:/bin")
	for _, kv := range env {
		if strings.Contains(kv, "SUPER_SECRET_TOKEN") {
			t.Fatalf("sanitizedGitEnv leaked an ambient env var: %v", env)
		}
	}
	var sawHome, sawPath bool
	for _, kv := range env {
		if strings.HasPrefix(kv, "HOME=") {
			sawHome = true
			if strings.Contains(kv, os.Getenv("HOME")) && os.Getenv("HOME") != "" {
				t.Fatalf("sanitizedGitEnv used the real HOME: %v", env)
			}
		}
		if strings.HasPrefix(kv, "PATH=") {
			sawPath = true
		}
	}
	if !sawHome || !sawPath {
		t.Fatalf("sanitizedGitEnv() = %v, want HOME and PATH set", env)
	}
}

// TestSecurity_Git_FsmonitorHookNeutralized proves gitSafeConfig actually
// defuses a hostile repository-local config: without the "core.fsmonitor="
// override, `git status` would execute the configured fsmonitor hook. This
// is the concrete regression test for the exec-safety rationale documented
// on gitSafeConfig.
func TestSecurity_Git_FsmonitorHookNeutralized(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	marker := filepath.Join(t.TempDir(), "pwned")
	hook := filepath.Join(fx.root, "fsmonitor-hook.sh")
	script := "#!/bin/sh\ntouch " + marker + "\nprintf ''\n"
	if err := os.WriteFile(hook, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, fx.root, "config", "core.fsmonitor", hook)

	st := newGitRepositoryStatusTool(fx.root, fx.binary, 4096)
	_, prepErr, _, runErr := prepareAndRun(context.Background(), t, st, `{}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("core.fsmonitor hook executed — gitSafeConfig failed to neutralize it")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

// TestSecurity_Git_DiffExternalNeutralized proves --no-ext-diff plus the
// diff.external= override stop a hostile external-diff config from running.
func TestSecurity_Git_DiffExternalNeutralized(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	marker := filepath.Join(t.TempDir(), "pwned")
	hook := filepath.Join(fx.root, "ext-diff.sh")
	script := "#!/bin/sh\ntouch " + marker + "\n"
	if err := os.WriteFile(hook, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	runTestGit(t, fx.root, "config", "diff.external", hook)
	mustWrite(t, filepath.Join(fx.root, "tracked.txt"), "line one changed\n")

	dt := newGitDiffTool(fx.root, fx.binary, 4096)
	_, prepErr, _, runErr := prepareAndRun(context.Background(), t, dt, `{"path":".","ref":"","staged":false}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatalf("diff.external hook executed — --no-ext-diff/gitSafeConfig failed to neutralize it")
	} else if !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
}

func TestSecurity_Git_Cancellation(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	before := snapshotGit(t, fx.root)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := newGitRepositoryStatusTool(fx.root, fx.binary, 4096)
	_, prepErr, result, runErr := prepareAndRun(ctx, t, st, `{}`)
	if prepErr != nil {
		return
	}
	if runErr == nil {
		t.Fatalf("status with a pre-cancelled context: err = nil, result = %v, want context.Canceled", result)
	}
	if !errors.Is(runErr, context.Canceled) {
		t.Fatalf("status with a pre-cancelled context: err = %v, want context.Canceled", runErr)
	}
	assertNoGitMutation(t, fx.root, before)
}

func TestSecurity_Git_NoMutation_AllTools(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	mustWrite(t, filepath.Join(fx.root, "untracked.txt"), "scratch\n")
	runTestGit(t, fx.root, "remote", "add", "origin", "https://example.com/org/repo.git")
	before := snapshotGit(t, fx.root)

	tools := []evidenceTool{
		newGitRepositoryStatusTool(fx.root, fx.binary, 4096),
		newGitDiffTool(fx.root, fx.binary, 4096),
		newGitRemotesTool(fx.root, fx.binary, nil),
		newGitBranchTool(fx.root, fx.binary),
	}
	argsFor := []string{`{}`, `{"path":".","ref":"","staged":false}`, `{}`, `{}`}
	for i, et := range tools {
		_, prepErr, _, runErr := prepareAndRun(context.Background(), t, et, argsFor[i])
		if prepErr != nil || runErr != nil {
			t.Fatalf("tool %d: prepErr=%v runErr=%v", i, prepErr, runErr)
		}
	}
	assertNoGitMutation(t, fx.root, before)
}

// ============================================================================
// BEHAVIOR TESTS
// ============================================================================

func TestBehavior_Git_RepositoryStatus(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	st := newGitRepositoryStatusTool(fx.root, fx.binary, 4096)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, st, `{}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	for _, want := range []string{"git_repository: true", "is_bare: false", "detached_head: false", "has_commits: true", "current_branch: main"} {
		if !strings.Contains(text, want) {
			t.Fatalf("status = %q, want to contain %q", text, want)
		}
	}
}

func TestBehavior_Git_NotARepository(t *testing.T) {
	t.Parallel()
	requireGit(t)
	root := t.TempDir()
	gitPath, _ := exec.LookPath("git")
	binary := newGitBinary(gitPath, os.Getenv("PATH"))

	tools := map[string]evidenceTool{
		toolNameGitRepositoryStatus: newGitRepositoryStatusTool(root, binary, 4096),
		toolNameGitDiff:             newGitDiffTool(root, binary, 4096),
		toolNameGitRemotes:          newGitRemotesTool(root, binary, nil),
		toolNameGitBranch:           newGitBranchTool(root, binary),
	}
	argsFor := map[string]string{
		toolNameGitRepositoryStatus: `{}`,
		toolNameGitDiff:             `{"path":".","ref":"","staged":false}`,
		toolNameGitRemotes:          `{}`,
		toolNameGitBranch:           `{}`,
	}
	for name, et := range tools {
		name, et := name, et
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, prepErr, result, runErr := prepareAndRun(context.Background(), t, et, argsFor[name])
			if prepErr != nil || runErr != nil {
				t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
			}
			if !strings.Contains(resultText(t, result), "git_repository: false") {
				t.Fatalf("%s over a non-repo dir = %q, want git_repository: false", name, resultText(t, result))
			}
		})
	}
}

// TestBehavior_Git_BinaryUnavailable directly constructs the
// git-binary-unresolvable condition (resolveGitBinary's degrade path when
// exec.LookPath("git") fails, catalog.go) rather than relying on every
// other non-repo test to exercise it only indirectly through
// isGitRepository() == false. It proves gitRun.run's uniform
// errGitUnavailable (git.go) funnels cleanly through every one of the 4 git
// evidence tools to a clean "git_repository: false" result, never a Go
// error or a panic, and does so regardless of whether git happens to be
// installed in this test environment.
func TestBehavior_Git_BinaryUnavailable(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	binary := newGitBinary("", "") // path == "": resolveGitBinary's degrade path.

	tools := map[string]evidenceTool{
		toolNameGitRepositoryStatus: newGitRepositoryStatusTool(root, binary, 4096),
		toolNameGitDiff:             newGitDiffTool(root, binary, 4096),
		toolNameGitRemotes:          newGitRemotesTool(root, binary, nil),
		toolNameGitBranch:           newGitBranchTool(root, binary),
	}
	argsFor := map[string]string{
		toolNameGitRepositoryStatus: `{}`,
		toolNameGitDiff:             `{"path":".","ref":"","staged":false}`,
		toolNameGitRemotes:          `{}`,
		toolNameGitBranch:           `{}`,
	}
	for name, et := range tools {
		name, et := name, et
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, prepErr, result, runErr := prepareAndRun(context.Background(), t, et, argsFor[name])
			if prepErr != nil || runErr != nil {
				t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
			}
			if !strings.Contains(resultText(t, result), "git_repository: false") {
				t.Fatalf("%s with an unresolvable git binary = %q, want git_repository: false", name, resultText(t, result))
			}
		})
	}
}

func TestBehavior_Git_EmptyRepository(t *testing.T) {
	t.Parallel()
	requireGit(t)
	root := t.TempDir()
	runTestGit(t, root, "-c", "init.defaultBranch=main", "init")
	gitPath, _ := exec.LookPath("git")
	binary := newGitBinary(gitPath, os.Getenv("PATH"))

	st := newGitRepositoryStatusTool(root, binary, 4096)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, st, `{}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "has_commits: false") {
		t.Fatalf("empty repo status = %q, want has_commits: false", text)
	}
	if !strings.Contains(text, "git_repository: true") {
		t.Fatalf("empty repo status = %q, want git_repository: true", text)
	}
}

func TestBehavior_Git_DetachedHead(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	sha := strings.TrimSpace(runTestGit(t, fx.root, "rev-parse", "HEAD"))
	runTestGit(t, fx.root, "checkout", "--detach", sha)
	t.Cleanup(func() { runTestGit(t, fx.root, "checkout", "main") })

	bt := newGitBranchTool(fx.root, fx.binary)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, bt, `{}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "detached_head: true") {
		t.Fatalf("branch info in detached HEAD = %q, want detached_head: true", resultText(t, result))
	}
}

func TestBehavior_Git_DiffUnstagedAndStaged(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	mustWrite(t, filepath.Join(fx.root, "tracked.txt"), "line one\nline two\n")
	dt := newGitDiffTool(fx.root, fx.binary, 4096)

	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, dt, `{"path":".","ref":"","staged":false}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "line two") {
		t.Fatalf("unstaged diff = %q, want to see the new line", resultText(t, result))
	}

	runTestGit(t, fx.root, "add", "tracked.txt")
	_, prepErr, result, runErr = prepareAndRun(context.Background(), t, dt, `{"path":".","ref":"","staged":false}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if strings.Contains(resultText(t, result), "line two") {
		t.Fatalf("unstaged diff after staging = %q, want no diff (already staged)", resultText(t, result))
	}

	_, prepErr, result, runErr = prepareAndRun(context.Background(), t, dt, `{"path":".","ref":"","staged":true}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "line two") {
		t.Fatalf("staged diff = %q, want to see the new line", resultText(t, result))
	}
	runTestGit(t, fx.root, "reset", "--hard", "HEAD")
}

// TestBehavior_Git_DiffAgainstExplicitRef proves the "ref" argument actually
// changes the comparison base (git diff [<ref>] [--] <path> positional
// syntax): diffing the current commit against its own parent must show the
// tracked file's full content as added, not an empty diff.
func TestBehavior_Git_DiffAgainstExplicitRef(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	mustWrite(t, filepath.Join(fx.root, "second.txt"), "second file\n")
	runTestGit(t, fx.root, "add", "second.txt")
	runTestGit(t, fx.root, "commit", "-m", "second commit")
	firstSHA := strings.TrimSpace(runTestGit(t, fx.root, "rev-list", "--max-parents=0", "HEAD"))

	dt := newGitDiffTool(fx.root, fx.binary, 4096)

	// Diffing against the default (no ref) sees no changes: nothing is
	// staged or modified relative to HEAD/the index right now.
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, dt, `{"path":".","ref":"","staged":false}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if strings.Contains(resultText(t, result), "second.txt") {
		t.Fatalf("default diff = %q, want no mention of second.txt (nothing uncommitted)", resultText(t, result))
	}

	// Diffing against the FIRST commit (an explicit ref) must show
	// second.txt as newly added — proving ref actually changes the base,
	// not just that it's accepted.
	args := fmt.Sprintf(`{"path":".","ref":%q,"staged":false}`, firstSHA)
	_, prepErr, result, runErr = prepareAndRun(context.Background(), t, dt, args)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "second.txt") || !strings.Contains(text, "second file") {
		t.Fatalf("diff against first commit = %q, want to see second.txt added", text)
	}
}

func TestBehavior_Git_Remotes(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	runTestGit(t, fx.root, "remote", "add", "origin", "https://github.com/example/repo.git")
	runTestGit(t, fx.root, "remote", "add", "upstream", "git@gitlab.com:example/repo.git")

	rt := newGitRemotesTool(fx.root, fx.binary, nil)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, rt, `{}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	for _, want := range []string{"remotes: 2", "origin fetch=https://github.com/example/repo.git hint=github.com visibility=unknown",
		"upstream fetch=git@gitlab.com:example/repo.git hint=gitlab.com visibility=unknown"} {
		if !strings.Contains(text, want) {
			t.Fatalf("remotes = %q, want to contain %q", text, want)
		}
	}
}

// TestSecurity_Git_Remotes_CredentialsStrippedFromModelVisibleResult is the
// fix for a review finding: `git remote -v` output was passed through
// verbatim into the tool result the LLM provider sees. A remote configured
// with embedded userinfo (common in CI checkouts, e.g.
// "https://user:token@host/...") must never leak that credential into
// model-visible evidence, while the credential-free parts of the URL (and
// the visibility hint derived from it) must still be reported.
func TestSecurity_Git_Remotes_CredentialsStrippedFromModelVisibleResult(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	runTestGit(t, fx.root, "remote", "add", "origin", "https://alice:ghp_supersecrettoken@github.com/org/repo.git")

	rt := newGitRemotesTool(fx.root, fx.binary, nil)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, rt, `{}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if strings.Contains(text, "ghp_supersecrettoken") {
		t.Fatalf("model-visible remotes result leaks the embedded credential: %q", text)
	}
	if strings.Contains(text, "alice") {
		t.Fatalf("model-visible remotes result leaks the embedded username: %q", text)
	}
	if !strings.Contains(text, "fetch=https://github.com/org/repo.git") {
		t.Fatalf("model-visible remotes result should still report the credential-free URL: %q", text)
	}
	if !strings.Contains(text, "hint=github.com") {
		t.Fatalf("visibility hint should still be derived from the credential-free host: %q", text)
	}
}

type fakeVisibilityResolver struct {
	result Visibility
	err    error
	calls  int
}

func (f *fakeVisibilityResolver) ResolveVisibility(context.Context, string) (Visibility, error) {
	f.calls++
	return f.result, f.err
}

func TestBehavior_Git_Remotes_InjectedResolver(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	runTestGit(t, fx.root, "remote", "add", "origin", "https://github.com/example/repo.git")

	resolver := &fakeVisibilityResolver{result: VisibilityPrivate}
	rt := newGitRemotesTool(fx.root, fx.binary, resolver)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, rt, `{}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "visibility=private") {
		t.Fatalf("remotes with injected resolver = %q, want visibility=private", resultText(t, result))
	}
	if resolver.calls != 1 {
		t.Fatalf("resolver.calls = %d, want 1", resolver.calls)
	}
}

func TestBehavior_Git_Remotes_ResolverFailsSafe(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	runTestGit(t, fx.root, "remote", "add", "origin", "https://github.com/example/repo.git")

	resolver := &fakeVisibilityResolver{err: errors.New("boom")}
	rt := newGitRemotesTool(fx.root, fx.binary, resolver)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, rt, `{}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "visibility=unknown") {
		t.Fatalf("remotes with a failing resolver = %q, want visibility=unknown (fail-safe)", resultText(t, result))
	}
}

func TestBehavior_Git_Branch_UpstreamAndDefaultBranch(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)

	// A bare repo standing in for a real remote, entirely local (no
	// network): push establishes refs/remotes/origin/main, and `remote
	// set-head` establishes origin/HEAD, without this test needing any
	// outbound network access.
	remote := t.TempDir()
	runTestGit(t, remote, "init", "--bare", "-b", "main")
	runTestGit(t, fx.root, "remote", "add", "origin", remote)
	runTestGit(t, fx.root, "push", "-u", "origin", "main")
	runTestGit(t, fx.root, "remote", "set-head", "origin", "main")

	bt := newGitBranchTool(fx.root, fx.binary)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, bt, `{}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	for _, want := range []string{"upstream: origin/main", "default_branch: main", "default_branch_source: origin/HEAD"} {
		if !strings.Contains(text, want) {
			t.Fatalf("branch = %q, want to contain %q", text, want)
		}
	}
}

func TestBehavior_Git_Branch_NoUpstreamUnknownDefault(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	runTestGit(t, fx.root, "checkout", "-b", "topic")
	runTestGit(t, fx.root, "branch", "-D", "main")
	mustWrite(t, filepath.Join(fx.root, "tracked.txt"), "topic change\n")
	runTestGit(t, fx.root, "commit", "-am", "topic commit")

	bt := newGitBranchTool(fx.root, fx.binary)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, bt, `{}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "upstream: none") {
		t.Fatalf("branch without upstream = %q, want upstream: none", text)
	}
	if !strings.Contains(text, "default_branch: unknown") {
		t.Fatalf("branch without a resolvable default = %q, want default_branch: unknown", text)
	}
}

func TestBehavior_Git_Info_MatchesToolInfosDeclaration(t *testing.T) {
	t.Parallel()
	fx := newGitFixture(t)
	declared := make(map[string]struct{ desc, schema string })
	for _, info := range gitToolInfos() {
		declared[info.Name] = struct{ desc, schema string }{info.Desc, string(info.Schema)}
	}
	tools := map[string]evidenceTool{
		toolNameGitRepositoryStatus: newGitRepositoryStatusTool(fx.root, fx.binary, 4096),
		toolNameGitDiff:             newGitDiffTool(fx.root, fx.binary, 4096),
		toolNameGitRemotes:          newGitRemotesTool(fx.root, fx.binary, nil),
		toolNameGitBranch:           newGitBranchTool(fx.root, fx.binary),
	}
	for name, et := range tools {
		info, err := et.Info(context.Background())
		if err != nil || info == nil {
			t.Fatalf("%s: Info() error = %v", name, err)
		}
		want, ok := declared[name]
		if !ok || info.Desc != want.desc || string(info.Schema) != want.schema {
			t.Fatalf("%s: built Info() drifted from catalog declaration", name)
		}
	}
}
