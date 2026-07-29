package evidence

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/looprig/core/content"
	"github.com/looprig/core/uuid"
	"github.com/looprig/harness/pkg/tool"
)

// ---- shared test infrastructure ---------------------------------------------

// evidenceTool is the combined interface every concrete tool in this package
// implements: PrepareCall (required by design §13.1's "every tool must
// implement tool.CallPreparer") followed by InvokableRun, matching exactly
// how Harness's evidence runner drives a call.
type evidenceTool interface {
	tool.InvokableTool
	tool.CallPreparer
}

// mustExecID mints a fresh execution id for a test call.
func mustExecID(t *testing.T) uuid.UUID {
	t.Helper()
	id, err := uuid.New()
	if err != nil {
		t.Fatalf("uuid.New() error = %v", err)
	}
	return id
}

// prepareAndRun drives et exactly the way evidence_runner.run does: PrepareCall
// once, then (only if it succeeded) InvokableRun with the SAME argsJSON. It
// returns the prepared request/error and the run result/error separately so
// tests can assert on either stage.
func prepareAndRun(ctx context.Context, t *testing.T, et evidenceTool, argsJSON string) (tool.Request, error, *tool.ToolResult, error) {
	t.Helper()
	execID := mustExecID(t)
	req, _, prepErr := et.PrepareCall(ctx, execID, argsJSON)
	if prepErr != nil {
		return tool.Request{}, prepErr, nil, nil
	}
	result, runErr := et.InvokableRun(ctx, argsJSON)
	return req, nil, result, runErr
}

func resultText(t *testing.T, result *tool.ToolResult) string {
	t.Helper()
	if result == nil || len(result.Content) != 1 {
		t.Fatalf("result = %v, want exactly one content block", result)
	}
	block, ok := result.Content[0].(*content.TextBlock)
	if !ok || block == nil {
		t.Fatalf("result.Content[0] = %#v, want *content.TextBlock", result.Content[0])
	}
	return block.Text
}

// ---- filesystem snapshot: the "no mutation" oracle ----------------------------

type fsSnapshot map[string]fsEntrySnapshot

type fsEntrySnapshot struct {
	mode    fs.FileMode
	size    int64
	modTime time.Time
	isDir   bool
	symlink string
	sha256  string
}

// snapshotTree walks root (which must exist) and records every entry's
// metadata plus a content hash for regular files, keyed by root-relative
// slash path. It never follows a symlink.
func snapshotTree(t *testing.T, root string) fsSnapshot {
	t.Helper()
	snap := make(fsSnapshot)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		if rel == "." {
			return nil
		}
		info, infoErr := d.Info()
		if infoErr != nil {
			return infoErr
		}
		entry := fsEntrySnapshot{mode: info.Mode(), size: info.Size(), modTime: info.ModTime(), isDir: d.IsDir()}
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			target, linkErr := os.Readlink(path)
			if linkErr != nil {
				return linkErr
			}
			entry.symlink = target
		case info.Mode().IsRegular():
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				// A deliberately permission-denied fixture file (see
				// newFixture's denied.txt) is unreadable by design; record
				// that fact rather than failing the snapshot itself. Mode,
				// size, and mod time (already captured above) still detect
				// any mutation of such a file.
				entry.sha256 = "unreadable:" + classifyOSError(readErr)
				break
			}
			sum := sha256.Sum256(data)
			entry.sha256 = hex.EncodeToString(sum[:])
		}
		snap[filepath.ToSlash(rel)] = entry
		return nil
	})
	if err != nil {
		t.Fatalf("snapshotTree(%s) error = %v", root, err)
	}
	return snap
}

func assertNoMutation(t *testing.T, root string, before fsSnapshot) {
	t.Helper()
	after := snapshotTree(t, root)
	if len(before) != len(after) {
		t.Fatalf("filesystem mutated: entry count before=%d after=%d", len(before), len(after))
	}
	for path, beforeEntry := range before {
		afterEntry, ok := after[path]
		if !ok {
			t.Fatalf("filesystem mutated: %s disappeared", path)
		}
		if beforeEntry != afterEntry {
			t.Fatalf("filesystem mutated: %s changed from %+v to %+v", path, beforeEntry, afterEntry)
		}
	}
}

// ---- shared fixture: a tree with an in-root symlink, an escaping symlink,
// and a permission-denied file, used across every filesystem tool's security
// tests.

type fixture struct {
	root string
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(filepath.Join(root, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(root, "file.txt"), "hello world\n")
	mustWrite(t, filepath.Join(root, "sub", "nested.txt"), "nested content\n")
	mustWrite(t, filepath.Join(outside, "secret.txt"), "top secret\n")

	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "escape.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape-dir")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file.txt", filepath.Join(root, "ok-link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("does-not-exist", filepath.Join(root, "broken-link.txt")); err != nil {
		t.Fatal(err)
	}

	denied := filepath.Join(root, "denied.txt")
	mustWrite(t, denied, "no access\n")
	if err := os.Chmod(denied, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(denied, 0o644) }) // TempDir cleanup needs read perm restored

	return fixture{root: root}
}

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func skipIfRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("permission-denied semantics do not apply when running as root")
	}
}

// ============================================================================
// SECURITY TESTS (written first, per superpowers:test-driven-development and
// this task's explicit "security tests come first" ordering)
// ============================================================================

func allFilesystemTools(root string) map[string]evidenceTool {
	return map[string]evidenceTool{
		toolNameFilesystemStat: newPathStatTool(root),
		toolNameFilesystemList: newListDirectoryTool(root, 100),
		toolNameFilesystemRead: newReadFileTool(root, 4096),
		toolNameFilesystemGlob: newGlobFilesTool(root, 100),
		toolNameFilesystemGrep: newGrepFilesTool(root, 100, 4096),
	}
}

// pathArgsFor returns a minimal, tool-appropriate JSON argument object naming
// path as its "path" field, with every other required field at its
// zero/sentinel value.
func pathArgsFor(toolName, path string) string {
	switch toolName {
	case toolNameFilesystemStat:
		return fmt.Sprintf(`{"path":%q}`, path)
	case toolNameFilesystemList:
		return fmt.Sprintf(`{"path":%q,"limit":0}`, path)
	case toolNameFilesystemRead:
		return fmt.Sprintf(`{"path":%q,"offset":0,"limit":0}`, path)
	case toolNameFilesystemGlob:
		return fmt.Sprintf(`{"path":%q,"pattern":"*","limit":0}`, path)
	case toolNameFilesystemGrep:
		return fmt.Sprintf(`{"path":%q,"pattern":"x","regex":false,"case_sensitive":false,"limit":0}`, path)
	default:
		panic("unknown tool " + toolName)
	}
}

func TestSecurity_MalformedArguments(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	tools := allFilesystemTools(fx.root)

	malformed := map[string][]string{
		toolNameFilesystemStat: {
			``, `not json`, `{`, `[]`, `"a string"`, `null`,
			`{"path":1}`, `{"path":null}`, `{"path":"a","extra":true}`, `{}`,
			`{"path":"a"}{"path":"b"}`,
		},
		toolNameFilesystemList: {
			``, `not json`, `{"path":"a"}`, `{"path":"a","limit":"x"}`,
			`{"path":"a","limit":1.5}`, `{"path":1,"limit":0}`,
			`{"path":"a","limit":0,"extra":1}`,
		},
		toolNameFilesystemRead: {
			``, `{"path":"a","offset":0}`, `{"path":"a","limit":0}`,
			`{"path":"a","offset":-1,"limit":0}`, `{"path":"a","offset":0,"limit":-1}`,
			`{"path":"a","offset":"x","limit":0}`,
		},
		toolNameFilesystemGlob: {
			``, `{"path":"a","pattern":"*"}`, `{"path":"a","pattern":"","limit":0}`,
			`{"path":"a","pattern":"[","limit":0}`, `{"path":"a","pattern":1,"limit":0}`,
		},
		toolNameFilesystemGrep: {
			``, `{"path":"a","pattern":"x"}`,
			`{"path":"a","pattern":"","regex":false,"case_sensitive":false,"limit":0}`,
			`{"path":"a","pattern":"x","regex":true,"case_sensitive":false,"limit":0,"pattern":"y"}`,
			`{"path":"a","pattern":"(","regex":true,"case_sensitive":false,"limit":0}`,
		},
	}

	for name, et := range tools {
		for _, args := range malformed[name] {
			et, args, name := et, args, name
			t.Run(name+"/"+truncateForDisplay(args, 40), func(t *testing.T) {
				t.Parallel()
				before := snapshotTree(t, fx.root)
				_, prepErr, _, _ := prepareAndRun(context.Background(), t, et, args)
				if prepErr == nil {
					t.Fatalf("PrepareCall(%q) error = nil, want error", args)
				}
				assertNoMutation(t, fx.root, before)
			})
		}
	}
}

func TestSecurity_Containment(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	tools := allFilesystemTools(fx.root)

	escaping := []string{
		"../outside/secret.txt",
		"../../outside/secret.txt",
		"sub/../../outside/secret.txt",
		"/etc/passwd",
		filepath.Join(filepath.Dir(fx.root), "outside", "secret.txt"), // absolute, happens to exist outside
		"..",
	}

	for name, et := range tools {
		for _, path := range escaping {
			et, path, name := et, path, name
			t.Run(name+"/"+path, func(t *testing.T) {
				t.Parallel()
				before := snapshotTree(t, fx.root)
				args := pathArgsFor(name, path)
				_, prepErr, result, runErr := prepareAndRun(context.Background(), t, et, args)
				if prepErr == nil {
					t.Fatalf("PrepareCall(path=%q) error = nil, want a containment error", path)
				}
				if result != nil || runErr != nil {
					t.Fatalf("InvokableRun must never run after a PrepareCall containment failure; result=%v err=%v", result, runErr)
				}
				assertNoMutation(t, fx.root, before)
			})
		}
	}
}

func TestSecurity_ContainmentEscapingSymlink(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)

	// Tools that would DEREFERENCE the final path component must refuse an
	// escaping symlink at PrepareCall time (real, filesystem-aware
	// containment via *os.Root — see precheckContainment(followFinal=true)).
	dereferencing := map[string]evidenceTool{
		toolNameFilesystemList: newListDirectoryTool(fx.root, 100),
		toolNameFilesystemRead: newReadFileTool(fx.root, 4096),
	}
	for name, et := range dereferencing {
		et, name := et, name
		t.Run(name+"/prepare_rejects_escaping_symlink", func(t *testing.T) {
			t.Parallel()
			before := snapshotTree(t, fx.root)
			args := pathArgsFor(name, "escape.txt")
			_, prepErr, _, _ := prepareAndRun(context.Background(), t, et, args)
			if prepErr == nil {
				t.Fatalf("PrepareCall on escaping symlink error = nil, want error")
			}
			assertNoMutation(t, fx.root, before)
		})
	}

	// evidence_filesystem_stat is explicitly allowed to succeed at
	// PrepareCall for an escaping symlink: it never follows the final
	// component (lstat semantics), so it never actually reads through it.
	// InvokableRun must report the symlink's own metadata plus an explicit
	// "does not resolve within the workspace" signal, and must not itself
	// read the escaped target's content.
	t.Run(toolNameFilesystemStat+"/reports_without_following", func(t *testing.T) {
		t.Parallel()
		before := snapshotTree(t, fx.root)
		st := newPathStatTool(fx.root)
		args := pathArgsFor(toolNameFilesystemStat, "escape.txt")
		_, prepErr, result, runErr := prepareAndRun(context.Background(), t, st, args)
		if prepErr != nil || runErr != nil {
			t.Fatalf("stat on escaping symlink: prepErr=%v runErr=%v", prepErr, runErr)
		}
		text := resultText(t, result)
		if !strings.Contains(text, "lstat_type: symlink") {
			t.Fatalf("stat result = %q, want lstat_type: symlink", text)
		}
		if strings.Contains(text, "top secret") {
			t.Fatalf("stat result leaked escaped target content: %q", text)
		}
		if strings.Contains(text, "target_within_root: true") {
			t.Fatalf("stat result = %q, want target_within_root: false for an escaping symlink", text)
		}
		assertNoMutation(t, fx.root, before)
	})

	// glob/grep must never surface content read through an escaping
	// symlink, and must not error the whole call — they simply skip it.
	for _, name := range []string{toolNameFilesystemGlob, toolNameFilesystemGrep} {
		name := name
		t.Run(name+"/skips_escaping_symlink_silently", func(t *testing.T) {
			t.Parallel()
			before := snapshotTree(t, fx.root)
			et := allFilesystemTools(fx.root)[name]
			args := pathArgsFor(name, ".")
			_, prepErr, result, runErr := prepareAndRun(context.Background(), t, et, args)
			if prepErr != nil || runErr != nil {
				t.Fatalf("%s over root: prepErr=%v runErr=%v", name, prepErr, runErr)
			}
			text := resultText(t, result)
			if strings.Contains(text, "escape.txt") || strings.Contains(text, "top secret") {
				t.Fatalf("%s result leaked escaping symlink content: %q", name, text)
			}
			assertNoMutation(t, fx.root, before)
		})
	}
}

func TestSecurity_ContainmentInRootSymlinkWorks(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	rf := newReadFileTool(fx.root, 4096)
	before := snapshotTree(t, fx.root)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, rf, pathArgsFor(toolNameFilesystemRead, "ok-link.txt"))
	if prepErr != nil || runErr != nil {
		t.Fatalf("read of in-root symlink: prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "hello world") {
		t.Fatalf("read of in-root symlink = %q, want content of file.txt", text)
	}
	assertNoMutation(t, fx.root, before)
}

// TestSecurity_ContainmentInRootSymlinkGlobAndGrep proves glob/grep also
// traverse a symlink whose target stays within the root (design intent
// documented on walkRoot): they must find and read through ok-link.txt,
// not silently skip every symlink regardless of where it points.
func TestSecurity_ContainmentInRootSymlinkGlobAndGrep(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	before := snapshotTree(t, fx.root)

	gt := newGlobFilesTool(fx.root, 100)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, gt, `{"path":".","pattern":"ok-link.txt","limit":0}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("glob: prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "ok-link.txt") {
		t.Fatalf("glob(ok-link.txt) = %q, want to find the in-root symlink", resultText(t, result))
	}

	grt := newGrepFilesTool(fx.root, 100, 4096)
	_, prepErr, result, runErr = prepareAndRun(context.Background(), t, grt, `{"path":".","pattern":"hello world","regex":false,"case_sensitive":true,"limit":0}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("grep: prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	// Both file.txt (the real file) and ok-link.txt (the in-root symlink to
	// it) must be found: the symlink is followed, not skipped, because it
	// never leaves the root.
	if !strings.Contains(text, "file.txt:") || !strings.Contains(text, "ok-link.txt:") {
		t.Fatalf("grep('hello world') = %q, want matches from both file.txt and ok-link.txt", text)
	}
	assertNoMutation(t, fx.root, before)
}

func TestSecurity_DeniedReads(t *testing.T) {
	skipIfRoot(t)
	t.Parallel()
	fx := newFixture(t)
	before := snapshotTree(t, fx.root)

	rf := newReadFileTool(fx.root, 4096)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, rf, pathArgsFor(toolNameFilesystemRead, "denied.txt"))
	if prepErr != nil {
		t.Fatalf("PrepareCall on a permission-denied (but contained) file: err = %v, want nil (denial surfaces at InvokableRun)", prepErr)
	}
	if runErr != nil {
		t.Fatalf("InvokableRun on a permission-denied file must fail cleanly (no Go error), got err = %v", runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "permission denied") {
		t.Fatalf("read of denied file = %q, want a clean permission-denied message", text)
	}
	if strings.Contains(text, "no access") {
		t.Fatalf("read of denied file leaked content: %q", text)
	}
	assertNoMutation(t, fx.root, before)
}

func TestSecurity_ExactByteLimits_Read(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	path := filepath.Join(fx.root, "exact.txt")
	mustWrite(t, path, strings.Repeat("A", 100))

	cases := []struct {
		name      string
		limit     int
		wantBytes int
		wantTrunc bool
	}{
		{"one_under", 99, 99, true},
		{"exact", 100, 100, false},
		{"one_over", 101, 100, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			before := snapshotTree(t, fx.root)
			rf := newReadFileTool(fx.root, 4096)
			args := fmt.Sprintf(`{"path":"exact.txt","offset":0,"limit":%d}`, tc.limit)
			_, prepErr, result, runErr := prepareAndRun(context.Background(), t, rf, args)
			if prepErr != nil || runErr != nil {
				t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
			}
			text := resultText(t, result)
			if !strings.Contains(text, fmt.Sprintf("bytes_read: %d", tc.wantBytes)) {
				t.Fatalf("limit=%d: result = %q, want bytes_read: %d", tc.limit, text, tc.wantBytes)
			}
			if !strings.Contains(text, fmt.Sprintf("truncated: %t", tc.wantTrunc)) {
				t.Fatalf("limit=%d: result = %q, want truncated: %t", tc.limit, text, tc.wantTrunc)
			}
			assertNoMutation(t, fx.root, before)
		})
	}
}

func TestSecurity_ExactByteLimits_List(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	for i := 0; i < 10; i++ {
		mustWrite(t, filepath.Join(base, fmt.Sprintf("f%02d.txt", i)), "x")
	}
	cases := []struct {
		name      string
		limit     int
		wantCount int
		wantTrunc bool
	}{
		{"one_under", 9, 9, true},
		{"exact", 10, 10, false},
		{"one_over", 11, 10, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			before := snapshotTree(t, base)
			lt := newListDirectoryTool(base, 500)
			args := fmt.Sprintf(`{"path":".","limit":%d}`, tc.limit)
			_, prepErr, result, runErr := prepareAndRun(context.Background(), t, lt, args)
			if prepErr != nil || runErr != nil {
				t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
			}
			text := resultText(t, result)
			if !strings.Contains(text, fmt.Sprintf("entries: %d", tc.wantCount)) {
				t.Fatalf("limit=%d: result = %q, want entries: %d", tc.limit, text, tc.wantCount)
			}
			if !strings.Contains(text, fmt.Sprintf("truncated: %t", tc.wantTrunc)) {
				t.Fatalf("limit=%d: result = %q, want truncated: %t", tc.limit, text, tc.wantTrunc)
			}
			assertNoMutation(t, base, before)
		})
	}
}

func TestSecurity_ExactByteLimits_Glob(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	for i := 0; i < 10; i++ {
		mustWrite(t, filepath.Join(base, fmt.Sprintf("f%02d.go", i)), "x")
	}
	cases := []struct {
		name      string
		limit     int
		wantCount int
		wantTrunc bool
	}{
		{"one_under", 9, 9, true},
		{"exact", 10, 10, false},
		{"one_over", 11, 10, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			before := snapshotTree(t, base)
			gt := newGlobFilesTool(base, 500)
			args := fmt.Sprintf(`{"path":".","pattern":"*.go","limit":%d}`, tc.limit)
			_, prepErr, result, runErr := prepareAndRun(context.Background(), t, gt, args)
			if prepErr != nil || runErr != nil {
				t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
			}
			text := resultText(t, result)
			if !strings.Contains(text, fmt.Sprintf("matches: %d", tc.wantCount)) {
				t.Fatalf("limit=%d: result = %q, want matches: %d", tc.limit, text, tc.wantCount)
			}
			if !strings.Contains(text, fmt.Sprintf("truncated: %t", tc.wantTrunc)) {
				t.Fatalf("limit=%d: result = %q, want truncated: %t", tc.limit, text, tc.wantTrunc)
			}
			assertNoMutation(t, base, before)
		})
	}
}

func TestSecurity_ExactByteLimits_Grep(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	var lines []string
	for i := 0; i < 10; i++ {
		lines = append(lines, fmt.Sprintf("needle %d", i))
	}
	mustWrite(t, filepath.Join(base, "haystack.txt"), strings.Join(lines, "\n")+"\n")

	cases := []struct {
		name      string
		limit     int
		wantCount int
		wantTrunc bool
	}{
		{"one_under", 9, 9, true},
		{"exact", 10, 10, false},
		{"one_over", 11, 10, false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			before := snapshotTree(t, base)
			gt := newGrepFilesTool(base, 500, 4096)
			args := fmt.Sprintf(`{"path":".","pattern":"needle","regex":false,"case_sensitive":true,"limit":%d}`, tc.limit)
			_, prepErr, result, runErr := prepareAndRun(context.Background(), t, gt, args)
			if prepErr != nil || runErr != nil {
				t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
			}
			text := resultText(t, result)
			if !strings.Contains(text, fmt.Sprintf("matches: %d", tc.wantCount)) {
				t.Fatalf("limit=%d: result = %q, want matches: %d", tc.limit, text, tc.wantCount)
			}
			if !strings.Contains(text, fmt.Sprintf("truncated: %t", tc.wantTrunc)) {
				t.Fatalf("limit=%d: result = %q, want truncated: %t", tc.limit, text, tc.wantTrunc)
			}
			assertNoMutation(t, base, before)
		})
	}
}

// TestUnit_WalkRoot_SignalsBudgetExhaustion proves walkRoot distinguishes a
// scan cut short by its node-visit budget from one that completed
// naturally: a caller (evidence_filesystem_glob/grep) must be able to tell
// "gave up looking" apart from "found nothing more" instead of treating a
// budget-exhausted walk as if it were exhaustive.
func TestUnit_WalkRoot_SignalsBudgetExhaustion(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	for i := 0; i < 10; i++ {
		mustWrite(t, filepath.Join(base, fmt.Sprintf("f%02d.txt", i)), "x")
	}
	r, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	visit := func(string, fs.DirEntry) (bool, error) { return true, nil }

	// Deliberately not t.Parallel() on either subtest: both share the same
	// *os.Root r, which the parent's deferred r.Close() would close as soon
	// as the parent function body returns — before a paused parallel
	// subtest ever actually runs its body — so these must run synchronously
	// while the parent is still on the stack.
	t.Run("budget exceeded", func(t *testing.T) {
		exhausted, walkErr := walkRoot(context.Background(), r, ".", 5, visit)
		if walkErr != nil {
			t.Fatalf("walkRoot() error = %v, want nil", walkErr)
		}
		if !exhausted {
			t.Fatal("walkRoot() budgetExhausted = false, want true when maxNodes is below the entry count")
		}
	})

	t.Run("budget not exceeded", func(t *testing.T) {
		exhausted, walkErr := walkRoot(context.Background(), r, ".", 100, visit)
		if walkErr != nil {
			t.Fatalf("walkRoot() error = %v, want nil", walkErr)
		}
		if exhausted {
			t.Fatal("walkRoot() budgetExhausted = true, want false when the whole tree fits under maxNodes")
		}
	})
}

// TestSecurity_ScanBudgetExhaustion_Glob and its grep counterpart below
// prove the exhaustion signal actually reaches the tool's own result, not
// just walkRoot's return value: an evidence_filesystem_glob/grep result
// with truncated: false must never coincide with a scan that gave up on
// part of the tree. This test lowers the package's scan-node budget for its
// own duration (deliberately NOT t.Parallel(): Go's test driver runs every
// non-parallel top-level test to full completion, including this one's
// t.Cleanup restore, before any parallel test in this package actually
// begins running its body, so this mutation of a shared package variable
// can never race with a concurrent reader).
func TestSecurity_ScanBudgetExhaustion_Glob(t *testing.T) {
	base := t.TempDir()
	for i := 0; i < 5; i++ {
		mustWrite(t, filepath.Join(base, fmt.Sprintf("f%02d.go", i)), "x")
	}
	original := hardMaxGlobScanned
	hardMaxGlobScanned = 2
	t.Cleanup(func() { hardMaxGlobScanned = original })

	gt := newGlobFilesTool(base, 500)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, gt, `{"path":".","pattern":"*.go","limit":500}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "scan_budget_exhausted: true") {
		t.Fatalf("glob over the scan budget = %q, want scan_budget_exhausted: true", text)
	}
	if !strings.Contains(text, "truncated: true") {
		t.Fatalf("glob over the scan budget = %q, want truncated: true", text)
	}
	if !strings.Contains(text, "scanned: 2") {
		t.Fatalf("glob over the scan budget = %q, want scanned: 2", text)
	}
}

func TestSecurity_ScanBudgetExhaustion_Grep(t *testing.T) {
	base := t.TempDir()
	for i := 0; i < 5; i++ {
		mustWrite(t, filepath.Join(base, fmt.Sprintf("f%02d.txt", i)), "needle\n")
	}
	original := hardMaxGrepScanned
	hardMaxGrepScanned = 2
	t.Cleanup(func() { hardMaxGrepScanned = original })

	gt := newGrepFilesTool(base, 500, 4096)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, gt, `{"path":".","pattern":"needle","regex":false,"case_sensitive":true,"limit":500}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "scan_budget_exhausted: true") {
		t.Fatalf("grep over the scan budget = %q, want scan_budget_exhausted: true", text)
	}
	if !strings.Contains(text, "truncated: true") {
		t.Fatalf("grep over the scan budget = %q, want truncated: true", text)
	}
}

// TestSecurity_ScanBudgetNotExhausted_ReportsFalse is the counterpart proof
// that a scan comfortably under budget still correctly reports
// scan_budget_exhausted: false — this signal must not be a one-way "always
// true" stub.
func TestSecurity_ScanBudgetNotExhausted_ReportsFalse(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	mustWrite(t, filepath.Join(base, "only.go"), "x")

	gt := newGlobFilesTool(base, 500)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, gt, `{"path":".","pattern":"*.go","limit":500}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "scan_budget_exhausted: false") {
		t.Fatalf("glob well under the scan budget = %q, want scan_budget_exhausted: false", text)
	}
	if !strings.Contains(text, "truncated: false") {
		t.Fatalf("glob well under the scan budget = %q, want truncated: false", text)
	}
}

func TestSecurity_Cancellation(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	for i := 0; i < 200; i++ {
		mustWrite(t, filepath.Join(base, fmt.Sprintf("f%03d.txt", i)), strings.Repeat("x", 100))
	}
	before := snapshotTree(t, base)

	tools := map[string]func() (evidenceTool, string){
		toolNameFilesystemGlob: func() (evidenceTool, string) {
			return newGlobFilesTool(base, 500), pathArgsFor(toolNameFilesystemGlob, ".")
		},
		toolNameFilesystemGrep: func() (evidenceTool, string) {
			return newGrepFilesTool(base, 500, 4096), pathArgsFor(toolNameFilesystemGrep, ".")
		},
	}
	for name, build := range tools {
		name, build := name, build
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			et, args := build()
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			_, prepErr, result, runErr := prepareAndRun(ctx, t, et, args)
			if prepErr != nil {
				// A cancelled PrepareCall context legitimately failing closed
				// (precheckContainment opens the root, which does not itself
				// check ctx) is acceptable; what matters is InvokableRun never
				// silently completes as if nothing happened.
				return
			}
			if runErr == nil {
				t.Fatalf("%s with a pre-cancelled context: err = nil, result = %v, want context.Canceled", name, result)
			}
			if !errors.Is(runErr, context.Canceled) {
				t.Fatalf("%s with a pre-cancelled context: err = %v, want context.Canceled", name, runErr)
			}
		})
	}
	assertNoMutation(t, base, before)
}

func TestSecurity_NoMutation_AllToolsAllFixtureCalls(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	before := snapshotTree(t, fx.root)

	calls := []struct {
		toolName string
		args     string
	}{
		{toolNameFilesystemStat, pathArgsFor(toolNameFilesystemStat, "file.txt")},
		{toolNameFilesystemStat, pathArgsFor(toolNameFilesystemStat, "escape.txt")},
		{toolNameFilesystemStat, pathArgsFor(toolNameFilesystemStat, "does-not-exist")},
		{toolNameFilesystemList, pathArgsFor(toolNameFilesystemList, ".")},
		{toolNameFilesystemList, pathArgsFor(toolNameFilesystemList, "sub")},
		{toolNameFilesystemRead, pathArgsFor(toolNameFilesystemRead, "file.txt")},
		{toolNameFilesystemRead, pathArgsFor(toolNameFilesystemRead, "sub/nested.txt")},
		{toolNameFilesystemGlob, pathArgsFor(toolNameFilesystemGlob, ".")},
		{toolNameFilesystemGrep, pathArgsFor(toolNameFilesystemGrep, ".")},
	}
	tools := allFilesystemTools(fx.root)
	var wg sync.WaitGroup
	for _, call := range calls {
		call := call
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _, _ = prepareAndRun(context.Background(), t, tools[call.toolName], call.args)
		}()
	}
	wg.Wait()
	assertNoMutation(t, fx.root, before)
}

// ============================================================================
// BEHAVIOR TESTS
// ============================================================================

func TestBehavior_Stat_CanonicalMetadata(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	st := newPathStatTool(fx.root)

	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, st, pathArgsFor(toolNameFilesystemStat, "file.txt"))
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	for _, want := range []string{"exists: true", "lstat_type: file", "lstat_size: 12"} {
		if !strings.Contains(text, want) {
			t.Fatalf("stat(file.txt) = %q, want to contain %q", text, want)
		}
	}
}

func TestBehavior_Stat_MissingPath(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	st := newPathStatTool(fx.root)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, st, pathArgsFor(toolNameFilesystemStat, "does-not-exist"))
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "exists: false") {
		t.Fatalf("stat(missing) = %q, want exists: false", text)
	}
}

func TestBehavior_Stat_SymlinkWithinRoot(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	st := newPathStatTool(fx.root)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, st, pathArgsFor(toolNameFilesystemStat, "ok-link.txt"))
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	for _, want := range []string{"lstat_type: symlink", "target_within_root: true", "target_type: file"} {
		if !strings.Contains(text, want) {
			t.Fatalf("stat(ok-link.txt) = %q, want to contain %q", text, want)
		}
	}
}

func TestBehavior_Stat_BrokenSymlink(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	st := newPathStatTool(fx.root)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, st, pathArgsFor(toolNameFilesystemStat, "broken-link.txt"))
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "target_exists: false") {
		t.Fatalf("stat(broken-link.txt) = %q, want target_exists: false", text)
	}
}

func TestBehavior_List_MissingDirectory(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	lt := newListDirectoryTool(fx.root, 100)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, lt, pathArgsFor(toolNameFilesystemList, "no-such-dir"))
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "exists: false") {
		t.Fatalf("list(missing) = %q, want exists: false", resultText(t, result))
	}
}

func TestBehavior_List_EmptyDirectory(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	if err := os.Mkdir(filepath.Join(fx.root, "empty"), 0o755); err != nil {
		t.Fatal(err)
	}
	lt := newListDirectoryTool(fx.root, 100)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, lt, pathArgsFor(toolNameFilesystemList, "empty"))
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "entries: 0") {
		t.Fatalf("list(empty) = %q, want entries: 0", resultText(t, result))
	}
}

func TestBehavior_List_SortedAndTyped(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	lt := newListDirectoryTool(fx.root, 100)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, lt, pathArgsFor(toolNameFilesystemList, "."))
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	idxBroken := strings.Index(text, "broken-link.txt")
	idxFile := strings.Index(text, "file.txt")
	if idxBroken == -1 || idxFile == -1 || idxBroken > idxFile {
		t.Fatalf("list(.) = %q, want lexicographically sorted entries", text)
	}
	if !strings.Contains(text, "escape-dir symlink") {
		t.Fatalf("list(.) = %q, want escape-dir reported as symlink (not traversed)", text)
	}
}

func TestBehavior_Read_OffsetAndDefaultLimit(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	rf := newReadFileTool(fx.root, 4096)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, rf, `{"path":"file.txt","offset":6,"limit":0}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "world") || strings.Contains(text, "hello ") {
		t.Fatalf("read(offset=6) = %q, want content starting at 'world'", text)
	}
}

func TestBehavior_Read_Directory(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	rf := newReadFileTool(fx.root, 4096)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, rf, pathArgsFor(toolNameFilesystemRead, "sub"))
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "is a directory") {
		t.Fatalf("read(dir) = %q, want an 'is a directory' message", resultText(t, result))
	}
}

func TestBehavior_Glob_BasenameAnywhereAndScopedPath(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	gt := newGlobFilesTool(fx.root, 100)

	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, gt, `{"path":".","pattern":"*.txt","limit":0}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text := resultText(t, result)
	if !strings.Contains(text, "sub/nested.txt") {
		t.Fatalf("glob(*.txt) = %q, want to match sub/nested.txt by basename-anywhere semantics", text)
	}

	_, prepErr, result, runErr = prepareAndRun(context.Background(), t, gt, `{"path":"sub","pattern":"*.txt","limit":0}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	text = resultText(t, result)
	if strings.Contains(text, "file.txt") || !strings.Contains(text, "nested.txt") {
		t.Fatalf("glob(path=sub) = %q, want only entries under sub", text)
	}
}

func TestBehavior_Grep_LiteralAndRegexCaseSensitivity(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	mustWrite(t, filepath.Join(base, "a.txt"), "Needle here\nno match\nneedle again\n")

	gt := newGrepFilesTool(base, 100, 4096)

	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, gt, `{"path":".","pattern":"needle","regex":false,"case_sensitive":false,"limit":0}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "matches: 2") {
		t.Fatalf("grep(case-insensitive) = %q, want matches: 2", resultText(t, result))
	}

	_, prepErr, result, runErr = prepareAndRun(context.Background(), t, gt, `{"path":".","pattern":"needle","regex":false,"case_sensitive":true,"limit":0}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "matches: 1") {
		t.Fatalf("grep(case-sensitive) = %q, want matches: 1", resultText(t, result))
	}

	_, prepErr, result, runErr = prepareAndRun(context.Background(), t, gt, `{"path":".","pattern":"^needle","regex":true,"case_sensitive":true,"limit":0}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "matches: 1") {
		t.Fatalf("grep(regex) = %q, want matches: 1", resultText(t, result))
	}
}

func TestBehavior_Grep_SkipsBinary(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "bin.dat"), []byte("needle\x00binary"), 0o644); err != nil {
		t.Fatal(err)
	}
	gt := newGrepFilesTool(base, 100, 4096)
	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, gt, `{"path":".","pattern":"needle","regex":false,"case_sensitive":true,"limit":0}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "matches: 0") {
		t.Fatalf("grep over binary file = %q, want matches: 0", resultText(t, result))
	}
}

// ---- Requirement/Request contract tests ---------------------------------------

func TestBehavior_PrepareCall_RequestContract(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	for name, et := range allFilesystemTools(fx.root) {
		name, et := name, et
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			execID := mustExecID(t)
			req, _, err := et.PrepareCall(context.Background(), execID, pathArgsFor(name, "file.txt"))
			if err != nil {
				t.Fatalf("PrepareCall error = %v", err)
			}
			if req.ToolName != name {
				t.Fatalf("req.ToolName = %q, want %q", req.ToolName, name)
			}
			if req.ExecutionID != execID.String() {
				t.Fatalf("req.ExecutionID = %q, want %q", req.ExecutionID, execID.String())
			}
			if len(req.Requirements) != 1 {
				t.Fatalf("len(req.Requirements) = %d, want 1", len(req.Requirements))
			}
			r := req.Requirements[0]
			if r.GrantClass != "" || r.GrantTarget != "" || len(r.Candidates) != 0 {
				t.Fatalf("evidence requirement must never request a grant or candidates: %+v", r)
			}
			if err := tool.ValidateRequest(req); err != nil {
				t.Fatalf("tool.ValidateRequest(req) error = %v", err)
			}
		})
	}
}

func TestBehavior_Info_MatchesToolInfosDeclaration(t *testing.T) {
	t.Parallel()
	fx := newFixture(t)
	declared := make(map[string]tool.ToolInfo)
	for _, info := range filesystemToolInfos() {
		declared[info.Name] = info
	}
	for name, et := range allFilesystemTools(fx.root) {
		info, err := et.Info(context.Background())
		if err != nil || info == nil {
			t.Fatalf("%s: Info() error = %v", name, err)
		}
		want, ok := declared[name]
		if !ok {
			t.Fatalf("%s: not present in filesystemToolInfos()", name)
		}
		if info.Name != want.Name || info.Desc != want.Desc || string(info.Schema) != string(want.Schema) {
			t.Fatalf("%s: built Info() drifted from catalog declaration", name)
		}
	}
}

func TestBehavior_Schemas_AreStrictObjects(t *testing.T) {
	t.Parallel()
	for _, info := range filesystemToolInfos() {
		if !strings.Contains(string(info.Schema), `"additionalProperties":false`) &&
			!strings.Contains(string(info.Schema), `"additionalProperties": false`) {
			t.Fatalf("%s: schema does not set additionalProperties:false: %s", info.Name, info.Schema)
		}
	}
}
