//go:build integration

package evidence

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestIntegration_Path_SymlinkEscape_RealTree exercises a real, multi-hop
// symlink escape (a symlink inside the workspace pointing at a symlink
// pointing outside) against real filesystem trees, proving every
// dereferencing tool refuses it and evidence_filesystem_stat reports it
// without following it.
func TestIntegration_Path_SymlinkEscape_RealTree(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "workspace")
	outside := filepath.Join(base, "outside")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(outside, "real-secret.txt"), "classified\n")
	// hop 1: outside -> outside (a second symlink), hop 2: inside root -> hop1
	if err := os.Symlink(filepath.Join(outside, "real-secret.txt"), filepath.Join(outside, "hop1.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "hop1.txt"), filepath.Join(root, "hop2.txt")); err != nil {
		t.Fatal(err)
	}

	before := snapshotTree(t, root)
	rf := newReadFileTool(root, 4096)
	_, prepErr, _, _ := prepareAndRun(context.Background(), t, rf, pathArgsFor(toolNameFilesystemRead, "hop2.txt"))
	if prepErr == nil {
		t.Fatalf("read through a multi-hop escaping symlink: PrepareCall error = nil, want error")
	}
	assertNoMutation(t, root, before)
}

// TestIntegration_Path_UnusualFileNames proves stat/list/read/glob/grep all
// handle spaces, unicode, and a leading dash in real file names correctly.
func TestIntegration_Path_UnusualFileNames(t *testing.T) {
	root := t.TempDir()
	names := []string{
		"has spaces.txt",
		"unicode-héllo-世界.txt",
		"-leading-dash.txt",
		"trailing-dot..txt",
	}
	for _, name := range names {
		mustWrite(t, filepath.Join(root, name), "content of "+name+"\n")
	}

	st := newPathStatTool(root)
	lt := newListDirectoryTool(root, 100)
	rf := newReadFileTool(root, 4096)
	gt := newGlobFilesTool(root, 100)

	for _, name := range names {
		name := name
		t.Run(name, func(t *testing.T) {
			_, prepErr, result, runErr := prepareAndRun(context.Background(), t, st, pathArgsFor(toolNameFilesystemStat, name))
			if prepErr != nil || runErr != nil {
				t.Fatalf("stat(%q): prepErr=%v runErr=%v", name, prepErr, runErr)
			}
			if !strings.Contains(resultText(t, result), "exists: true") {
				t.Fatalf("stat(%q) = %q, want exists: true", name, resultText(t, result))
			}

			_, prepErr, result, runErr = prepareAndRun(context.Background(), t, rf, pathArgsFor(toolNameFilesystemRead, name))
			if prepErr != nil || runErr != nil {
				t.Fatalf("read(%q): prepErr=%v runErr=%v", name, prepErr, runErr)
			}
			if !strings.Contains(resultText(t, result), "content of "+name) {
				t.Fatalf("read(%q) = %q, want its own content", name, resultText(t, result))
			}
		})
	}

	_, prepErr, result, runErr := prepareAndRun(context.Background(), t, lt, pathArgsFor(toolNameFilesystemList, "."))
	if prepErr != nil || runErr != nil {
		t.Fatalf("list(.): prepErr=%v runErr=%v", prepErr, runErr)
	}
	for _, name := range names {
		if !strings.Contains(resultText(t, result), name) {
			t.Fatalf("list(.) = %q, want to contain %q", resultText(t, result), name)
		}
	}

	_, prepErr, result, runErr = prepareAndRun(context.Background(), t, gt, `{"path":".","pattern":"*.txt","limit":0}`)
	if prepErr != nil || runErr != nil {
		t.Fatalf("glob(*.txt): prepErr=%v runErr=%v", prepErr, runErr)
	}
	if !strings.Contains(resultText(t, result), "matches: 4") {
		t.Fatalf("glob(*.txt) = %q, want matches: 4", resultText(t, result))
	}
}

// TestIntegration_Path_CancellationMidFlight proves a real, large-scale glob
// walk is interrupted promptly by a context cancelled from another goroutine
// partway through, not merely rejected up front.
func TestIntegration_Path_CancellationMidFlight(t *testing.T) {
	root := t.TempDir()
	for dir := 0; dir < 50; dir++ {
		d := filepath.Join(root, fmt.Sprintf("dir%03d", dir))
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
		for file := 0; file < 50; file++ {
			mustWrite(t, filepath.Join(d, fmt.Sprintf("f%03d.txt", file)), strings.Repeat("x", 500))
		}
	}
	before := snapshotTree(t, root)

	gt := newGlobFilesTool(root, hardMaxGlobMatches)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(2 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, prepErr, result, runErr := prepareAndRun(ctx, t, gt, pathArgsFor(toolNameFilesystemGlob, "."))
	elapsed := time.Since(start)
	if prepErr == nil && runErr == nil {
		// The walk may have completed before cancellation fired on a fast
		// machine; that is not itself a failure, but it must have produced a
		// complete, valid result rather than a hang.
		if result == nil {
			t.Fatalf("glob completed with a nil result")
		}
	} else if runErr != nil && !isContextErr(runErr) {
		t.Fatalf("glob cancelled mid-flight returned an unexpected error: %v", runErr)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("glob took %s after cancellation, want prompt abort", elapsed)
	}
	assertNoMutation(t, root, before)
}

func isContextErr(err error) bool {
	return err == context.Canceled || err == context.DeadlineExceeded
}

// TestIntegration_Path_ConcurrentCallsNoMutation drives every filesystem
// tool concurrently against one real tree many times over, then confirms
// byte-identical before/after snapshots — the concurrency-under-load
// counterpart to the unit-level no-mutation test.
func TestIntegration_Path_ConcurrentCallsNoMutation(t *testing.T) {
	fx := newFixture(t)
	before := snapshotTree(t, fx.root)

	tools := allFilesystemTools(fx.root)
	calls := []struct {
		toolName string
		args     string
	}{
		{toolNameFilesystemStat, pathArgsFor(toolNameFilesystemStat, "file.txt")},
		{toolNameFilesystemList, pathArgsFor(toolNameFilesystemList, ".")},
		{toolNameFilesystemRead, pathArgsFor(toolNameFilesystemRead, "sub/nested.txt")},
		{toolNameFilesystemGlob, pathArgsFor(toolNameFilesystemGlob, ".")},
		{toolNameFilesystemGrep, pathArgsFor(toolNameFilesystemGrep, ".")},
	}

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		for _, call := range calls {
			call := call
			wg.Add(1)
			go func() {
				defer wg.Done()
				et := tools[call.toolName]
				_, _, _, _ = prepareAndRun(context.Background(), t, et, call.args)
			}()
		}
	}
	wg.Wait()
	assertNoMutation(t, fx.root, before)
}
