package buildtest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestReleaseModfileGuardRejectsLocalReplacements exercises
// scripts/check-release-modfile.sh against a simulated release modfile,
// proving the guard accepts tagged/versioned dependencies and rejects every
// form of local filesystem replacement (relative path, absolute path, file
// URL, and an unversioned bare replacement target). This is the release
// counterpart to the local-replace-only development go.mod a later task may
// add: `make release-check` must never let a local checkout path leak into
// a tagged release build. Adapted from the equivalent guard in
// github.com/looprig/tests (scripts/check-release-modfile.sh +
// release_modfile_guard_test.go).
func TestReleaseModfileGuardRejectsLocalReplacements(t *testing.T) {
	root := repoRoot(t)
	scriptPath := filepath.Join(root, "scripts", "check-release-modfile.sh")
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("release modfile guard script missing: %v", err)
	}

	tests := []struct {
		name    string
		modfile string
		wantErr string
	}{
		{
			name:    "tagged release modules",
			modfile: "module github.com/looprig/classifiers\n\ngo 1.26.4\n\nrequire github.com/looprig/harness v0.13.0\n",
		},
		{
			name:    "versioned module replacement",
			modfile: "module github.com/looprig/classifiers\n\ngo 1.26.4\n\nreplace github.com/looprig/harness v0.13.0 => example.com/harness v0.13.1\n",
		},
		{
			name:    "relative local replacement",
			modfile: "module github.com/looprig/classifiers\n\ngo 1.26.4\n\nreplace github.com/looprig/harness => ../harness-permission-classifier\n",
			wantErr: "local filesystem replacement",
		},
		{
			name: "absolute local replacement in block",
			modfile: "module github.com/looprig/classifiers\n\ngo 1.26.4\n\nreplace (\n" +
				"\tgithub.com/looprig/harness => /private/tmp/harness\n)\n",
			wantErr: "local filesystem replacement",
		},
		{
			name:    "file URL replacement",
			modfile: "module github.com/looprig/classifiers\n\ngo 1.26.4\n\nreplace github.com/looprig/harness => file:///private/tmp/harness\n",
			wantErr: "local filesystem replacement",
		},
		{
			name:    "unversioned replacement target",
			modfile: "module github.com/looprig/classifiers\n\ngo 1.26.4\n\nreplace github.com/looprig/harness => local-harness\n",
			wantErr: "local filesystem replacement",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			modfile := filepath.Join(t.TempDir(), "go.release.mod")
			if err := os.WriteFile(modfile, []byte(tt.modfile), 0o600); err != nil {
				t.Fatalf("write temporary modfile: %v", err)
			}

			cmd := exec.Command("sh", scriptPath, modfile)
			output, err := cmd.CombinedOutput()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("guard rejected release modfile: %v\n%s", err, output)
				}
				return
			}

			if err == nil {
				t.Fatalf("guard accepted forbidden modfile")
			}
			if !strings.Contains(string(output), tt.wantErr) {
				t.Fatalf("guard output %q does not contain %q", output, tt.wantErr)
			}
		})
	}
}

func TestReleaseModfileGuardRejectsAbsentModfile(t *testing.T) {
	root := repoRoot(t)
	scriptPath := filepath.Join(root, "scripts", "check-release-modfile.sh")
	if _, err := os.Stat(scriptPath); err != nil {
		t.Fatalf("release modfile guard script missing: %v", err)
	}

	absent := filepath.Join(t.TempDir(), "absent.mod")
	cmd := exec.Command("sh", scriptPath, absent)
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("guard accepted an absent release modfile")
	}
	if !strings.Contains(string(output), "not prepared") {
		t.Fatalf("guard output %q does not explain absent modfile", output)
	}
}
