// Package buildtest contains layout and dependency-boundary tests for the
// classifiers module scaffold. It has no exported API. It exists solely to
// assert structural invariants required by
// docs/plans/2026-07-27-permission-classifier-hustle-design.md §2, §6.2, and
// §22.8: no root-level Go source files, an exact module path, Go code
// confined to pkg/ and internal/, no Harness internal import, no
// module-internal import cycle, and a release-modfile guard that rejects
// local filesystem replacement directives.
package buildtest

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// wantModulePath is the exact module path this repository must declare. It
// is also the prefix used to recognize module-internal import paths when
// building the dependency graph in TestNoImportCycleOrHarnessInternalImport.
const wantModulePath = "github.com/looprig/classifiers"

// harnessInternalImportPrefix is the forbidden Harness import boundary: the
// classifiers module may import Harness's public packages (once a later
// task adds that dependency) but must never import Harness internal
// packages. See design §6.1: "Harness never imports the classifiers
// module. The classifiers module imports public Harness contracts."
const harnessInternalImportPrefix = "github.com/looprig/harness/internal"

// repoRoot returns the absolute path of the module root, derived from this
// test package's own location (internal/buildtest) rather than the process
// working directory, so these tests behave the same regardless of how
// `go test` is invoked.
func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	root, err := filepath.Abs(filepath.Join(wd, "..", ".."))
	if err != nil {
		t.Fatalf("resolve module root: %v", err)
	}
	return root
}

// skipDir reports whether a directory must be excluded from source-tree
// walks: version control metadata, a vendored dependency tree, and any
// nested worktree module.
func skipDir(name string) bool {
	switch name {
	case ".git", "vendor", ".worktrees":
		return true
	}
	return false
}

func TestNoRootLevelGoFiles(t *testing.T) {
	root := repoRoot(t)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatalf("read module root: %v", err)
	}

	var found []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if strings.HasSuffix(entry.Name(), ".go") {
			found = append(found, entry.Name())
		}
	}
	if len(found) != 0 {
		t.Fatalf("module root must have no .go files, found: %v", found)
	}
}

func TestModulePathIsExact(t *testing.T) {
	root := repoRoot(t)
	data, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatalf("read go.mod: %v", err)
	}

	modulePattern := regexp.MustCompile(`(?m)^module\s+(\S+)\s*$`)
	match := modulePattern.FindSubmatch(data)
	if match == nil {
		t.Fatalf("go.mod has no module directive:\n%s", data)
	}
	if got := string(match[1]); got != wantModulePath {
		t.Fatalf("go.mod module = %q, want %q", got, wantModulePath)
	}
}

// goFileTopLevelDirs walks the module tree (excluding VCS metadata, vendor,
// and nested worktrees) and returns the sorted, de-duplicated set of
// top-level directory names that directly or transitively contain a
// production .go file. Runnable documentation examples are test files, so
// they remain outside the module's production package boundary. Root-level
// .go files are excluded here; TestNoRootLevelGoFiles covers that case on its
// own.
func goFileTopLevelDirs(t *testing.T, root string) []string {
	t.Helper()

	found := map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
		parts := strings.Split(rel, string(filepath.Separator))
		if d.IsDir() {
			if skipDir(parts[0]) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") || len(parts) == 1 {
			return nil
		}
		found[parts[0]] = true
		return nil
	})
	if err != nil {
		t.Fatalf("walk module tree: %v", err)
	}

	dirs := make([]string, 0, len(found))
	for name := range found {
		dirs = append(dirs, name)
	}
	sort.Strings(dirs)
	return dirs
}

// TestGoSourceLivesOnlyUnderPkgOrInternal covers both "public packages only
// under pkg" and "implementation packages under internal": the module's
// only permitted production Go source locations are pkg/ (public construction
// API) and internal/ (everything else). Test-only documentation examples do
// not become importable module packages and are excluded by the walker.
func TestGoSourceLivesOnlyUnderPkgOrInternal(t *testing.T) {
	root := repoRoot(t)
	for _, dir := range goFileTopLevelDirs(t, root) {
		if dir != "pkg" && dir != "internal" {
			t.Errorf("found Go source outside pkg/ and internal/: %s/", dir)
		}
	}
}

func TestPublicCommandSafetyPackageExists(t *testing.T) {
	root := repoRoot(t)
	assertGoPackageDoc(t, filepath.Join(root, "pkg", "commandsafety", "doc.go"), "commandsafety")
}

func TestPublicCatalogPackageExists(t *testing.T) {
	root := repoRoot(t)
	assertGoPackageDoc(t, filepath.Join(root, "pkg", "catalog", "doc.go"), "catalog")
}

func assertGoPackageDoc(t *testing.T, path, wantPackage string) {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, data, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	if file.Name.Name != wantPackage {
		t.Fatalf("%s declares package %q, want %q", path, file.Name.Name, wantPackage)
	}
	if file.Doc == nil || strings.TrimSpace(file.Doc.Text()) == "" {
		t.Fatalf("%s has no package doc comment", path)
	}
}

// TestNoImportCycleOrHarnessInternalImport builds the module-internal import
// graph for every non-test .go file under pkg/ and internal/, then asserts:
//
//   - no file imports a Harness internal package; and
//   - the module-internal package graph has no import cycle.
//
// At this scaffold stage the doc-only packages import nothing, so this test
// exercises real, reusable machinery against an empty graph. It becomes a
// standing invariant check as later tasks add real imports.
func TestNoImportCycleOrHarnessInternalImport(t *testing.T) {
	root := repoRoot(t)
	graph := map[string]map[string]bool{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
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
		parts := strings.Split(rel, string(filepath.Separator))
		if d.IsDir() {
			if skipDir(parts[0]) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		if parts[0] != "pkg" && parts[0] != "internal" {
			return nil
		}

		pkgDir := filepath.ToSlash(filepath.Dir(rel))
		if graph[pkgDir] == nil {
			graph[pkgDir] = map[string]bool{}
		}

		fset := token.NewFileSet()
		file, parseErr := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, imp := range file.Imports {
			importPath, unquoteErr := strconv.Unquote(imp.Path.Value)
			if unquoteErr != nil {
				return unquoteErr
			}
			if importPath == harnessInternalImportPrefix || strings.HasPrefix(importPath, harnessInternalImportPrefix+"/") {
				t.Errorf("%s imports forbidden Harness internal package %q", path, importPath)
			}
			if strings.HasPrefix(importPath, wantModulePath+"/") {
				graph[pkgDir][strings.TrimPrefix(importPath, wantModulePath+"/")] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module tree: %v", err)
	}

	if cycle := findImportCycle(graph); cycle != nil {
		t.Fatalf("module-internal import cycle detected: %s", strings.Join(cycle, " -> "))
	}
}

// findImportCycle runs an iterative-style DFS (visiting/done coloring) over
// a package import graph and returns the first cycle found as an ordered
// path of package directories, or nil when the graph is acyclic.
func findImportCycle(graph map[string]map[string]bool) []string {
	const (
		unvisited = 0
		visiting  = 1
		done      = 2
	)
	state := map[string]int{}
	var stack []string

	var visit func(node string) []string
	visit = func(node string) []string {
		state[node] = visiting
		stack = append(stack, node)

		deps := make([]string, 0, len(graph[node]))
		for dep := range graph[node] {
			deps = append(deps, dep)
		}
		sort.Strings(deps)

		for _, dep := range deps {
			switch state[dep] {
			case unvisited:
				if cycle := visit(dep); cycle != nil {
					return cycle
				}
			case visiting:
				cycleStart := 0
				for i, n := range stack {
					if n == dep {
						cycleStart = i
						break
					}
				}
				cycle := append([]string{}, stack[cycleStart:]...)
				return append(cycle, dep)
			}
		}

		stack = stack[:len(stack)-1]
		state[node] = done
		return nil
	}

	nodes := make([]string, 0, len(graph))
	for node := range graph {
		nodes = append(nodes, node)
	}
	sort.Strings(nodes)

	for _, node := range nodes {
		if state[node] == unvisited {
			if cycle := visit(node); cycle != nil {
				return cycle
			}
		}
	}
	return nil
}
