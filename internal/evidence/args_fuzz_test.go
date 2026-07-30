package evidence

// FuzzDecodeEvidenceArguments covers design §22.5's "evidence tool-call
// decoding" for this classifier: the model-supplied argument JSON every
// evidence tool's PrepareCall/InvokableRun decodes via decodeArgs, plus the
// downstream validators that consume its decoded fields (resolveRootRelative
// for every path argument, validPattern and compileGrepMatcher for a
// glob/grep pattern, validRef for a Git ref). All of these are pure,
// side-effect-free functions reachable directly from the raw argument
// string, so this fuzzes the full decode-and-validate pipeline without
// touching the filesystem or a git subprocess.

import (
	"testing"
)

func FuzzDecodeEvidenceArguments(f *testing.F) {
	f.Add(`{"path":"a/b.txt"}`)
	f.Add(`{"path":"a","limit":5}`)
	f.Add(`{"path":"a","offset":0,"limit":5}`)
	f.Add(`{"path":"a","pattern":"*.go","limit":5}`)
	f.Add(`{"path":"a","pattern":"TODO","regex":false,"case_sensitive":false,"limit":5}`)
	f.Add(`{"path":"a","pattern":"(","regex":true,"case_sensitive":true,"limit":5}`)
	f.Add(`{"path":"a","ref":"HEAD","staged":true}`)
	f.Add(`{"path":"../escape"}`)
	f.Add(`{"path":"/absolute"}`)
	f.Add(`{"path":"a","path":"b"}`) // duplicate top-level key
	f.Add(`{"path":null}`)           // null masquerading as omitted
	f.Add(`not-json`)
	f.Add(``)
	f.Add(`{}`)
	f.Add(`null`)
	f.Add(`{"path":"a","extra":"unexpected"}`)
	f.Add(`{"path":"` + string([]byte{0x00}) + `"}`)

	f.Fuzz(func(t *testing.T, raw string) {
		var pathArgs pathArgsV1
		if err := decodeArgs(raw, pathArgsKeys, &pathArgs); err != nil {
			assertMalformedArgumentsOnly(t, "pathArgsV1", err)
		} else {
			assertPathDecodeSafe(t, pathArgs.Path)
		}

		var listArgs listArgsV1
		if err := decodeArgs(raw, listArgsKeys, &listArgs); err != nil {
			assertMalformedArgumentsOnly(t, "listArgsV1", err)
		} else {
			assertPathDecodeSafe(t, listArgs.Path)
		}

		var readArgs readArgsV1
		if err := decodeArgs(raw, readArgsKeys, &readArgs); err != nil {
			assertMalformedArgumentsOnly(t, "readArgsV1", err)
		} else {
			assertPathDecodeSafe(t, readArgs.Path)
		}

		var globArgs globArgsV1
		if err := decodeArgs(raw, globArgsKeys, &globArgs); err != nil {
			assertMalformedArgumentsOnly(t, "globArgsV1", err)
		} else {
			assertPathDecodeSafe(t, globArgs.Path)
			if err := validPattern(globArgs.Pattern); err != nil && err != errMalformedArguments {
				t.Fatalf("validPattern() unexpected error = %v", err)
			}
		}

		var grepArgs grepArgsV1
		if err := decodeArgs(raw, grepArgsKeys, &grepArgs); err != nil {
			assertMalformedArgumentsOnly(t, "grepArgsV1", err)
		} else {
			assertPathDecodeSafe(t, grepArgs.Path)
			if _, err := compileGrepMatcher(grepArgs); err != nil && err != errMalformedArguments {
				t.Fatalf("compileGrepMatcher() unexpected error = %v", err)
			}
		}

		var gitDiffArgs gitDiffArgsV1
		if err := decodeArgs(raw, gitDiffArgsKeys, &gitDiffArgs); err != nil {
			assertMalformedArgumentsOnly(t, "gitDiffArgsV1", err)
		} else {
			assertPathDecodeSafe(t, gitDiffArgs.Path)
			// validRef is a pure boolean predicate: it can never panic and
			// has no error to bound, but it must terminate and must never
			// be reached with a nil/invalid UTF-8 crash regardless of what
			// the fuzzer supplies as the ref.
			_ = validRef(gitDiffArgs.Ref)
		}
	})
}

// assertMalformedArgumentsOnly proves decodeArgs never leaks the raw fuzz
// payload through its error: every failure path returns the same static
// sentinel, never a payload-derived message.
func assertMalformedArgumentsOnly(t *testing.T, shape string, err error) {
	t.Helper()
	if err != errMalformedArguments {
		t.Fatalf("decodeArgs(%s) error = %v, want the static errMalformedArguments sentinel (no payload echo)", shape, err)
	}
}

// assertPathDecodeSafe proves resolveRootRelative never panics and only
// ever fails with one of its two static sentinels, regardless of the
// decoded path string's content.
func assertPathDecodeSafe(t *testing.T, path string) {
	t.Helper()
	if _, err := resolveRootRelative(path); err != nil && err != errMalformedArguments && err != errPathOutsideRoot {
		t.Fatalf("resolveRootRelative(%q) unexpected error = %v", path, err)
	}
}
