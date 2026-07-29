package evidence

import (
	"context"
	"errors"
	"testing"
)

// ============================================================================
// SECURITY TESTS
// ============================================================================

// TestSecurity_Visibility_NilResolverNeverGuesses is the core security
// property of this seam: with no injected resolver (the default), every
// remote is reported unknown — this package must never infer
// public/private from URL text alone (design §13.1/§13.3: no arbitrary
// network access, and a familiar hostname is not an access-control
// signal).
func TestSecurity_Visibility_NilResolverNeverGuesses(t *testing.T) {
	t.Parallel()
	urls := []string{
		"https://github.com/org/repo.git",
		"git@github.com:org/repo.git",
		"https://gitlab.com/org/repo.git",
		"/local/path/to/repo",
		"",
	}
	for _, url := range urls {
		if got := resolveVisibility(context.Background(), nil, url); got != VisibilityUnknown {
			t.Fatalf("resolveVisibility(nil, %q) = %q, want %q", url, got, VisibilityUnknown)
		}
	}
}

type panickyResolver struct{}

func (panickyResolver) ResolveVisibility(context.Context, string) (Visibility, error) {
	panic("hostile resolver panicked")
}

func TestSecurity_Visibility_ResolverPanicFailsSafe(t *testing.T) {
	t.Parallel()
	got := resolveVisibility(context.Background(), panickyResolver{}, "https://github.com/org/repo.git")
	if got != VisibilityUnknown {
		t.Fatalf("resolveVisibility with a panicking resolver = %q, want %q (fail-safe)", got, VisibilityUnknown)
	}
}

type erroringResolver struct{ err error }

func (r erroringResolver) ResolveVisibility(context.Context, string) (Visibility, error) {
	return VisibilityPublic, r.err
}

func TestSecurity_Visibility_ResolverErrorFailsSafe(t *testing.T) {
	t.Parallel()
	got := resolveVisibility(context.Background(), erroringResolver{err: errors.New("boom")}, "u")
	if got != VisibilityUnknown {
		t.Fatalf("resolveVisibility with an erroring resolver = %q, want %q even though the resolver also returned a value", got, VisibilityUnknown)
	}
}

type invalidValueResolver struct{}

func (invalidValueResolver) ResolveVisibility(context.Context, string) (Visibility, error) {
	return Visibility("not-a-real-value"), nil
}

func TestSecurity_Visibility_UnrecognizedValueFailsSafe(t *testing.T) {
	t.Parallel()
	got := resolveVisibility(context.Background(), invalidValueResolver{}, "u")
	if got != VisibilityUnknown {
		t.Fatalf("resolveVisibility with an unrecognized value = %q, want %q", got, VisibilityUnknown)
	}
}

// ============================================================================
// BEHAVIOR TESTS
// ============================================================================

type staticResolver struct {
	visibility Visibility
	gotCtx     context.Context
	gotURL     string
}

func (r *staticResolver) ResolveVisibility(ctx context.Context, url string) (Visibility, error) {
	r.gotCtx = ctx
	r.gotURL = url
	return r.visibility, nil
}

type testContextKey struct{}

func TestBehavior_Visibility_ResolverReceivesExactArguments(t *testing.T) {
	t.Parallel()
	ctx := context.WithValue(context.Background(), testContextKey{}, "marker")
	resolver := &staticResolver{visibility: VisibilityPublic}
	got := resolveVisibility(ctx, resolver, "https://github.com/org/repo.git")
	if got != VisibilityPublic {
		t.Fatalf("resolveVisibility() = %q, want %q", got, VisibilityPublic)
	}
	if resolver.gotURL != "https://github.com/org/repo.git" {
		t.Fatalf("resolver.gotURL = %q, want the exact remote URL", resolver.gotURL)
	}
	if resolver.gotCtx != ctx {
		t.Fatalf("resolver did not receive the caller's exact context")
	}
}

func TestBehavior_RemoteVisibilityHint(t *testing.T) {
	t.Parallel()
	cases := []struct {
		url  string
		want string
	}{
		{"https://github.com/org/repo.git", "github.com"},
		{"git@github.com:org/repo.git", "github.com"},
		{"ssh://git@gitlab.example.com:2222/org/repo.git", "gitlab.example.com"},
		{"/srv/git/repo.git", "local filesystem"},
		{"./relative/repo", "local filesystem"},
		{"file:///srv/git/repo.git", "local filesystem"},
		{"", "unspecified"},
		{"not a url at all", "unknown"},
	}
	for _, tc := range cases {
		if got := RemoteVisibilityHint(tc.url); got != tc.want {
			t.Errorf("RemoteVisibilityHint(%q) = %q, want %q", tc.url, got, tc.want)
		}
	}
}

func TestBehavior_Visibility_ValidVisibilityEnum(t *testing.T) {
	t.Parallel()
	for _, v := range []Visibility{VisibilityUnknown, VisibilityPublic, VisibilityPrivate, VisibilityInternal} {
		if !validVisibility(v) {
			t.Errorf("validVisibility(%q) = false, want true", v)
		}
	}
	if validVisibility(Visibility("bogus")) {
		t.Errorf("validVisibility(bogus) = true, want false")
	}
}
