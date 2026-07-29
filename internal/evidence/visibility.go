package evidence

import (
	"context"
	"net/url"
	"strings"
)

// Visibility is the closed classification of a Git remote's visibility, as
// reported by the evidence_git_remotes tool.
//
// The default and safe outcome is VisibilityUnknown: this package never
// makes an outbound network call (design §13.3 forbids evidence tools from
// accessing arbitrary network resources), so a real public/private/internal
// answer can only ever come from a consumer-injected VisibilityResolver
// wired to a real, governed, read-only hosting API. Nothing in this package
// ever infers VisibilityPublic or VisibilityPrivate from the remote URL
// text alone — a familiar hostname is not evidence of access control.
type Visibility string

const (
	VisibilityUnknown  Visibility = "unknown"
	VisibilityPublic   Visibility = "public"
	VisibilityPrivate  Visibility = "private"
	VisibilityInternal Visibility = "internal"
)

func validVisibility(v Visibility) bool {
	switch v {
	case VisibilityUnknown, VisibilityPublic, VisibilityPrivate, VisibilityInternal:
		return true
	default:
		return false
	}
}

// VisibilityResolver is the explicitly configured, read-only network
// identity source design §13.2 calls for ("repository visibility evidence
// through an explicitly configured, read-only network identity source").
// It is OPTIONAL — StandardEvidence accepts a nil resolver, in which case
// every remote is reported VisibilityUnknown. This package supplies no
// implementation that performs network I/O: injecting a real one (e.g.
// backed by a hosting provider's repository-visibility endpoint) is a
// consumer decision, made by a party that can govern its egress, auth, and
// rate limits. A configured resolver MUST be read-only, MUST NOT mutate any
// remote state, and is expected to perform at most one bounded lookup per
// call; ResolveVisibility failing or returning an unrecognized value is
// always treated as VisibilityUnknown, never as an error that aborts the
// review (see resolveVisibility).
type VisibilityResolver interface {
	ResolveVisibility(ctx context.Context, remoteURL string) (Visibility, error)
}

// resolveVisibility calls resolver for remoteURL and fails safe to
// VisibilityUnknown on any nil resolver, error, or unrecognized value. It
// never panics regardless of what an injected resolver does with a
// malformed URL — the resolver is untrusted-in-behavior consumer code
// running inside a security-relevant evidence path.
func resolveVisibility(ctx context.Context, resolver VisibilityResolver, remoteURL string) (result Visibility) {
	result = VisibilityUnknown
	if resolver == nil {
		return result
	}
	defer func() {
		if recover() != nil {
			result = VisibilityUnknown
		}
	}()
	v, err := resolver.ResolveVisibility(ctx, remoteURL)
	if err != nil || !validVisibility(v) {
		return VisibilityUnknown
	}
	return v
}

// RemoteVisibilityHint derives a best-effort, purely LOCAL, non-network
// description of a remote URL's hosting family (e.g. "github.com",
// "local filesystem") for display alongside Visibility. It is a hint about
// WHERE the remote is hosted, never a verdict on public/private access —
// that distinction always requires VisibilityResolver, and is
// VisibilityUnknown without one.
func RemoteVisibilityHint(remoteURL string) string {
	trimmed := strings.TrimSpace(remoteURL)
	if trimmed == "" {
		return "unspecified"
	}
	if host := hostOf(trimmed); host != "" {
		return strings.ToLower(host)
	}
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "./") || strings.HasPrefix(trimmed, "../") || strings.HasPrefix(trimmed, "file://") {
		return "local filesystem"
	}
	return "unknown"
}

// hostOf extracts a host from either a well-formed URL
// (scheme://host/path) or SCP-like Git syntax (user@host:path). It never
// executes, follows, or otherwise resolves the URL — this is pure string
// parsing.
func hostOf(remoteURL string) string {
	if parsed, err := url.Parse(remoteURL); err == nil && parsed.Host != "" {
		return parsed.Hostname()
	}
	if at := strings.Index(remoteURL, "@"); at >= 0 {
		rest := remoteURL[at+1:]
		if colon := strings.Index(rest, ":"); colon > 0 {
			return rest[:colon]
		}
	}
	return ""
}
