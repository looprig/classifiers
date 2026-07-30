package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"

	"github.com/looprig/harness/pkg/tool"
)

// This file implements Harness's optional tool.EvidenceObservation
// capability (design §13.4, TOCTOU — see
// github.com/looprig/harness-permission-classifier's
// docs/plans/2026-07-27-permission-classifier-hustle-implementation.md,
// Addendum 4) for the two evidence tools in this package that genuinely
// resolve and report the state of ONE canonical target:
//
//   - evidence_filesystem_stat (pathStatTool): the flagship case — it
//     already exists specifically to report one path's lstat-level identity.
//   - evidence_filesystem_read (readFileTool): reads exactly one file's
//     bytes; the file it read is exactly as single-target as the path stat
//     already reports on.
//
// Every OTHER evidence tool in this package is deliberately left
// unimplemented:
//
//   - evidence_filesystem_list, evidence_filesystem_glob,
//     evidence_filesystem_grep: each reports on a VARIABLE-SIZE set of
//     matched/listed entries under one starting directory, not one target's
//     own canonical identity — recording an observation for "the directory
//     listing" or "the grep match set" does not map to "one target's
//     canonical identity, then and now" the way design §13.4 means it
//     (this is the addendum's own explicit exclusion for glob/grep-style
//     multi-match tools, applied identically to list).
//   - evidence_git_repository_status, evidence_git_remotes: both report
//     aggregate, whole-repository state (status across every changed path,
//     every configured remote) — the same "spans many things, not one
//     canonical target" shape as list/glob/grep, not a single resolved
//     ref/path.
//   - evidence_git_diff, evidence_git_branch: each DOES resolve something
//     that could naturally be target-sensitive (a ref-scoped diff, HEAD's
//     resolved branch/commit). They are still deliberately NOT wired here:
//     tool.Requirement's own doc comment reserves Match for "stored-rule
//     matching" and Scope for "access routing" — neither is a general
//     carrier for the extra structured data (git diff's ref/staged flag;
//     which specific ref branch resolution used) an observation token would
//     need to be self-describing from Target alone. Repurposing either
//     field, or overloading Request.Command (meant for command-backed
//     capabilities) to smuggle that data through, would risk silently
//     breaking whatever already depends on their documented contracts.
//     Giving Git evidence tools a real, precisely-specified target/token
//     scheme needs a small, deliberate carrier added to tool.Requirement (or
//     an equivalent), which is a Harness-side change — a follow-up dispatch,
//     not a tuck-in here. (When that lands, prefer the resolved commit/blob
//     SHA `git rev-parse` already gives as the token: it is naturally
//     content-addressed, and design §13.4 explicitly prefers reusing that
//     over inventing a weaker derived one.)
//
// ---- token derivation scheme (read this before changing anything below) --
//
// Both wired tools share ONE token formula,
// filesystemObservationFingerprint(root, rel): a SHA-256 over the target
// path's lstat-level identity (never following the final symlink) plus,
// only when the path IS itself a symlink, its immediate link-target text and
// the link target's own resolved metadata (when the link resolves at all).
// This directly captures "whether the path is/was a symlink and what it
// resolves to" — the exact signal design §13.4's own worked example (a
// deletion target being swapped for a symlink between evidence-gathering
// and auto-approval) requires; a token that omitted it would not defend
// against the attack this mechanism exists to close.
//
// Concretely, for a target that EXISTS, the hashed field sequence (via
// observationDigest, see its own doc comment for the exact wire encoding)
// is:
//
//	"fsv1", "present",
//	<lstat fields: entryKind, decimal size, decimal raw os.FileMode bits,
//	 decimal UnixNano mtime>,
//	then, ONLY if the lstat entry is itself a symlink, one of:
//	  "link_target", <raw readlink() text>, "link_resolved",
//	    <resolved-target lstat fields, same 4-tuple as above>
//	  "link_target_absent"        (link target does not exist)
//	  "link_target_unresolvable"  (link target could not be resolved —
//	                                e.g. it escapes containment)
//	  "link_unreadable"           (readlink itself failed)
//
// For a target that does NOT exist, the hashed sequence is just
// "fsv1", "absent" — deliberately not "no observation" (ok=false): a
// classifier that observed "this deletion target does not exist" IS making
// a real, TOCTOU-relevant observation (design's own worked example), so
// absence must produce a real, valid token, not a skip.
//
// "fsv1" is a fixed scheme-version literal: change it (to "fsv2", etc.)
// whenever the field list, order, or format below changes, so an old
// recorded token can never silently compare equal to a new one computed
// under a different scheme.
//
// entryKind, decimal size/mode/mtime are computed EXACTLY as
// entryKind/fileInfoFingerprintFields below do — see those for the precise
// formulas (Go's os.FileInfo.Size()/Mode()/ModTime(), no reformatting).
//
// HOW TO INDEPENDENTLY RE-DERIVE THIS TOKEN (for the CodeRig-side
// gate.EvidenceObservationVerifier that rechecks it against a fresh look):
// call filesystemObservationFingerprint with root = the verifier's own
// canonicalized read root (gate.EvidenceContainmentPolicy's ReadRoot — or,
// equivalently, treat the recorded Target as already-absolute: it always
// equals filepath.Join(root, rel), so root can also be recovered as
// Target's directory chain up to the policy's own ReadRoot) and rel = the
// path relative to that root. Re-running the identical algorithm against
// live filesystem state and comparing the resulting hex digest to the
// recorded Token IS the recheck — no other data is required, and none of
// this format depends on anything ephemeral to one particular tool call
// (there is no offset/limit/content dependency: see readFileTool's
// ObservedRequirement doc comment below for why).

// filesystemObservationFingerprint computes the token described above for
// one root-relative path. It is the SOLE token formula for every
// tool.EvidenceObservation implementation in this file — pathStatTool and
// readFileTool call it identically, so a target's fingerprint means the
// same thing regardless of which tool observed it.
func filesystemObservationFingerprint(root, rel string) (string, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return "", err
	}
	defer r.Close()

	info, err := r.Lstat(rel)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return observationDigest("fsv1", "absent"), nil
	case err != nil:
		return "", err
	}

	fields := []string{"fsv1", "present"}
	fields = append(fields, fileInfoFingerprintFields(info)...)

	if info.Mode()&fs.ModeSymlink == 0 {
		return observationDigest(fields...), nil
	}

	target, linkErr := r.Readlink(rel)
	if linkErr != nil {
		fields = append(fields, "link_unreadable")
		return observationDigest(fields...), nil
	}
	fields = append(fields, "link_target", target)

	resolved, statErr := r.Stat(rel)
	switch {
	case statErr == nil:
		fields = append(fields, "link_resolved")
		fields = append(fields, fileInfoFingerprintFields(resolved)...)
	case errors.Is(statErr, fs.ErrNotExist):
		fields = append(fields, "link_target_absent")
	default:
		fields = append(fields, "link_target_unresolvable")
	}
	return observationDigest(fields...), nil
}

// fileInfoFingerprintFields is the exact 4-tuple every lstat/stat result
// (the target itself, and separately a symlink's resolved target)
// contributes to the fingerprint: entryKind (this package's existing
// file/dir/symlink/other classifier), decimal byte size, the RAW decimal
// os.FileMode bit pattern (type bits and permission bits together — a
// mode change, including a type change such as file-to-symlink, always
// changes this even if entryKind's own coarser classification did not),
// and the modification time as decimal UnixNano (full available precision,
// not the truncated-to-the-second text writeFileInfo prints for humans).
func fileInfoFingerprintFields(info fs.FileInfo) []string {
	return []string{
		entryKind(info),
		strconv.FormatInt(info.Size(), 10),
		strconv.FormatUint(uint64(info.Mode()), 10),
		strconv.FormatInt(info.ModTime().UTC().UnixNano(), 10),
	}
}

// observationDigest deterministically and unambiguously combines fields
// into one SHA-256 hex digest. Each field is netstring-encoded
// (<decimal-byte-length>:<raw-bytes>, e.g. "3:abc") rather than joined with
// a fixed separator byte: a separator byte could appear INSIDE a field this
// package does not fully control (a symlink target's raw text may contain
// almost any byte short of NUL and '/'), which would let two different
// field sequences serialize to the identical byte string and collide. A
// length prefix makes that impossible regardless of a field's own content.
func observationDigest(fields ...string) string {
	var encoded []byte
	for _, f := range fields {
		encoded = append(encoded, []byte(fmt.Sprintf("%d:", len(f)))...)
		encoded = append(encoded, f...)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

// canonicalObservationTarget is the Target half of every
// ObservationRequirement this file produces: root and rel joined and
// cleaned into one absolute path (filepath.Join already does both). This is
// self-describing on its own (an independent re-verifier needs no
// side-channel to know what it names), and is exactly what
// filesystemObservationFingerprint(root, rel) reports on.
func canonicalObservationTarget(root, rel string) string {
	return filepath.Join(root, rel)
}

// filesystemObservationRequirement extracts (root, rel) from a prepared
// evidence Request's single Requirement, requiring it to carry exactly the
// expected Kind and non-empty Scope/Match — the same shape every filesystem
// evidence tool's own PrepareCall in this package already produces. Any
// other shape (multiple/zero Requirements, a mismatched Kind, an empty
// field) is treated as "this call made no target-sensitive observation"
// (ok=false), never as an error — ObservedRequirement's own contract is
// that a malformed report is simply dropped, not fatal.
func filesystemObservationRequirement(request tool.Request, kind string) (root, rel string, ok bool) {
	if len(request.Requirements) != 1 {
		return "", "", false
	}
	requirement := request.Requirements[0]
	if requirement.Kind != kind || requirement.Scope == "" || requirement.Match == "" {
		return "", "", false
	}
	return requirement.Scope, requirement.Match, true
}

// ObservedRequirement implements tool.EvidenceObservation for
// evidence_filesystem_stat. It reports an observation for EVERY successful
// stat call, including one whose target does not exist — design §13.4's own
// worked example ("confirms a deletion target is empty/non-symlinked") is
// exactly an absence observation, and absence is exactly as TOCTOU-relevant
// as presence (see filesystemObservationFingerprint's doc comment).
func (t *pathStatTool) ObservedRequirement(request tool.Request, _ *tool.ToolResult) (target, token string, ok bool) {
	root, rel, ok := filesystemObservationRequirement(request, KindFilesystemStat)
	if !ok {
		return "", "", false
	}
	fingerprint, err := filesystemObservationFingerprint(root, rel)
	if err != nil {
		return "", "", false
	}
	return canonicalObservationTarget(root, rel), fingerprint, true
}

var _ tool.EvidenceObservation = (*pathStatTool)(nil)

// ObservedRequirement implements tool.EvidenceObservation for
// evidence_filesystem_read, reusing filesystemObservationFingerprint
// UNCHANGED from pathStatTool's own implementation — deliberately, not as
// an oversight. tool.Request carries only ToolName/Summary/ExecutionID/
// Command/WorkingDirectory/ExpiresAtUnixMilli/Requirements; a read call's
// offset/limit arguments never reach it (readFileTool's PrepareCall records
// only Requirement{Kind, Scope: root, Match: rel, Description}, exactly
// like every other tool in this package). A token that depended on the
// exact byte range read would therefore NOT be independently re-derivable
// from Target alone — the whole point this scheme exists to satisfy (see
// this file's top-of-file doc comment) — since nothing durable records
// which offset/limit produced it. Reusing the identical whole-file
// lstat/symlink-chain fingerprint instead keeps Read's token exactly as
// meaningful and exactly as reproducible as Stat's: it still catches the
// same classic TOCTOU swap (a file replaced by a symlink between the read
// and the eventual auto-approval), just not a content edit that leaves
// size/mode/mtime untouched — a strictly narrower, forgeable-only-by-an-
// attacker-who-can-also-forge-metadata gap Stat's own token already
// accepts.
func (t *readFileTool) ObservedRequirement(request tool.Request, _ *tool.ToolResult) (target, token string, ok bool) {
	root, rel, ok := filesystemObservationRequirement(request, KindFilesystemRead)
	if !ok || rel == "." {
		return "", "", false
	}
	fingerprint, err := filesystemObservationFingerprint(root, rel)
	if err != nil {
		return "", "", false
	}
	return canonicalObservationTarget(root, rel), fingerprint, true
}

var _ tool.EvidenceObservation = (*readFileTool)(nil)
