package normalization

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"path"
	"strings"

	"github.com/aizen299/secure-dev/internal/scanners"
)

// fieldSeparator joins fingerprint inputs.
//
// US (0x1f) rather than a printable character, and rejected inside fields, so
// the join is unambiguous. Plain concatenation is not: "ab"+"c" and "a"+"bc"
// produce the same string, which would let two different findings collide into
// one identity.
const fieldSeparator = "\x1f"

// ErrUnfingerprintable reports input that cannot be given a stable identity.
var ErrUnfingerprintable = errors.New("cannot fingerprint")

// FingerprintInput is everything that contributes to a finding's identity.
//
// Deliberately a separate type from Finding: it names exactly the fields that
// matter, so adding a field to Finding cannot silently change every existing
// finding's identity. Changing identity is a migration, not an edit.
type FingerprintInput struct {
	// Category distinguishes a secret from a SAST finding at the same place.
	Category scanners.Category
	// RuleID is the scanner's stable rule identifier. Empty for findings
	// identified by vulnerability rather than by rule.
	RuleID string
	// Location is a path within the target. Empty when the finding has no
	// file, such as a dependency or an endpoint.
	Location string
	// Package identifies an affected component: a purl where the scanner gives
	// one, otherwise name@version.
	Package string
	// VulnerabilityID is a CVE, GHSA, or equivalent. Empty when the finding is
	// not a known vulnerability.
	VulnerabilityID string
}

// Fingerprint computes a finding's stable identity.
//
// What is NOT here is as deliberate as what is. Line numbers, titles,
// descriptions, severities, and the scanner's own name are all excluded, each
// for a reason recorded in docs/architecture/fingerprinting.md. The short
// version: everything excluded is something that changes while the finding
// stays the same, and identity that changes is not identity.
func Fingerprint(in FingerprintInput) (string, error) {
	fields := []string{
		strings.ToLower(strings.TrimSpace(string(in.Category))),
		normalizeRuleID(in.RuleID),
		NormalizeLocation(in.Location),
		normalizePackage(in.Package),
		normalizeVulnerabilityID(in.VulnerabilityID),
	}

	// A field containing the separator could forge another field's boundary.
	// Rejected rather than escaped: escaping is another thing to get wrong,
	// and no legitimate value contains a unit separator.
	for i, f := range fields {
		if strings.Contains(f, fieldSeparator) {
			return "", fmt.Errorf("%w: field %d contains the separator", ErrUnfingerprintable, i)
		}
	}

	// A finding with nothing but a category has no identity worth the name:
	// every such finding would collide with every other. Better to refuse than
	// to mint an identity that means nothing.
	if fields[1] == "" && fields[2] == "" && fields[3] == "" && fields[4] == "" {
		return "", fmt.Errorf("%w: no distinguishing input beyond category", ErrUnfingerprintable)
	}

	sum := sha256.Sum256([]byte(strings.Join(fields, fieldSeparator)))
	return hex.EncodeToString(sum[:]), nil
}

// NormalizeLocation puts a path into the one form identity uses.
//
// Exported because adapters need the same normalization when they record an
// occurrence's file, and two spellings of one path must not become two
// findings.
func NormalizeLocation(p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	// Backslashes to forward slashes before Clean, so a Windows-style path
	// from a scanner normalizes to the same thing as its POSIX spelling.
	p = strings.ReplaceAll(p, "\\", "/")
	p = path.Clean(p)
	// Both "./x" and "/x" describe the same file inside a target: the leading
	// forms are an artifact of how a scanner was invoked, not of where the
	// finding is.
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	return p
}

// EndpointTargetPath reduces a scan's target URL to the part that says which page
// it looked at: the path, in the form NormalizeLocation gives it, without origin,
// query, or fragment. The site root is the empty string.
//
// EscapedPath rather than Path: decoding would make /files/a%2Fb and /files/a/b look
// like one page, and a clean scan of one would then close a finding from the other.
//
// Reports false when the value is not a usable URL. Exported so that deciding
// whether two website scans looked at the same page has one derivation (ADR 042).
func EndpointTargetPath(raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return "", false
	}
	return NormalizeLocation(u.EscapedPath()), true
}

// normalizeRuleID lowercases and trims a scanner's rule identifier. Case is not
// meaningful in any of the five scanners' rule namespaces, and a scanner that
// changes the case of its own rule id has not found a different problem.
func normalizeRuleID(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// normalizePackage canonicalises a component identifier.
//
// A purl is already canonical, so it is only lowercased and trimmed. A bare
// name@version is lowercased too: package ecosystems are overwhelmingly
// case-insensitive in practice, and treating "Express" and "express" as two
// components would split one finding in two.
func normalizePackage(s string) string {
	return strings.ToLower(strings.TrimSpace(s))
}

// normalizeVulnerabilityID uppercases a CVE or advisory identifier, which is
// how every issuer writes them and how every consumer expects to read them.
func normalizeVulnerabilityID(s string) string {
	return strings.ToUpper(strings.TrimSpace(s))
}
