// Package canon canonicalizes served/outbound bytes: it replaces volatile fields
// (absolute paths, timestamps) and secret-shaped tokens with stable placeholders. The
// SAME pass serves two purposes - a byte-stable prefix (identical context across turns =>
// KV-cache hits) and outbound redaction (secrets/paths never leak). Deterministic, pure.
package canon

import "regexp"

var (
	reToken     = regexp.MustCompile(`(?:sk|gh[pousr]|xox[baprs])[-_][A-Za-z0-9_-]{16,}`)
	reHexSecret = regexp.MustCompile(`\b[A-Fa-f0-9]{32,}\b`)
	reAbsPath   = regexp.MustCompile(`/(?:home|Users|tmp|var|opt|etc)/[^\s":']+`)
	reTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?`)
)

// Canonicalize returns b with secret-shaped and volatile substrings replaced by stable
// tags. Order matters: tokens and hex secrets are redacted before paths/timestamps.
func Canonicalize(b []byte) []byte {
	s := string(b)
	s = reToken.ReplaceAllString(s, "<TOKEN>")
	s = reHexSecret.ReplaceAllString(s, "<SECRET>")
	s = reAbsPath.ReplaceAllString(s, "<PATH>")
	s = reTimestamp.ReplaceAllString(s, "<TS>")
	return []byte(s)
}
