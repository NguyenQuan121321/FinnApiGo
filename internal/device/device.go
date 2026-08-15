// Package device extracts a clean, human-readable device label from a raw
// User-Agent header (e.g. "Chrome on Windows", "Safari on iPhone"). It uses
// only the stdlib and avoids regular expressions on the hot path so the
// parsing stays cheap under flood traffic.
package device

import "strings"

// MaxUserAgentLen bounds the input we are willing to inspect. A real
// User-Agent is well under 1 KiB; anything larger is pathological and can be
// truncated before parsing.
const MaxUserAgentLen = 512

// Parse returns a compact "<browser> on <os>" label for a User-Agent string.
// Unknown components collapse away, so "" yields "Unknown device" and a bare
// UA yields just the component we recognized.
//
// It is intentionally dependency-free and best-effort — the goal is a
// recognizable label for the "your sessions" list, not a perfect parser.
func Parse(userAgent string) string {
	ua := strings.TrimSpace(userAgent)
	if ua == "" {
		return "Unknown device"
	}
	if len(ua) > MaxUserAgentLen {
		ua = ua[:MaxUserAgentLen]
	}
	lower := strings.ToLower(ua)
	browser := detectBrowser(lower, ua)
	os := detectOS(lower)
	switch {
	case browser == "" && os == "":
		return "Unknown device"
	case os == "":
		return browser
	case browser == "":
		return os
	default:
		return browser + " on " + os
	}
}

// detectBrowser identifies the browser family. Order matters: Edge and
// Chrome mobile include "chrome"/"safari" in their UA, so the more specific
// tokens are checked first. Matching is case-insensitive on the lowercased UA.
func detectBrowser(lower, raw string) string {
	switch {
	case strings.Contains(lower, "edg/"):
		return "Edge"
	case strings.Contains(lower, "opr/") || strings.Contains(lower, "opera"):
		return "Opera"
	case strings.Contains(lower, "firefox"):
		return "Firefox"
	case strings.Contains(lower, "chrome") || strings.Contains(lower, "crios"):
		return "Chrome"
	case strings.Contains(lower, "safari"):
		return "Safari"
	}
	return titleCaseVersionless(raw)
}

// detectOS identifies the operating system from the UA's platform hint.
func detectOS(lower string) string {
	switch {
	case strings.Contains(lower, "iphone"):
		return "iPhone"
	case strings.Contains(lower, "ipad"):
		return "iPad"
	case strings.Contains(lower, "android"):
		return "Android"
	case strings.Contains(lower, "windows"):
		return "Windows"
	case strings.Contains(lower, "mac os") || strings.Contains(lower, "macintosh"):
		return "macOS"
	case strings.Contains(lower, "linux"):
		return "Linux"
	}
	return ""
}

// titleCaseVersionless is a last-ditch fallback: if we couldn't match a known
// browser token, surface the first whitespace-delimited word of the UA
// title-cased (e.g. "Mozilla" → "Mozilla") so the label is never empty when
// the caller actually sent something. Returns "" if nothing usable remains.
func titleCaseVersionless(raw string) string {
	for _, w := range strings.Fields(raw) {
		// Drop any /version suffix (e.g. "Mozilla/5.0" → "Mozilla") so the
		// skip-list below sees the bare product token.
		if i := strings.IndexByte(w, '/'); i >= 0 {
			w = w[:i]
		}
		w = strings.Trim(w, "();,.")
		if w == "" {
			continue
		}
		// Skip generic preamble tokens that carry no device signal.
		if lw := strings.ToLower(w); lw == "mozilla" || lw == "compatible" || lw == "applewebkit" {
			continue
		}
		if r := []rune(w); len(r) > 0 {
			if r[0] >= 'a' && r[0] <= 'z' {
				r[0] = r[0] - 'a' + 'A'
			}
			return string(r)
		}
	}
	return ""
}
