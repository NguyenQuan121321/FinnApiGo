package services

import (
	"strings"
)

// disposableDomains is a curated subset of well-known throwaway-email
// providers (§2). Not exhaustive — operators can append to this set or swap in
// a third-party lookup. Kept short intentionally; the goal is to raise the bar
// for scripted mass registration, not to be a complete blocklist.
var disposableDomains = map[string]struct{}{
	"mailinator.com":    {},
	"guerrillamail.com": {},
	"10minutemail.com":  {},
	"tempmail.com":      {},
	"temp-mail.org":     {},
	"throwawaymail.com": {},
	"yopmail.com":       {},
	"getnada.com":       {},
	"trashmail.com":     {},
	"sharklasers.com":   {},
	"dispostable.com":   {},
	"maildrop.cc":       {},
	"fakeinbox.com":     {},
	"tempinbox.com":     {},
	"mailnesia.com":     {},
}

// isDisposableEmail reports whether the email's domain is a known throwaway
// provider (§2). Case-insensitive.
func isDisposableEmail(email string) bool {
	at := strings.LastIndex(email, "@")
	if at < 0 || at == len(email)-1 {
		return false
	}
	domain := strings.ToLower(strings.TrimSpace(email[at+1:]))
	_, ok := disposableDomains[domain]
	return ok
}
