package passwordpostgres

import (
	password "github.com/faustbrian/go-identity/password"
	database "github.com/faustbrian/go-postgres"
)

// NewPhoneMFASigninService selects verified-phone/password signin followed by
// confirmed TOTP. Phone must be configured without Username; AllowedMethods is
// empty or exactly "totp". Known-empty factor authority retains ordinary SFA;
// enrolled accounts receive only the original phone-bound non-final challenge.
// Missing, changed or unsupported factors deny without a weaker fallback.
// No final authentication proof or session is issued before TOTP completion.
// The pool and immutable policy owners are borrowed for bounded concurrent use.
func NewPhoneMFASigninService(pool *database.Pool, c SigninConfig, m MFAChallengeConfig) (*SigninService, error) {
	if c.Phone == nil || c.Username != nil || len(m.AllowedMethods) > 1 || len(m.AllowedMethods) == 1 && m.AllowedMethods[0] != "totp" {
		return nil, password.ErrPasswordWork
	}
	return newMFASigninService(pool, c, m)
}
