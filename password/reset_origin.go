package password

import (
	"strconv"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication"
	"github.com/faustbrian/go-capability"
	identity "github.com/faustbrian/go-identity"
)

// ResolveOriginal reconstructs unchanged issuance intent from a genuinely
// verified grant and the frozen trusted callback allowlist. Retained binding
// keys resolve only the original callback; retired keys/callbacks, incompatible
// scope and expiry return ErrInvalidReset and zero intent. It never renews
// timestamps or substitutes current versions. Work is bounded by the profile's
// 32 callbacks, performs no IO and is concurrent-safe.
//
// Success validates signed scope, not durable issuance or recovery eligibility.
// The workflow must separately authenticate issuer-owned durable provenance,
// fence current account/identifier/factor authority and atomically consume the
// proof with the protected mutation. The returned intent is sensitive metadata,
// not a public response or permission to reset a password.
func (p ResetProfile) ResolveOriginal(g capability.Grant, now time.Time) (ResetGrantSpec, error) {
	if p.state == nil {
		return ResetGrantSpec{}, ErrInvalidReset
	}
	w := g.Payload()
	if !strings.HasPrefix(w.Resource, "identity.password/") {
		return ResetGrantSpec{}, ErrInvalidReset
	}
	s := ResetGrantSpec{
		TenantID: identity.TenantID(w.Tenant), UserID: identity.UserID(w.Subject),
		CredentialID:    identity.CredentialID(strings.TrimPrefix(w.Resource, "identity.password/")),
		IdentifierID:    identity.IdentifierID(w.Caveats["password.identifier"]),
		OriginCommandID: identity.CommandID(w.CorrelationID), RecoveryPath: auth.RecoveryPathEmail,
		IssuedAt: w.IssuedAt, ExpiresAt: w.ExpiresAt,
	}
	for _, field := range []struct {
		key    string
		target *uint64
	}{
		{"password.credential-version", &s.CredentialVersion},
		{"password.credential-authority-version", &s.CredentialAuthorityVersion},
		{"password.user-authority-version", &s.UserAuthorityVersion},
		{"password.identifier-version", &s.IdentifierVersion},
	} {
		value, err := strconv.ParseUint(w.Caveats[field.key], 10, 64)
		if err != nil || value == 0 {
			return ResetGrantSpec{}, ErrInvalidReset
		}
		*field.target = value
	}
	if raw, present := w.Caveats["password.factor-version"]; present {
		value, err := strconv.ParseUint(raw, 10, 64)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != raw {
			return ResetGrantSpec{}, ErrInvalidReset
		}
		s.FactorVersion = value
	}
	var resolved ResetGrantSpec
	matches := 0
	for callback := range p.state.callbacks {
		s.CallbackURL = callback
		if p.Authorize(g, s, now) == nil {
			resolved = s
			matches++
		}
	}
	if matches != 1 {
		return ResetGrantSpec{}, ErrInvalidReset
	}
	return resolved, nil
}
