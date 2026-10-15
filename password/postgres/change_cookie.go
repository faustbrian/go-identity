package passwordpostgres

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

type passwordChangeCSRF struct {
	keys   []session.CSRFKey
	intent session.CSRFKey
}

func (p passwordChangeCSRF) check(state session.CSRFState, binding session.CSRFBinding, token session.CSRFToken) error {
	spec, err := state.Bindings()
	if err == nil {
		for _, key := range p.keys {
			if key.Version() == spec.KeyVersion {
				if state.Check(binding, token, key) == nil {
					return nil
				}
				break
			}
		}
	}
	return identity.ForbiddenError{}
}

func (p passwordChangeCSRF) checkSession(original session.Session, token session.CSRFToken) error {
	spec, err := original.Bindings()
	if err != nil {
		return identity.ForbiddenError{}
	}
	return p.check(original.CSRFState(), session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, token)
}

// CookiePasswordChangeRequest carries the same original password-change input,
// exactly one required retry key and the session owner's opaque synchronizer.
// HTTP must separately enforce exact origin, strict cookies and one CSRF channel.
// Borrowed Password remains caller-owned; destroy it after Change returns.
type CookiePasswordChangeRequest struct {
	Request        PasswordChangeRequest
	IdempotencyKey identity.IdempotencyKey
	CSRFToken      session.CSRFToken
}

// CookieKeyedPasswordChangeService selects a strict cookie profile over the sole
// native keyed transaction. It owns no journal, transaction, provider or goroutine.
// Its immutable borrowed dependencies must outlive calls. Zero denies. Calls are
// concurrency-safe with independently owned request secrets.
type CookieKeyedPasswordChangeService struct {
	native func() *KeyedPasswordChangeService
}

// NewCookieKeyedPasswordChangeService freezes 1..4 distinct eligible named CSRF
// keys. It never mutates base or falls back to its bearer profile. Key retention
// is trusted deployment policy, not request input. Correlation is domain-separated
// from bearer requests and uses the existing session digest engine without raw
// token persistence, Reveal, or a second synchronizer implementation.
func NewCookieKeyedPasswordChangeService(base *KeyedPasswordChangeService, keys []session.CSRFKey) (*CookieKeyedPasswordChangeService, error) {
	if base == nil || base.native == nil || base.config == nil || base.crypto == nil || base.csrf != nil || len(keys) < 1 || len(keys) > 4 {
		return nil, password.ErrPasswordWork
	}
	for i, key := range keys {
		if key.Version() == 0 {
			return nil, password.ErrPasswordWork
		}
		for _, prior := range keys[:i] {
			if prior.Version() == key.Version() {
				return nil, password.ErrPasswordWork
			}
		}
	}
	key := base.config().intentKey()
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-password-cookie-intent-key-v1"))
	material := mac.Sum(nil)
	defer clear(material)
	intent, err := session.NewCSRFKey(1, material)
	if err != nil {
		return nil, password.ErrPasswordWork
	}
	profile := passwordChangeCSRF{keys: append([]session.CSRFKey(nil), keys...), intent: intent}
	native := *base
	native.csrf = func() passwordChangeCSRF { return profile }
	native.identity = sha256.Sum256(append([]byte("identity-password-cookie-profile-v1\x00"), base.identity[:]...))
	return &CookieKeyedPasswordChangeService{native: func() *KeyedPasswordChangeService { return &native }}, nil
}

// Change requires the original session-bound token both before preparation and
// under the primary session fence before counters/hash admission and mutation.
// CSRF rotation after source observation denies through exact session equality;
// token checks alone never grant authority. Matching retries retain original
// outcomes and token intent, never renewing session/proof/risk freshness.
func (s *CookieKeyedPasswordChangeService) Change(ctx context.Context, r CookiePasswordChangeRequest) (PasswordChangeResult, error) {
	if s == nil || s.native == nil {
		return PasswordChangeResult{}, password.ErrPasswordWork
	}
	return s.native().change(ctx, r.Request, r.IdempotencyKey, r.CSRFToken)
}

// Recover delegates code-free original result access to the native query policy.
// It never resubmits a token/password or performs a protected mutation.
func (s *CookieKeyedPasswordChangeService) Recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (PasswordChangeResult, error) {
	if s == nil || s.native == nil {
		return PasswordChangeResult{}, password.ErrPasswordWork
	}
	return s.native().Recover(ctx, q, caller)
}

// Format prevents diagnostics from traversing borrowed secret custody.
func (CookiePasswordChangeRequest) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.CookiePasswordChangeRequest(redacted)")
}

// MarshalJSON denies implicit sensitive export.
func (CookiePasswordChangeRequest) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit sensitive export.
func (CookiePasswordChangeRequest) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// Format prevents diagnostics from traversing native runtime owners.
func (CookieKeyedPasswordChangeService) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.CookieKeyedPasswordChangeService(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (CookieKeyedPasswordChangeService) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies implicit runtime export.
func (CookieKeyedPasswordChangeService) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}
