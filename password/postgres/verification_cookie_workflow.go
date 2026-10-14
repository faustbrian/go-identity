package passwordpostgres

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"slices"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	password "github.com/faustbrian/go-identity/password"
	"github.com/faustbrian/go-identity/session"
)

// CookieVerificationWorkflow selects synchronizer-protected native verification
// without a second proof engine, journal, transaction or goroutine. It borrows
// the immutable configured service and dedicated retained keys; drain calls
// before closing its primary pool. Concurrent calls need independent passwords.
// Zero denies. HTTP must separately enforce exact origin and exclusive channels.
type CookieVerificationWorkflow struct {
	native func() *ReauthenticationService
	keys   func() []session.CSRFKey
}

var _ password.CookieVerificationService = (*CookieVerificationWorkflow)(nil)

// NewCookieVerificationWorkflow freezes 1..4 distinct positive named CSRF keys
// without IO or mutating base. Request/session state cannot supply key material
// or select a bearer fallback. Retention is trusted deployment policy; missing
// or retired state-named keys deny even when another eligible key exists.
func NewCookieVerificationWorkflow(base *ReauthenticationService, keys []session.CSRFKey) (*CookieVerificationWorkflow, error) {
	if _, err := NewVerificationWorkflow(base); err != nil || len(keys) < 1 || len(keys) > 4 {
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
	frozen := slices.Clone(keys)
	return &CookieVerificationWorkflow{native: func() *ReauthenticationService { return base }, keys: func() []session.CSRFKey { return frozen }}, nil
}

type reauthenticationCSRF struct {
	token session.CSRFToken
	keys  []session.CSRFKey
}

func (c *reauthenticationCSRF) key(original session.Session) (session.CSRFKey, error) {
	spec, err := original.Bindings()
	state, stateErr := original.CSRFState().Bindings()
	if err == nil && stateErr == nil {
		for _, key := range c.keys {
			if key.Version() == state.KeyVersion {
				if original.CSRFState().Check(session.CSRFBinding{TenantID: spec.TenantID, SessionID: spec.SessionID, SessionVersion: spec.Version}, c.token, key) == nil {
					return key, nil
				}
				break
			}
		}
	}
	return session.CSRFKey{}, identity.ForbiddenError{}
}

// Verify preserves original borrowed password/session/synchronizer custody.
// The native owner checks the exact named token before password work, then
// repeats session-owned CSRF admission and complete primary session/family
// fencing in the sole proof/audit/outbox transaction. Rotation after lookup
// denies even without a session-version change. It never consumes or rotates
// the synchronizer, renews a session or automatically retries. Failed/ambiguous
// delivery retains original command/outcome observations without a proof.
func (s *CookieVerificationWorkflow) Verify(ctx context.Context, r password.CookieVerificationRequest) (password.VerificationResult, error) {
	if s == nil || s.native == nil || s.keys == nil || ctx == nil {
		return password.VerificationResult{}, password.ErrPasswordWork
	}
	if err := ctx.Err(); err != nil {
		return password.VerificationResult{}, err
	}
	if err := r.Validate(); err != nil {
		return password.VerificationResult{}, err
	}
	p := r.Request
	result, err := s.native().verify(ctx, ReauthenticationRequest{TenantID: p.TenantID, Session: p.Session, Password: p.Password, Target: ReauthenticationTarget{Purpose: p.Target.Purpose, Action: p.Target.Action, Audience: p.Target.Audience}, Caller: p.Caller, Network: p.Network, Device: p.Device}, &reauthenticationCSRF{token: r.CSRFToken, keys: s.keys()})
	return portableVerificationResult(result), err
}

// Recover delegates original scoped history to the existing native result
// policy. No password or synchronizer is needed, and no proof is redelivered.
// Restart/key retirement cannot turn recovery into new issuance authority.
func (s *CookieVerificationWorkflow) Recover(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (password.VerificationResult, error) {
	if s == nil || s.native == nil || s.keys == nil {
		return password.VerificationResult{}, password.ErrPasswordWork
	}
	return (&VerificationWorkflow{native: s.native}).Recover(ctx, q, caller)
}

// Format redacts implicit traversal of runtime and dedicated key custody.
func (CookieVerificationWorkflow) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "passwordpostgres.CookieVerificationWorkflow(redacted)")
}

// MarshalJSON denies implicit runtime export.
func (CookieVerificationWorkflow) MarshalJSON() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// MarshalText denies text and map-key export.
func (CookieVerificationWorkflow) MarshalText() ([]byte, error) {
	return nil, password.ErrSensitiveSerialization
}

// LogValue returns only a fixed marker.
func (CookieVerificationWorkflow) LogValue() slog.Value {
	return slog.StringValue("passwordpostgres.CookieVerificationWorkflow(redacted)")
}
