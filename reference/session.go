package reference

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// SessionService is this graph's narrow read/self-signout/recovery port. Calls
// require initialized graph custody and an allowed tenant. Cookie signout
// requires the selected native CSRF profile; bearer signout rejects CSRF and
// never falls back to cookie authority. Recovery returns historical metadata,
// not a session, credential, renewed validity or permission to retry execution.
// Implementations honor earlier deadlines and are concurrent-safe.
type SessionService interface {
	Get(context.Context, session.GetRequest) (session.GetResult, error)
	SignOut(context.Context, session.SignOutRequest, session.CSRFToken) (session.SignOutResult, error)
	RecoverSignOut(context.Context, identity.RecoveryQuery, authorization.DecisionContext) (kernel.CommandRecord, error)
}

// Sessions returns guarded native operations only when explicitly selected.
// Obtaining a handle starts no IO or route. Retained handles deny after Close.
func (f FeatureSet) Sessions() (SessionService, error) {
	s := f.state
	if s == nil {
		return nil, identity.InvalidInputError{Field: "reference_session"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.features == nil || !s.features.composed || s.features.session == nil {
		return nil, identity.UnavailableError{}
	}
	return composedSession{state: s}, nil
}

type composedSession struct{ state *storeState }

func (f composedSession) Get(ctx context.Context, r session.GetRequest) (session.GetResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return session.GetResult{}, err
	}
	defer done()
	return f.state.features.session.reader.Get(w, r)
}

func (f composedSession) SignOut(ctx context.Context, r session.SignOutRequest, csrf session.CSRFToken) (session.SignOutResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return session.SignOutResult{}, err
	}
	defer done()
	owner := f.state.features.session
	switch r.Transport {
	case session.CredentialCookie:
		if owner.cookie == nil {
			return session.SignOutResult{}, session.ErrCSRFDenied
		}
		return owner.cookie.SignOut(w, r, csrf)
	case session.CredentialBearer:
		if csrf != (session.CSRFToken{}) {
			return session.SignOutResult{}, session.ErrInvalidCSRF
		}
		return owner.bearer.SignOut(w, r)
	default:
		return session.SignOutResult{}, session.ErrInvalidInput
	}
}

func (f composedSession) RecoverSignOut(ctx context.Context, q identity.RecoveryQuery, caller authorization.DecisionContext) (kernel.CommandRecord, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, q.TenantID)
	if err != nil {
		return kernel.CommandRecord{}, err
	}
	defer done()
	return f.state.features.session.revoke.RecoverRevokeOneCommand(w, q, caller)
}

var _ SessionService = composedSession{}
