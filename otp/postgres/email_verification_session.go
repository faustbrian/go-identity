package postgres

import (
	"context"
	"crypto/hmac"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	"github.com/faustbrian/go-identity/session"
)

// EmailVerificationSession authenticates actual token possession against the
// named retained native session without renewing its lifetime or claiming active
// authority. This bounded read supports transport subject/CSRF mapping even
// after the verification's own identifier-epoch change. It is not a session
// validation API: Send/EmailVerify and historical recovery retain their distinct
// current-authority checks. Original private metadata must never be exported.
func (s *EmailVerificationService) EmailVerificationSession(ctx context.Context, tenant identity.TenantID, flow otp.SendFlow) (session.Session, error) {
	if ctx == nil || s == nil || s.sender == nil || s.sender.owner == nil || s.sender.owner.store.initiation == nil || s.sender.owner.store.session == nil {
		return session.Session{}, ErrInvalidCommand
	}
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return session.Session{}, ErrInvalidCommand
	}
	kind, id, bearer, err := flow.Bindings()
	if err != nil || kind != otp.FlowAuthorizationAuthenticatedSession {
		return session.Session{}, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, s.sender.timeout)
	defer stop()
	p := s.sender.owner.store
	stored, err := p.initiation.sessions.Get(ctx, tenant, id)
	if err != nil {
		return session.Session{}, custodyFailure(ctx)
	}
	original, err := stored.Session.Bindings()
	if err != nil || original.TenantID != tenant || original.SessionID != id || original.Authentication.Kind != session.AuthenticationVerified || original.Authentication.Proof.Method != p.session.profile.AuthenticationMethod || original.Authentication.CredentialID == "" {
		return session.Session{}, identity.ForbiddenError{}
	}
	key, exists := p.session.keys[original.Lookup.KeyVersion]
	if !exists {
		return session.Session{}, identity.ForbiddenError{}
	}
	token, err := session.ParseToken(bearer.Token())
	if err != nil {
		return session.Session{}, identity.ForbiddenError{}
	}
	actual, err := token.Digest(key, string(tenant))
	if err != nil || actual.KeyVersion != original.Lookup.KeyVersion || !hmac.Equal(actual.Sum[:], original.Lookup.Sum[:]) {
		return session.Session{}, identity.ForbiddenError{}
	}
	if err := ctx.Err(); err != nil {
		return session.Session{}, err
	}
	return stored.Session, nil
}

var _ otp.EmailVerificationSessionSource = (*EmailVerificationService)(nil)
