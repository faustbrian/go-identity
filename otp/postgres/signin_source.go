package postgres

import (
	"context"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
)

// ResolveSigninSource authenticates original Send/pre-auth possession, requires
// current flow/directory and proposed single-factor policy, and rechecks the
// original recipient. Its original scope is for trusted rate admission, not a
// proof or authorization lease; Signin independently rechecks and consumes.
// No code, attempt, command, reservation, session or credential is created.
// Sender/caller deadlines bound all work. Calls are concurrent-safe, retain no
// per-request state and require no new schema or application-supplied reader.
// Suppression and mismatched possession deny without disclosing a destination.
func (s *SigninService) ResolveSigninSource(ctx context.Context, r otp.SigninSourceRequest) (result otp.SigninSource, err error) {
	if ctx == nil || s == nil || s.sender == nil {
		return result, ErrInvalidCommand
	}
	if err := r.Validate(); err != nil {
		return result, err
	}
	if s.source == nil || s.owner == nil || s.sender.owner == nil || s.sender.owner.store == nil || s.sender.owner.store.initiation == nil {
		return result, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, s.sender.timeout)
	defer stop()
	defer func() {
		if recover() != nil {
			result, err = otp.SigninSource{}, ErrUnavailable
		}
	}()
	command, custody, flow, err := s.source.restoreSource(ctx, r.TenantID, r.UserID, r.Caller, r.Flow, r.SendCommandID)
	if err != nil {
		return result, err
	}
	spec, _ := command.Feature()
	issued, err := custody.challenge.Bindings()
	if err != nil || custody.recipient == nil {
		return result, identity.ForbiddenError{}
	}
	if err := s.owner.requireSigninRecipient(*custody.recipient); err != nil {
		return result, err
	}
	continuation, err := issued.Continuation.Bindings()
	if err != nil || continuation.Scope.Purpose != otp.PurposeSignin {
		return result, identity.ForbiddenError{}
	}
	if err := s.source.requireCurrent(ctx, spec.Binding, custody.authority, flow); err != nil {
		return result, err
	}
	factorVersion, err := s.readSigninFactors(ctx, *custody.recipient)
	if err != nil {
		return result, err
	}
	if _, err := s.authorizeRecipient(ctx, r.Caller, *custody.recipient, false); err != nil {
		return result, err
	}
	// Borrow the same exact primary reader as protected recipient admission.
	// Observation time is not a renewable lease; preserve original identity and
	// security epochs. This snapshot grants no consuming authority.
	expected := *custody.recipient
	current, err := s.sender.owner.store.initiation.kernel.ResolveRecipient(ctx, expected.Query)
	if err != nil {
		return result, err
	}
	if current.Suppressed || current.User.ID != expected.User.ID || current.Identifier != expected.Identifier || current.Verification != expected.Verification || current.UserAuthorityVersion != expected.UserAuthorityVersion || current.IdentifierAuthorityVersion != expected.IdentifierAuthorityVersion || current.CredentialAuthorityVersion != expected.CredentialAuthorityVersion {
		return result, identity.ForbiddenError{}
	}
	if err := s.source.requireCurrent(ctx, spec.Binding, custody.authority, flow); err != nil {
		return result, err
	}
	currentFactorVersion, err := s.readSigninFactors(ctx, *custody.recipient)
	if err != nil {
		return result, err
	}
	if currentFactorVersion != factorVersion {
		return result, identity.ForbiddenError{}
	}
	return otp.NewSigninSource(otp.SigninSourceBindings{TenantID: spec.Binding.TenantID, SendCommandID: r.SendCommandID, Channel: continuation.Scope.Channel, Destination: continuation.Scope.Destination})
}
