package session

import (
	"fmt"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// AdminSessionRevokeOperation identifies the separate target-session command.
// It does not authorize a call or alter self-service revocation.
func AdminSessionRevokeOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/session", OperationID: "identity.admin.session-revoke", SchemaID: "session-admin-revoke-one", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// AdminSessionRevocation holds the exact target command and the original
// administrator-session admission. Zero is invalid. Copies do not renew the
// admission. It carries no authorization decision or target observation.
type AdminSessionRevocation struct{ state *adminSessionRevocationState }

type adminSessionRevocationState struct {
	binding identity.CommandBinding
	caller  GetResult
	csrf    CSRFToken
}

// PrepareAdminSessionRevoke binds a selected ordinary password/TOTP cookie
// session to one exact tenant, administrator, target user and target session.
// It only checks custody; the durable executor must independently authorize
// the target, then check current actor authority, session, factor and CSRF
// in the transaction before changing anything. It must use its own CSRF key
// policy and never serialize the input secret into command or recovery data.
func (s *SessionService) PrepareAdminSessionRevoke(caller GetResult, binding identity.CommandBinding, token CSRFToken, key CSRFKey) (out AdminSessionRevocation, err error) {
	defer func() {
		if recover() != nil {
			out, err = AdminSessionRevocation{}, ErrUnavailable
		}
	}()
	if !s.Configured() || binding.ValidateFor(AdminSessionRevokeOperation()) != nil || binding.ActorKind != authorization.SubjectUser {
		return out, ErrInvalidSessionCommand
	}
	if err := validateAdminSessionCaller(s, caller, binding, s.config.Clock.Now()); err != nil {
		return out, err
	}
	source, _ := caller.Session.Bindings()
	csrf := CSRFBinding{TenantID: source.TenantID, SessionID: source.SessionID, SessionVersion: source.Version}
	if caller.Session.CSRFState().Check(csrf, token, key) != nil {
		return out, ErrCSRFDenied
	}
	return AdminSessionRevocation{state: &adminSessionRevocationState{binding: cloneCommandBinding(binding), caller: caller, csrf: token}}, nil
}

func validateAdminSessionCaller(s *SessionService, caller GetResult, binding identity.CommandBinding, now time.Time) error {
	if s == nil || caller.validity == nil || caller.validity.owner != s || caller.validity.transport != CredentialCookie || caller.ValidateAt(now) != nil {
		return ErrUnauthenticated
	}
	source, err := caller.Session.Bindings()
	if err != nil || source.TenantID != binding.TenantID || identity.ActorID(source.UserID) != binding.ActorID {
		return identity.ForbiddenError{}
	}
	factor, err := caller.Session.MFAAuthentication().Bindings()
	if err != nil || source.Authentication.Proof.Purpose != "identity.password.mfa-primary" || factor.Method != "totp" {
		return identity.ForbiddenError{}
	}
	lifetime, err := caller.Session.Lifetime(now)
	// Match the selected M24 administrator-write profile: a fresh ordinary
	// session and a TOTP confirmation less than fifteen minutes old.
	if err != nil || !lifetime.Fresh || now.Before(factor.VerifiedAt) || now.Sub(factor.VerifiedAt) >= 15*time.Minute {
		return identity.ForbiddenError{}
	}
	return nil
}

// Validate checks this service's original, still-fresh actor admission.
// It neither reads the primary nor renews the original cutoff.
func (r AdminSessionRevocation) Validate(service *SessionService, now time.Time) error {
	if r.state == nil {
		return ErrUnauthenticated
	}
	return validateAdminSessionCaller(service, r.state.caller, r.state.binding, now)
}

// Binding returns the exact operation/actor/target correlation, not admission.
func (r AdminSessionRevocation) Binding() (identity.CommandBinding, bool) {
	if r.state == nil {
		return identity.CommandBinding{}, false
	}
	return r.state.binding, true
}

// Caller returns the original administrator record, never the target session.
func (r AdminSessionRevocation) Caller() Session {
	if r.state == nil {
		return Session{}
	}
	return r.state.caller.Session
}

// CSRFToken returns opaque input for the trusted transactional session owner.
// It is not a proof. Do not reveal or retain it beyond the execution attempt.
func (r AdminSessionRevocation) CSRFToken() CSRFToken {
	if r.state == nil {
		return CSRFToken{}
	}
	return r.state.csrf
}

// ValidUntil reports the original exclusive admission deadline, not permission.
func (r AdminSessionRevocation) ValidUntil() time.Time {
	if r.state == nil {
		return time.Time{}
	}
	return r.state.caller.ValidUntil()
}

// Format redacts both the authority custody and target identifiers.
func (AdminSessionRevocation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("session.AdminSessionRevocation(redacted)"))
}

// MarshalJSON disallows implicit serialization of this admission.
func (AdminSessionRevocation) MarshalJSON() ([]byte, error) { return nil, ErrSecretSerialization }

// MarshalText disallows implicit serialization of this admission.
func (AdminSessionRevocation) MarshalText() ([]byte, error) { return nil, ErrSecretSerialization }
