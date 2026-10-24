package postgres

import (
	"strings"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func passkeySignupSessionOperation() identity.FeatureOperation {
	const operation = "identity.passkey.register-verify"
	return identity.FeatureOperation{Owner: "passkey", OperationID: operation, SchemaID: operation + ".signup-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// Signup creates these owner epochs in the same transaction. A newer value
// cannot be adopted as an initial account, credential, factor or RP mapping.
// Global/tenant epochs remain the independently observed deployment authority.
func passkeySignupRecord(record session.Session) bool {
	if !passkeySigninRecord(record) {
		return false
	}
	s, _ := record.Bindings()
	v, _ := s.Authority.Bindings()
	return s.Authentication.CredentialVersion == 1 && v.User.Version == 1 && v.Identifier.Version == 1 && v.Credential.Version == 1 && v.Authorization.Version == 1 && v.Factor.Binding.Version == 1 && v.Passkey.Binding.Version == 1
}

// PasskeySignupSessionFields freezes the complete original prospective initial
// session in the existing closed session.result vocabulary. No bearer or
// WebAuthn response is projected. Known-empty MFA and initial RP authority are
// retained, not inferred or refreshed. This structural projection never proves
// successful registration, actual account creation or permission to issue.
func PasskeySignupSessionFields(record session.Session) ([]identity.FeatureField, error) {
	if !passkeySignupRecord(record) {
		return nil, session.ErrInvalidSessionCommand
	}
	return PasskeySigninSessionFields(record)
}

// PasskeySignupSession restores only the exact anonymous prospective-account
// profile, binding the selected session user to kernel-owned registration.user
// and its credential to the original lifecycle subject. Unknown session fields,
// missing fields, existing-account profiles and noninitial owner epochs deny.
// The native owner still must prove real WebAuthn verification and all current
// authorities, and stage account/protocol/session effects in the sole Work.
// Successful mapping grants no authentication, custody or freshness renewal.
func PasskeySignupSession(command identity.Command) (session.Session, error) {
	p, ok := command.Feature()
	if !ok || p.Operation != passkeySignupSessionOperation() || p.Binding.ValidateFor(p.Operation) != nil || p.Binding.ActorKind != authorization.SubjectServiceAccount {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	var user identity.UserID
	fields := make([]identity.FeatureField, 0, 96)
	for _, field := range p.Fields {
		if field.Name == "registration.user" {
			if user != "" || field.Value.Kind != identity.FeatureText {
				return session.Session{}, session.ErrInvalidSessionCommand
			}
			user = identity.UserID(field.Value.Text)
		}
		if name, owned := strings.CutPrefix(field.Name, passwordSessionPrefix); owned {
			field.Name = originalSessionPrefix + name
			fields = append(fields, field)
		}
	}
	record, err := OriginalSessionFromFields(p.Binding.TenantID, user, fields)
	if err != nil || !passkeySignupRecord(record) {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	s, _ := record.Bindings()
	if s.Authentication.CredentialID != p.Binding.RecordID {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	return record, nil
}
