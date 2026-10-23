package postgres

import (
	"strings"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func passkeySessionOperation() identity.FeatureOperation {
	const id = "identity.passkey.signin-verify"
	return identity.FeatureOperation{Owner: "passkey", OperationID: id, SchemaID: id + ".native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func passkeySigninRecord(record session.Session) bool {
	spec, err := record.Bindings()
	if err != nil || spec.Version != 1 || spec.FamilyVersion != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) || record.MFAAuthentication() != (session.MFAAuthentication{}) {
		return false
	}
	v, err := spec.Authority.Bindings()
	if err != nil || v.Organization.Present || !v.Factor.Present || !v.Passkey.Present || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "passkey" || spec.Authentication.Proof.Assurance != auth.AssurancePhishingResistant {
		return false
	}
	if _, continued := record.CredentialContinuation(); continued {
		return false
	}
	return spec.Authentication.Proof.Validate(auth.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: "session-issue", Audience: spec.Audience, Now: spec.IssuedAt}) == nil
}

// PasskeySigninSessionFields freezes the complete original prospective session
// before native intent fingerprinting. The closed session.result vocabulary
// retains authenticating credential, remember, all epochs and CSRF, not bearer
// bytes or a cryptographic assertion. Mapping never authenticates or authorizes.
func PasskeySigninSessionFields(record session.Session) ([]identity.FeatureField, error) {
	if !passkeySigninRecord(record) {
		return nil, session.ErrInvalidSessionCommand
	}
	fields, err := OriginalSessionFields(record)
	if err != nil {
		return nil, err
	}
	for i := range fields {
		fields[i].Name = passwordSessionPrefix + strings.TrimPrefix(fields[i].Name, originalSessionPrefix)
	}
	return fields, nil
}

// PasskeySigninSession restores only the complete canonical prospective record
// of the exact identified passkey assertion command. Mixed/unknown fields deny;
// other namespaces belong to the native passkey owner. Opaque WebAuthn custody,
// current RP/mapping/factor/risk and atomic protocol/session effects remain
// mandatory. A successful projection is not successful authentication.
func PasskeySigninSession(command identity.Command) (session.Session, error) {
	p, ok := command.Feature()
	if !ok || p.Operation != passkeySessionOperation() || p.Binding.UserID == "" || p.Binding.AnonymousFlowID != "" {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	fields := make([]identity.FeatureField, 0, 96)
	for _, field := range p.Fields {
		if name, owned := strings.CutPrefix(field.Name, passwordSessionPrefix); owned {
			field.Name = originalSessionPrefix + name
			fields = append(fields, field)
		}
	}
	record, err := OriginalSessionFromFields(p.Binding.TenantID, p.Binding.UserID, fields)
	if err != nil || !passkeySigninRecord(record) {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	spec, _ := record.Bindings()
	if p.Binding.RecordID != spec.SessionID {
		return session.Session{}, session.ErrInvalidSessionCommand
	}
	return record, nil
}
