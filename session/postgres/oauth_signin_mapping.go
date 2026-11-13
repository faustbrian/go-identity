package postgres

import (
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

func oauthSessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/oauth", OperationID: "identity.oauth.callback", SchemaID: "oauth-signin-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// OAuthSigninSessionFields freezes the complete prospective provider session
// under session.result before the native owner fingerprints the command.
// Authentication and current link/factor checks remain native-owned: mapping
// creates neither an opaque proof nor permission to issue credentials. Only
// initial existing-account OAuth/SFA with a known-empty factor epoch is selected;
// organization, passkey, completed-MFA and credential-continuation profiles deny.
// Tenant/user remain explicit even though the callback's command is anonymous.
func OAuthSigninSessionFields(record session.Session) ([]identity.FeatureField, error) {
	if !oauthSigninRecord(record) {
		return nil, session.ErrInvalidSessionCommand
	}
	fields, err := OriginalSessionFields(record)
	if err != nil {
		return nil, session.ErrInvalidSessionCommand
	}
	for index := range fields {
		fields[index].Name = passwordSessionPrefix + strings.TrimPrefix(fields[index].Name, originalSessionPrefix)
	}
	spec, _ := record.Bindings()
	return append(fields,
		identity.FeatureField{Name: passwordSessionPrefix + "tenant.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(spec.TenantID)}},
		identity.FeatureField{Name: passwordSessionPrefix + "user.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(spec.UserID)}},
	), nil
}

// OAuthSigninSession restores only the exact existing-account callback schema
// and original preauth custody. It preserves provider-credential provenance,
// Remember, all authority epochs and optional CSRF; it never authenticates them.
// Missing/unknown/malformed session fields and different custody deny. Other
// field namespaces remain the OAuth native owner's responsibility. That owner
// must bind provider evidence to this exact selected user and credential, check
// current authority and atomically consume state with the complete session.
func OAuthSigninSession(command identity.Command) (session.Session, error) {
	deny := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	feature, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	_, bearer := command.SessionToken()
	if !ok || !cookie || code || recovery || bearer || feature.Operation != oauthSessionOperation() || feature.Binding.ActorKind != authorization.SubjectServiceAccount || feature.Binding.UserID != "" || feature.Binding.AnonymousFlowID == "" {
		return deny()
	}
	var tenant identity.TenantID
	var user identity.UserID
	fields := make([]identity.FeatureField, 0, 64)
	for _, field := range feature.Fields {
		name, selected := strings.CutPrefix(field.Name, passwordSessionPrefix)
		if !selected {
			continue
		}
		switch name {
		case "tenant.id", "user.id":
			if field.Value.Kind != identity.FeatureText || field.Value.Uint64 != 0 || field.Value.Int64 != 0 || field.Value.Bool || field.Value.Time != (time.Time{}) || field.Value.Bytes != nil {
				return deny()
			}
			if name == "tenant.id" {
				tenant = identity.TenantID(field.Value.Text)
			} else {
				user = identity.UserID(field.Value.Text)
			}
		default:
			field.Name = originalSessionPrefix + name
			fields = append(fields, field)
		}
	}
	if tenant != feature.Binding.TenantID || user == "" {
		return deny()
	}
	record, err := OriginalSessionFromFields(tenant, user, fields)
	if err != nil || !oauthSigninRecord(record) {
		return deny()
	}
	spec, _ := record.Bindings()
	if string(spec.Authentication.Proof.ID) != string(feature.Binding.CommandID) {
		return deny()
	}
	return record, nil
}

func oauthSigninRecord(record session.Session) bool {
	spec, err := record.Bindings()
	if err != nil || spec.Version != 1 || spec.FamilyVersion != 1 || !spec.IssuedAt.Equal(spec.LastActivityAt) || record.MFAAuthentication() != (session.MFAAuthentication{}) {
		return false
	}
	if _, continued := record.CredentialContinuation(); continued {
		return false
	}
	vector, err := spec.Authority.Bindings()
	if err != nil || vector.Organization.Present || !vector.Factor.Present || vector.Passkey.Present || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "oauth" || spec.Authentication.Proof.Assurance != auth.AssuranceSingleFactor {
		return false
	}
	return spec.Authentication.Proof.Validate(auth.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: "session-issue", Audience: spec.Audience, Now: spec.IssuedAt}) == nil
}
