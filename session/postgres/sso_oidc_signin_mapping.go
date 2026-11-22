package postgres

import (
	"strings"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

const ssoOIDCSessionPrefix = "sso.oidc.session."

func ssoOIDCSessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/oidc", OperationID: "identity.sso.oidc-callback", SchemaID: "sso-enterprise-oidc-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// SSOOIDCSigninSessionFields binds the complete prospective enterprise session
// to the callback's keyed intent. The contact, organization, factor and
// credential metadata grant no authority. The coordinator must subsequently
// validate current ownership and stage session effects in its original Work.
func SSOOIDCSigninSessionFields(record session.Session) ([]identity.FeatureField, error) {
	spec, err := ssoOIDCSigninSessionSpec(record)
	if err != nil {
		return nil, err
	}
	fields, err := OriginalSessionFields(record)
	if err != nil {
		return nil, err
	}
	for index := range fields {
		fields[index].Name = ssoOIDCSessionPrefix + strings.TrimPrefix(fields[index].Name, originalSessionPrefix)
	}
	return append(fields,
		identity.FeatureField{Name: ssoOIDCSessionPrefix + "tenant.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(spec.TenantID)}},
		identity.FeatureField{Name: ssoOIDCSessionPrefix + "user.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(spec.UserID)}},
	), nil
}

// SSOOIDCSigninSession reconstructs only the exact enterprise callback and
// its original browser custody. The selected user remains part of the session,
// not a substitute for the command's anonymous flow. Decoding never creates an
// opaque proof, restores a bearer, refreshes evidence or checks live authority.
func SSOOIDCSigninSession(command identity.Command) (session.Session, error) {
	deny := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	feature, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	_, bearer := command.SessionToken()
	if !ok || !cookie || code || recovery || bearer || feature.Operation != ssoOIDCSessionOperation() {
		return deny()
	}
	binding := feature.Binding
	start, err := identity.ParseCommandID(binding.RecordID)
	if err != nil || start == binding.CommandID || binding.ActorKind != authorization.SubjectServiceAccount || binding.UserID != "" || binding.AnonymousFlowID == "" {
		return deny()
	}
	var tenant identity.TenantID
	var user identity.UserID
	fields := make([]identity.FeatureField, 0, len(feature.Fields))
	for _, field := range feature.Fields {
		name, selected := strings.CutPrefix(field.Name, ssoOIDCSessionPrefix)
		if !selected {
			continue
		}
		switch name {
		case "tenant.id", "user.id":
			if field.Value.Kind != identity.FeatureText {
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
	if tenant != binding.TenantID || user == "" {
		return deny()
	}
	record, err := OriginalSessionFromFields(tenant, user, fields)
	if err != nil {
		return deny()
	}
	spec, err := ssoOIDCSigninSessionSpec(record)
	if err != nil || string(spec.Authentication.Proof.ID) != string(binding.CommandID) {
		return deny()
	}
	return record, nil
}

func ssoOIDCSigninSessionSpec(record session.Session) (session.SessionSpec, error) {
	deny := func() (session.SessionSpec, error) { return session.SessionSpec{}, session.ErrInvalidSessionCommand }
	spec, err := record.Bindings()
	if err != nil || spec.Version != 1 || spec.FamilyVersion != 1 || !spec.IssuedAt.Equal(spec.LastActivityAt) || record.MFAAuthentication() != (session.MFAAuthentication{}) {
		return deny()
	}
	if _, continued := record.CredentialContinuation(); continued {
		return deny()
	}
	vector, err := spec.Authority.Bindings()
	proof := spec.Authentication.Proof
	if err != nil || !vector.Organization.Present || !vector.Factor.Present || vector.Passkey.Present || spec.Authentication.Kind != session.AuthenticationVerified || proof.Method != "sso-oidc" || proof.Assurance != auth.AssuranceSingleFactor {
		return deny()
	}
	if proof.Validate(auth.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: "session-issue", Audience: spec.Audience, Now: spec.IssuedAt}) != nil {
		return deny()
	}
	return spec, nil
}
