package postgres

import (
	"strings"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

const ssoOIDCSessionPrefix = "sso.oidc.session."
const ssoOAuth2SessionPrefix = "sso.oauth2.session."
const ssoSAMLSessionPrefix = "sso.saml.session."

func ssoOIDCSessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/oidc", OperationID: "identity.sso.oidc-callback", SchemaID: "sso-enterprise-oidc-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

func ssoOAuth2SessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "sso/oauth2", OperationID: "identity.sso.oauth-callback", SchemaID: "sso-enterprise-oauth2-callback-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// SSOOIDCSigninSessionFields binds the complete prospective enterprise session
// to the callback's keyed intent. The contact, organization, factor and
// credential metadata grant no authority. The coordinator must subsequently
// validate current ownership and stage session effects in its original Work.
func SSOOIDCSigninSessionFields(record session.Session) ([]identity.FeatureField, error) {
	return ssoSigninSessionFields(record, ssoOIDCSessionPrefix, "sso-oidc")
}

// SSOOAuth2SigninSessionFields freezes the prospective OAuth member session
// in the exact callback intent. It creates neither authentication nor storage;
// the original transaction must still fence current account and browser use.
func SSOOAuth2SigninSessionFields(record session.Session) ([]identity.FeatureField, error) {
	return ssoSigninSessionFields(record, ssoOAuth2SessionPrefix, "sso-oauth2")
}

// SSOSAMLSigninSessionFields freezes the exact SAML session intent for the
// existing native coordinator. It does not authenticate a provider or issue.
func SSOSAMLSigninSessionFields(record session.Session) ([]identity.FeatureField, error) {
	return ssoSigninSessionFields(record, ssoSAMLSessionPrefix, "sso-saml")
}

func ssoSigninSessionFields(record session.Session, prefix, method string) ([]identity.FeatureField, error) {
	spec, err := ssoSigninSessionSpec(record, method)
	if err != nil {
		return nil, err
	}
	fields, err := OriginalSessionFields(record)
	if err != nil {
		return nil, err
	}
	for index := range fields {
		fields[index].Name = prefix + strings.TrimPrefix(fields[index].Name, originalSessionPrefix)
	}
	return append(fields,
		identity.FeatureField{Name: prefix + "tenant.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(spec.TenantID)}},
		identity.FeatureField{Name: prefix + "user.id", Value: identity.FeatureValue{Kind: identity.FeatureText, Text: string(spec.UserID)}},
	), nil
}

// SSOOIDCSigninSession reconstructs only the exact enterprise callback and
// its original browser custody. The selected user remains part of the session,
// not a substitute for the command's anonymous flow. Decoding never creates an
// opaque proof, restores a bearer, refreshes evidence or checks live authority.
func SSOOIDCSigninSession(command identity.Command) (session.Session, error) {
	return ssoSigninSession(command, ssoOIDCSessionOperation(), ssoOIDCSessionPrefix, "sso-oidc", ssoOAuth2SessionPrefix, ssoSAMLSessionPrefix)
}

// SSOOAuth2SigninSession decodes only the exact OAuth callback's original
// browser-bound intent. It cannot restore a secret or renew current authority.
func SSOOAuth2SigninSession(command identity.Command) (session.Session, error) {
	return ssoSigninSession(command, ssoOAuth2SessionOperation(), ssoOAuth2SessionPrefix, "sso-oauth2", ssoOIDCSessionPrefix, ssoSAMLSessionPrefix)
}

// SSOSAMLSigninSession decodes only the original SAML callback's prospective
// linked session, not browser possession or live authority.
func SSOSAMLSigninSession(command identity.Command) (session.Session, error) {
	return ssoSigninSession(command, kernel.SSOSAMLSigninOperation(), ssoSAMLSessionPrefix, "sso-saml", ssoOIDCSessionPrefix, ssoOAuth2SessionPrefix)
}

func ssoSigninSession(command identity.Command, operation identity.FeatureOperation, prefix, method string, foreignPrefixes ...string) (session.Session, error) {
	deny := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	feature, ok := command.Feature()
	_, cookie := command.PreAuthCookie()
	_, code := command.OneTimeCode()
	_, recovery := command.RecoveryCode()
	_, bearer := command.SessionToken()
	if !ok || !cookie || code || recovery || bearer || feature.Operation != operation {
		return deny()
	}
	binding := feature.Binding
	start, err := identity.ParseCommandID(binding.RecordID)
	if err != nil || start == binding.CommandID || binding.ActorKind != authorization.SubjectServiceAccount || binding.UserID != "" || binding.AnonymousFlowID == "" {
		return deny()
	}
	return ssoSigninSessionFromFields(feature, prefix, method, append(foreignPrefixes, ssoSAMLIDPConfirmationSessionPrefix)...)
}

func ssoSigninSessionFromFields(feature identity.FeatureCommandSpec, prefix, method string, foreignPrefixes ...string) (session.Session, error) {
	deny := func() (session.Session, error) { return session.Session{}, session.ErrInvalidSessionCommand }
	binding := feature.Binding
	var tenant identity.TenantID
	var user identity.UserID
	fields := make([]identity.FeatureField, 0, len(feature.Fields))
	for _, field := range feature.Fields {
		for _, foreign := range foreignPrefixes {
			if strings.HasPrefix(field.Name, foreign) {
				return deny()
			}
		}
		name, selected := strings.CutPrefix(field.Name, prefix)
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
	if tenant != binding.TenantID || user == "" || (binding.UserID != "" && user != binding.UserID) {
		return deny()
	}
	record, err := OriginalSessionFromFields(tenant, user, fields)
	if err != nil {
		return deny()
	}
	spec, err := ssoSigninSessionSpec(record, method)
	if err != nil || string(spec.Authentication.Proof.ID) != string(binding.CommandID) {
		return deny()
	}
	return record, nil
}

func ssoSigninSessionSpec(record session.Session, method string) (session.SessionSpec, error) {
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
	if err != nil || !vector.Organization.Present || !vector.Factor.Present || vector.Passkey.Present || spec.Authentication.Kind != session.AuthenticationVerified || proof.Method != method || proof.Assurance != auth.AssuranceSingleFactor {
		return deny()
	}
	if proof.Validate(auth.ProofUse{Tenant: string(spec.TenantID), Subject: string(spec.UserID), Purpose: "session-issue", Audience: spec.Audience, Now: spec.IssuedAt}) != nil {
		return deny()
	}
	return spec, nil
}
