package mfapostgres

import (
	"context"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// RequireSSOOAuth2GrantRevocationFactors locks the original single-factor
// enterprise OAuth2 session's known-empty MFA generation for the exact registered
// same-user grant-revocation settlement. Command and Work must retain the same
// binding and operation, including the original grant callback record ID and
// exact session ID/version. The SSO owner must independently fence the original
// grant, current session, account/provider and membership in the same Work.
// Call in Apply and final checks, propagating every error to abort. Locks stay
// with the sole coordinator until commit or rollback. No factor state, proof,
// session, renewed authority, transaction or provider revocation is created.
func RequireSSOOAuth2GrantRevocationFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, record session.Session) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	sessionSpec, version, err := ssoOAuth2SessionFactors(record)
	if err != nil {
		return err
	}
	spec, ok := command.Feature()
	if !ok {
		return invalidAuthority()
	}
	binding, feature, life, err := w.FeatureScope(owner)
	if err != nil || ssoOAuth2GrantRevocationFactorScope(spec, binding, feature, life, sessionSpec) != nil {
		return invalidAuthority()
	}
	_, err = readKnownEmptyFactors(ctx, w, binding, sessionSpec.UserID, version)
	return err
}

func ssoOAuth2GrantRevocationFactorScope(command identity.FeatureCommandSpec, binding identity.CommandBinding, feature kernel.FeatureRegistration, life kernel.LifecyclePlan, record session.SessionSpec) error {
	operation := identity.FeatureOperation{
		Owner: "sso", OperationID: "identity.sso.provider-token.revoke",
		SchemaID: "identity.sso.provider-token.revoke.native-v1", SchemaVersion: 1,
		RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectUser,
	}
	if command.Binding != binding || command.Operation != operation || feature.Operation != operation || binding.ValidateFor(operation) != nil {
		return invalidAuthority()
	}
	if binding.TenantID != record.TenantID || binding.UserID != record.UserID || binding.ActorKind != authorization.SubjectUser || string(binding.ActorID) != string(record.UserID) || binding.AnonymousFlowID != "" {
		return invalidAuthority()
	}
	if _, err := identity.ParseCommandID(binding.RecordID); err != nil {
		return invalidAuthority()
	}
	if feature.Contributor != (kernel.ContributorDescriptor{Owner: "sso/postgres", ContractID: "sso.enterprise-token-vault", Version: 1}) || life != (kernel.LifecyclePlan{EventType: "enterprise_provider.token_revocation_settled.v1", AfterVersion: 1}) {
		return invalidAuthority()
	}

	var sessionID, sessionVersion bool
	for _, field := range command.Fields {
		switch field.Name {
		case "sso.vault.session-id":
			if sessionID || field.Value.Kind != identity.FeatureText || field.Value.Text != record.SessionID {
				return invalidAuthority()
			}
			sessionID = true
		case "sso.vault.session-version":
			if sessionVersion || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 != record.Version {
				return invalidAuthority()
			}
			sessionVersion = true
		}
	}
	if !sessionID || !sessionVersion {
		return invalidAuthority()
	}
	return nil
}
