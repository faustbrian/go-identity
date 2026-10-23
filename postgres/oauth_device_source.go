package postgres

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
)

// RequireOAuthDeviceGrantSource locks and compares the approved human source's
// exact credential and authorization epochs without changing a device poll's
// client actor, anonymous flow, audit or recovery scope. Only the closed native
// device-token participant and its original preparation/apply/final command are
// admitted. Current source withdrawal poisons Work, including ignored denials.
//
// The native owner must derive these expectations through the session owner's
// OriginalDeviceGrantAdmission, bind the complete original source into its keyed
// command and match its locked grant, client and consent. This fence is not
// authentication, authorization, consent, proof consumption or a validity lease.
// Directory/session checks and original temporal bounds remain separate. Locks,
// SQL, errors and transaction lifetime retain the existing credential and
// authorization owners; no transaction, cache or authority is created here.
func (w Work) RequireOAuthDeviceGrantSource(ctx context.Context, owner FeatureExecutionContributor, credential CredentialAdmission, policy UserAuthorizationAdmission) (time.Time, error) {
	if err := w.usable(); err != nil {
		return time.Time{}, err
	}
	if ctx == nil {
		return time.Time{}, w.fail(w.state.ctx, invalidWork())
	}
	if err := ctx.Err(); err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	binding, err := w.oauthDeviceGrantSourceBinding(owner, credential, policy)
	if err != nil {
		return time.Time{}, w.fail(ctx, err)
	}
	if _, err := w.requireActiveCredential(ctx, binding, credential); err != nil {
		return time.Time{}, err
	}
	if err := w.requireActiveUserAuthorization(ctx, binding, policy); err != nil {
		return time.Time{}, err
	}
	// The authorization lock can wait across credential expiry. Repeat the
	// existing credential-owner check after all locks, without renewing Work.
	return w.requireActiveCredential(ctx, binding, credential)
}

func (w Work) oauthDeviceGrantSourceBinding(owner FeatureExecutionContributor, credential CredentialAdmission, policy UserAuthorizationAdmission) (identity.CommandBinding, error) {
	b, feature, _, err := w.FeatureScope(owner)
	op := identity.FeatureOperation{Owner: "oauth-server/device", OperationID: "identity.oauth-server.device-token", SchemaID: "identity.oauth-server.device-token.native-device-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	if err != nil || feature.Operation != op || feature.Contributor != (ContributorDescriptor{Owner: "oauth-server/postgres", ContractID: "identity.oauth-server", Version: 1}) || b.ValidateFor(op) != nil || b.ActorKind != authorization.SubjectServiceAccount || b.UserID != "" || b.AnonymousFlowID != b.RecordID {
		return identity.CommandBinding{}, invalidWork()
	}
	var original *identity.Command
	switch {
	case w.state.featureApplying:
		original = w.state.featureApplyCommand
	case w.state.featurePreparationCommand != nil && w.state.featurePreparationPlan != nil:
		original = w.state.featurePreparationCommand
	default:
		original = w.state.featureCommitCommand
	}
	if original == nil {
		return identity.CommandBinding{}, invalidWork()
	}
	s, ok := commandFeature(*original)
	if !ok || s.Binding != b || s.Operation != op {
		return identity.CommandBinding{}, invalidWork()
	}
	want := map[string]string{"oauth.device-source-user": string(credential.Credential.UserID), "oauth.client": string(b.ActorID), "oauth.grant": b.RecordID}
	seen := make(map[string]bool, len(want))
	for _, field := range s.Fields {
		if expected, selected := want[field.Name]; selected {
			if seen[field.Name] || field.Value.Kind != identity.FeatureText || field.Value.Text != expected {
				return identity.CommandBinding{}, invalidWork()
			}
			seen[field.Name] = true
		}
	}
	source := credential.Credential.UserID
	if len(seen) != len(want) || credential.Credential.Validate(b.TenantID, source) != nil || credential.Credential.Kind != identity.CredentialPassword || credential.Credential.Owner != "identity/password" || credential.UserAuthorityVersion == 0 || credential.IdentifierAuthorityVersion == 0 || credential.CredentialAuthorityVersion == 0 || policy.Scope.Validate() != nil || policy.Version == 0 || string(policy.Scope.TenantID) != string(b.TenantID) || string(policy.Scope.SubjectID) != string(source) {
		return identity.CommandBinding{}, invalidWork()
	}
	// Only existing owner lookups see the source user. The actual command and
	// Work binding retain the client actor and anonymous device transaction.
	b.UserID = source
	return b, nil
}
