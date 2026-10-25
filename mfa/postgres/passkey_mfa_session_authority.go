package mfapostgres

import (
	"context"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
)

// RequireMFAPasskeySessionFactors fences the original confirmed TOTP enrollment
// and account-wide factor generation of a completed passkey/TOTP session, only
// in exact native passkey label-update, additional-key enrollment or removal
// Work. It does not broaden the known-empty guard or permit signin.
//
// The registered native owner must authenticate possession and fence directory,
// credential, policy and original session/family, and require genuine fresh
// action-bound UV for the mutation. Call in Apply and final checks, before RP
// mapping locks, returning any error to abort the coordinator's transaction.
// Account/factor locks remain owned by that coordinator. No factor secret,
// replay counter, generation, proof or freshness lease is created or changed.
func RequireMFAPasskeySessionFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, record session.Session) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := record.Bindings()
	m, me := record.MFAAuthentication().Bindings()
	if err != nil || me != nil || s.Authentication.Kind != session.AuthenticationVerified || s.Authentication.Proof.Method != "passkey" || s.Authentication.Proof.Purpose != session.PasskeyMFAPrimaryPurpose || s.Authentication.Proof.Assurance != auth.AssurancePhishingResistant || m.Method != "totp" || string(m.PrimaryCommandID) != string(s.Authentication.Proof.ID) {
		return invalidAuthority()
	}
	if _, continued := record.CredentialContinuation(); continued {
		return invalidAuthority()
	}
	v, err := s.Authority.Bindings()
	key, ke := FactorAuthorityKey(s.TenantID, s.UserID)
	if err != nil || ke != nil || v.Organization.Present || !v.Passkey.Present || !v.Factor.Present || v.Factor.Binding.ScopeKey != key || v.Factor.Binding.Version != m.FactorAuthorityVersion {
		return invalidAuthority()
	}
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || b.ValidateFor(f.Operation) != nil || b.TenantID != s.TenantID || b.UserID != s.UserID || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || b.ActorID != identity.ActorID(s.UserID) || f.Contributor != (kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}) {
		return invalidAuthority()
	}
	op := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.update", SchemaID: "identity.passkey.update.options-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	switch {
	case f.Operation == op:
		if life != (kernel.LifecyclePlan{EventType: "passkey.reauthentication.started.v1", AfterVersion: 1}) {
			return invalidAuthority()
		}
	case f.Operation == (identity.FeatureOperation{Owner: op.Owner, OperationID: op.OperationID, SchemaID: "identity.passkey.update.assertion-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}):
		if life.EventType != "identity.passkey.rename_credential" || life.EventIndex != 0 || life.BeforeVersion == 0 || life.BeforeVersion == ^uint64(0) || life.AfterVersion != life.BeforeVersion+1 {
			return invalidAuthority()
		}
	case f.Operation == (identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.register-options", SchemaID: "identity.passkey.register-options.session-assertion-options-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}):
		if b.RecordID != string(b.CommandID) || life != (kernel.LifecyclePlan{EventType: "passkey.reauthentication.started.v1", AfterVersion: 1}) {
			return invalidAuthority()
		}
	case f.Operation == (identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.register-options", SchemaID: "identity.passkey.register-options.session-registration-options-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}):
		if b.RecordID != string(b.CommandID) || life != (kernel.LifecyclePlan{EventType: "passkey.registration.started.v1", AfterVersion: 1}) {
			return invalidAuthority()
		}
	case f.Operation == (identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.register-verify", SchemaID: "identity.passkey.register-verify.session-registration-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}):
		if b.RecordID != string(b.CommandID) || life != (kernel.LifecyclePlan{EventType: "identity.passkey.create_credential", AfterVersion: 1}) {
			return invalidAuthority()
		}
	case f.Operation == (identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: "identity.passkey.delete.options-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}):
		if b.RecordID != string(b.CommandID) || life != (kernel.LifecyclePlan{EventType: "passkey.reauthentication.started.v1", AfterVersion: 1}) {
			return invalidAuthority()
		}
	case f.Operation == (identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: "identity.passkey.delete.assertion-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}):
		if life.EventType != "identity.passkey.remove_credential" || life.EventIndex != 0 || life.BeforeVersion == 0 || life.BeforeVersion == ^uint64(0) || life.AfterVersion != life.BeforeVersion+1 {
			return invalidAuthority()
		}
	default:
		return invalidAuthority()
	}
	return requireTOTPSessionFactor(ctx, w, b, s.UserID, m.FactorID, TOTPSessionFactorState{EnrollmentVersion: m.EnrollmentVersion, AuthorityVersion: m.FactorAuthorityVersion})
}
