package mfapostgres

import (
	"context"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	database "github.com/faustbrian/go-postgres"
)

// ReadPasskeySessionFactors requires the record's original positive known-empty
// factor generation on the primary. Missing, enrolled, foreign or newer state
// denies; it never selects a replacement generation. The pool is borrowed and
// maximum is 1ms..5s, bounded by earlier cancellation. Success is neither
// authentication nor a freshness lease. The native passkey owner must retain
// its read-start time before contributing IO and fence again in protected Work.
func ReadPasskeySessionFactors(ctx context.Context, pool *database.Pool, record session.Session, maximum time.Duration) error {
	spec, version, err := passkeySessionFactorRecord(record)
	if err != nil {
		return err
	}
	state, err := readKnownEmptyPrimary(ctx, pool, spec.TenantID, spec.UserID, maximum)
	if err != nil {
		return err
	}
	if state.Version() != version {
		return identity.ForbiddenError{}
	}
	return nil
}

// RequirePasskeySessionFactors locks the original known-empty MFA generation
// only in exact native identified passkey signin, action-bound label-update or
// additional-enrollment/removal phases, or self-session revoke-one Work. The registered
// owner must already bind the genuine original command
// and record and fence directory, credential, policy and RP/mapping authority.
// Signin targets this exact new record; revocation also permits the caller's
// same-user source session when its target is a sibling. Call in Apply and
// final checks, returning every error to abort. Locks belong to the sole
// coordinator until commit/abort. No authentication, transaction, generation
// adoption, factor mutation, proof consumption or journal is created here.
func RequirePasskeySessionFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, record session.Session) error {
	if ctx == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	spec, version, err := passkeySessionFactorRecord(record)
	if err != nil {
		return err
	}
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || b.ValidateFor(f.Operation) != nil || b.TenantID != spec.TenantID || b.UserID != spec.UserID || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(spec.UserID) {
		return invalidAuthority()
	}
	signin := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.signin-verify", SchemaID: "identity.passkey.signin-verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	// Both phases belong to the protected update action. Public signin options
	// select Authentication/BeforeCredential, not its transactional mutation
	// counters; substituting that profile would misclassify current-session use.
	updateOptions := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.update", SchemaID: "identity.passkey.update.options-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	updateAssertion := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.update", SchemaID: "identity.passkey.update.assertion-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	deleteOptions := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: "identity.passkey.delete.options-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	deleteAssertion := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.delete", SchemaID: "identity.passkey.delete.assertion-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	enrollmentAssertion := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.register-options", SchemaID: "identity.passkey.register-options.session-assertion-options-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	enrollmentRegistration := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.register-options", SchemaID: "identity.passkey.register-options.session-registration-options-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	enrollmentComplete := identity.FeatureOperation{Owner: "passkey", OperationID: "identity.passkey.register-verify", SchemaID: "identity.passkey.register-verify.session-registration-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	passkeyOwner := kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}
	switch {
	case f.Operation == signin && f.Contributor == passkeyOwner:
		if b.RecordID != spec.SessionID || spec.Version != 1 || spec.FamilyVersion != 1 || !spec.LastActivityAt.Equal(spec.IssuedAt) || life != (kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}) {
			return invalidAuthority()
		}
	case f.Operation == updateOptions && f.Contributor == passkeyOwner:
		if life != (kernel.LifecyclePlan{EventType: "passkey.reauthentication.started.v1", AfterVersion: 1}) {
			return invalidAuthority()
		}
	case f.Operation == updateAssertion && f.Contributor == passkeyOwner:
		// The native owner binds the original live session and genuine UV
		// assertion to the target metadata. These are metadata versions, not
		// session or protocol-counter versions; factor authority never advances.
		if life.EventType != "identity.passkey.rename_credential" || life.EventIndex != 0 || life.BeforeVersion == 0 || life.BeforeVersion == ^uint64(0) || life.AfterVersion != life.BeforeVersion+1 {
			return invalidAuthority()
		}
	case f.Operation == deleteOptions && f.Contributor == passkeyOwner:
		if b.RecordID != string(b.CommandID) || life != (kernel.LifecyclePlan{EventType: "passkey.reauthentication.started.v1", AfterVersion: 1}) {
			return invalidAuthority()
		}
	case f.Operation == deleteAssertion && f.Contributor == passkeyOwner:
		// Native/protocol owners prove original session UV and last-path safety.
		// This guard retains the same known-empty generation even when this Work
		// removes its authenticating key; it cannot adopt or mutate factor state.
		if life.EventType != "identity.passkey.remove_credential" || life.EventIndex != 0 || life.BeforeVersion == 0 || life.BeforeVersion == ^uint64(0) || life.AfterVersion != life.BeforeVersion+1 {
			return invalidAuthority()
		}
	case (f.Operation == enrollmentAssertion || f.Operation == enrollmentRegistration || f.Operation == enrollmentComplete) && f.Contributor == passkeyOwner:
		// Enrollment authenticates through a genuine existing-key UV assertion;
		// its three phases must not borrow password enrollment's profile or
		// advance/adopt a newer factor generation. The native/protocol owners
		// bind intent and preserve the original assertion's authority ceiling.
		event := "passkey.reauthentication.started.v1"
		if f.Operation == enrollmentRegistration {
			event = "passkey.registration.started.v1"
		} else if f.Operation == enrollmentComplete {
			event = "identity.passkey.create_credential"
		}
		if life != (kernel.LifecyclePlan{EventType: event, AfterVersion: 1}) {
			return invalidAuthority()
		}
	case f.Operation == session.RevokeOneOperation() && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1}):
		if life.EventType != "session.revoked.v1" || life.EventIndex != 0 || life.BeforeVersion == 0 || life.BeforeVersion == ^uint64(0) || life.AfterVersion != life.BeforeVersion+1 || b.RecordID == spec.SessionID && life.BeforeVersion != spec.Version {
			return invalidAuthority()
		}
	default:
		return invalidAuthority()
	}
	_, err = readKnownEmptyFactors(ctx, w, b, spec.UserID, version)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func passkeySessionFactorRecord(record session.Session) (session.SessionSpec, uint64, error) {
	spec, err := record.Bindings()
	if err != nil || spec.Authentication.Kind != session.AuthenticationVerified || spec.Authentication.Proof.Method != "passkey" || spec.Authentication.Proof.Purpose != "session-issue" || spec.Authentication.Proof.Assurance != auth.AssurancePhishingResistant || record.MFAAuthentication() != (session.MFAAuthentication{}) {
		return session.SessionSpec{}, 0, invalidAuthority()
	}
	if _, continued := record.CredentialContinuation(); continued {
		return session.SessionSpec{}, 0, invalidAuthority()
	}
	vector, err := spec.Authority.Bindings()
	key, keyErr := FactorAuthorityKey(spec.TenantID, spec.UserID)
	if err != nil || keyErr != nil || vector.Organization.Present || !vector.Passkey.Present || !vector.Factor.Present || vector.Factor.Binding.ScopeKey != key || vector.Factor.Binding.Version == 0 {
		return session.SessionSpec{}, 0, invalidAuthority()
	}
	return spec, vector.Factor.Binding.Version, nil
}
