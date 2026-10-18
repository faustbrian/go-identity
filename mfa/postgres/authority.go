package mfapostgres

import (
	"context"
	"encoding/base64"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

func invalidAuthority() error { return identity.InvalidInputError{Field: "factor_authority"} }

// InitializeSignup establishes known empty factor state only for the account
// genuinely created by this unchanged signup in the current coordinator Work.
// Call after kernel registration and before commit; neutral acceptance and
// pre-existing users cannot initialize state. Duplicate calls fail, not upsert
// or erase enrollment. The coordinator owns rollback/replay and resource life.
// This does not enroll, verify or disable a factor or grant recovery permission.
func InitializeSignup(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, user identity.UserID) error {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return err
	}
	b, f, life, err := w.FeatureScope(owner)
	profile := f.Operation.Owner == "identity/password" && b.OperationID == "identity.password.signup" && f.Operation.SchemaID == "password-signup" || f.Operation.Owner == "identity/username" && b.OperationID == "identity.username.signup" && f.Operation.SchemaID == "username-signup"
	if err != nil || !profile || f.Operation.SchemaVersion != 1 || f.Operation.RecordRequirement != identity.FeatureRecordOmitted || f.Operation.SubjectRequirement > identity.FeatureSubjectAnonymousFlow || b.ValidateFor(f.Operation) != nil || f.Contributor.Owner != "identity/password/postgres" || f.Contributor.ContractID != "identity.password" || f.Contributor.Version != 1 || life.EventType != "user.created.v1" || life.BeforeVersion != 0 || life.AfterVersion != 0 {
		return invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return invalidAuthority()
	}
	id, err := base64.RawURLEncoding.DecodeString(string(b.CommandID))
	if err != nil || len(id) != 16 {
		return invalidAuthority()
	}
	n, err := w.Exec(ctx, `INSERT INTO identity_mfa.factor_authorities(tenant_id,user_id,version,active_factors,initialized_command_id,initialized_purpose)
SELECT r.tenant_id,r.user_id,1,0,r.command_id,r.purpose
FROM identity.registration_bindings r
JOIN identity.users u ON u.tenant_id=r.tenant_id AND u.user_id=r.user_id
WHERE r.tenant_id=$1 AND r.purpose=$4 AND r.command_id=$2 AND r.user_id=$3
AND u.status='active' AND u.version=1`, string(b.TenantID), id, string(user), b.OperationID)
	if err != nil {
		return identity.UnavailableError{}
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}

// RequireEmailRecovery locks the current MFA generation for this native reset
// until the sole coordinator commits or rolls back. Missing or enrolled state
// denies; no absence is inferred from schema installation or session metadata.
// Request permits expectedVersion=0 to select current known-empty state;
// completion requires the nonzero generation authenticated by original custody.
// Account/email/risk/capability admission remain independently required.
// Return errors to the coordinator. A returned view must not be cached or used
// after Work closes. This function starts no transaction, retry or goroutine.
func RequireEmailRecovery(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, user identity.UserID, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return mfa.FactorAuthority{}, err
	}
	b, f, _, err := w.FeatureScope(owner)
	if err != nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return requireEmailRecovery(ctx, w, b, f, user, expectedVersion)
}

// RequireEmailRecoveryPreparation fences the signed original factor generation
// before reset-completion generation. Only the exact registered preparation
// owner's active Work and unchanged reset input scope are accepted. It retains
// the primary row lock through that admission transaction; final mutation must
// independently call RequireEmailRecovery again, since generation runs outside
// the transaction. It never infers absence, initializes state or authorizes
// hashing, capability consumption or password replacement by itself.
func RequireEmailRecoveryPreparation(ctx context.Context, w kernel.Work, owner kernel.FeaturePreparationContributor, command identity.Command, user identity.UserID, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	spec, ok := command.PasswordResetInputFeature()
	b, f, _, err := w.FeatureScope(owner)
	if err != nil || !ok || b != spec.Binding || f.Operation != spec.Operation || b.OperationID != "identity.password.reset-complete" || b.UserID != user {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return requireEmailRecovery(ctx, w, b, f, user, expectedVersion)
}

// RequireEmailRecoveryRequestPreparation selects and locks current known-empty
// factor authority for the exact anonymous native reset-request preparation.
// Missing or enrolled authority denies; it never initializes or infers state.
// The selected generation must enter original signed issuance and be fenced
// again at final Work because generation runs outside this transaction.
func RequireEmailRecoveryRequestPreparation(ctx context.Context, w kernel.Work, owner kernel.FeaturePreparationContributor, command identity.Command, user identity.UserID) (mfa.FactorAuthority, error) {
	spec, ok := command.Feature()
	b, f, _, err := w.FeatureScope(owner)
	if ctx == nil || err != nil || !ok || b != spec.Binding || f.Operation != spec.Operation || b.OperationID != "identity.password.reset-request" || b.UserID != "" {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return requireEmailRecovery(ctx, w, b, f, user, 0)
}

func requireEmailRecovery(ctx context.Context, w kernel.Work, b identity.CommandBinding, f kernel.FeatureRegistration, user identity.UserID, expectedVersion uint64) (mfa.FactorAuthority, error) {
	request := b.OperationID == "identity.password.reset-request"
	complete := b.OperationID == "identity.password.reset-complete"
	if (!request && !complete) || complete && expectedVersion == 0 || f.Operation.Owner != "identity/password" || f.Contributor.Owner != "identity/password/postgres" || f.Contributor.ContractID != "identity.password" || f.Contributor.Version != 1 || b.UserID != "" && b.UserID != user {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return readKnownEmptyFactors(ctx, w, b, user, expectedVersion)
}

// Both workflow families use the same authoritative MFA row and lock. No
// second factor generation, inferred absence or feature-local enrollment exists.
func readKnownEmptyFactors(ctx context.Context, w kernel.Work, b identity.CommandBinding, user identity.UserID, expectedVersion uint64) (mfa.FactorAuthority, error) {
	state, err := readFactorAuthority(ctx, w, b, user, expectedVersion)
	if err != nil {
		return mfa.FactorAuthority{}, err
	}
	if err := state.RequireEmailRecovery(b.TenantID, user); err != nil {
		return mfa.FactorAuthority{}, err
	}
	return state, nil
}

func readFactorAuthority(ctx context.Context, w kernel.Work, b identity.CommandBinding, user identity.UserID, expectedVersion uint64) (mfa.FactorAuthority, error) {
	rows, err := w.Query(ctx, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 FOR UPDATE`, string(b.TenantID), string(user))
	if err != nil {
		return mfa.FactorAuthority{}, identity.UnavailableError{}
	}
	defer rows.Close()
	if !rows.Next() {
		if rows.Err() != nil {
			return mfa.FactorAuthority{}, identity.UnavailableError{}
		}
		return mfa.FactorAuthority{}, identity.ForbiddenError{}
	}
	var version string
	var active int32
	if rows.Scan(&version, &active) != nil {
		return mfa.FactorAuthority{}, identity.UnavailableError{}
	}
	if rows.Next() || rows.Err() != nil {
		return mfa.FactorAuthority{}, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil || active < 0 || expectedVersion != 0 && v != expectedVersion {
		return mfa.FactorAuthority{}, identity.ForbiddenError{}
	}
	state, err := mfa.NewFactorAuthority(mfa.AuthorityRecord{TenantID: b.TenantID, UserID: user, Version: v, ActiveFactors: uint32(active)})
	if err != nil {
		return mfa.FactorAuthority{}, identity.UnavailableError{}
	}
	return state, nil
}
