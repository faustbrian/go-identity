package mfapostgres

import (
	"context"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// ReadOTPSigninFactors reads the current known-empty factor generation for the
// native OTP-only signin profile. Missing, enrolled or corrupt state denies;
// nothing initializes or infers absence. This is preliminary metadata, not
// authentication or a freshness lease. Freeze it in original native custody and
// fence the same generation in each counted, reservation and protected phase.
// The pool is borrowed; duration is 1ms..5s and earlier cancellation wins. No
// transaction, retry or goroutine is owned and provider errors are redacted.
func ReadOTPSigninFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximum time.Duration) (mfa.FactorAuthority, error) {
	return readKnownEmptyPrimary(ctx, pool, tenant, user, maximum)
}

// RequireOTPSigninAttemptFactors fences the original known-empty MFA generation
// before the exact live native OTP signin owner compares or charges an attempt.
// The supplied user must be the actual recipient authenticated by original
// native custody, including for anonymous-flow commands. Errors must abort the
// coordinator phase; the row lock lasts until its transaction closes. It grants
// no code, session or authentication authority and owns no transaction or retry.
func RequireOTPSigninAttemptFactors(ctx context.Context, w kernel.OTPAttemptWork, owner kernel.OTPAttemptContributor, user identity.UserID, expectedVersion uint64) error {
	if err := validateOTPSigninFactorRequest(ctx, user, expectedVersion); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	if err != nil {
		return err
	}
	command, err := w.NativeCommand(owner)
	if err != nil {
		return err
	}
	spec, ok := command.Feature()
	if !ok {
		return invalidAuthority()
	}
	return requireOTPSigninFactors(ctx, w.Query, b.Command, spec, owner.Descriptor(), b.Plan, user, expectedVersion)
}

// RequireOTPSigninReservationFactors fences the unchanged original known-empty
// generation before native OTP signin reservation or rebind. Only the exact live
// owner and consume profile are accepted. The recipient, error propagation and
// transaction-owned lock rules match RequireOTPSigninAttemptFactors; this does
// not authorize comparison, consumption, a session, or a recovery downgrade.
func RequireOTPSigninReservationFactors(ctx context.Context, w kernel.OTPReservationWork, owner kernel.OTPReservationContributor, user identity.UserID, expectedVersion uint64) error {
	if err := validateOTPSigninFactorRequest(ctx, user, expectedVersion); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	if err != nil {
		return err
	}
	command, err := w.NativeCommand(owner)
	if err != nil {
		return err
	}
	spec, ok := command.Feature()
	if !ok {
		return invalidAuthority()
	}
	return requireOTPSigninFactors(ctx, w.Query, b.Command, spec, owner.Descriptor(), b.Plan, user, expectedVersion)
}

// RequireOTPSigninApplyFactors locks the unchanged original known-empty MFA
// generation during native OTP signin protected admission, without exposing the
// code or general Work. The actual custody-authenticated recipient is required;
// errors abort the coordinator transaction and the lock lasts until it closes.
// Finalization must independently repeat this fence. No authority is renewed.
func RequireOTPSigninApplyFactors(ctx context.Context, w kernel.OTPApplyWork, owner kernel.OTPReservationContributor, user identity.UserID, expectedVersion uint64) error {
	if err := validateOTPSigninFactorRequest(ctx, user, expectedVersion); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	if err != nil {
		return err
	}
	spec, err := w.CommandSpec(owner)
	if err != nil {
		return err
	}
	return requireOTPSigninFactors(ctx, w.Query, b.Command, spec, owner.Descriptor(), b.Plan, user, expectedVersion)
}

// RequireOTPSigninFinalizeFactors repeats the original known-empty generation
// fence immediately before native OTP signin finalization. It accepts only the
// exact owner's live finalization handle and custody-authenticated recipient.
// Propagate errors to roll back all protected effects; the coordinator retains
// the factor lock through its sole commit. Recovery and release are unaffected.
func RequireOTPSigninFinalizeFactors(ctx context.Context, w kernel.OTPFinalizeWork, owner kernel.OTPReservationContributor, user identity.UserID, expectedVersion uint64) error {
	if err := validateOTPSigninFactorRequest(ctx, user, expectedVersion); err != nil {
		return err
	}
	b, err := w.Binding(owner)
	if err != nil {
		return err
	}
	spec, err := w.CommandSpec(owner)
	if err != nil {
		return err
	}
	return requireOTPSigninFactors(ctx, w.Query, b.Command, spec, owner.Descriptor(), b.Plan, user, expectedVersion)
}

func validateOTPSigninFactorRequest(ctx context.Context, user identity.UserID, expectedVersion uint64) error {
	if ctx == nil || expectedVersion == 0 {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return invalidAuthority()
	}
	return nil
}

func validateOTPSigninFactorScope(b identity.CommandBinding, spec identity.FeatureCommandSpec, descriptor kernel.ContributorDescriptor, plan kernel.OTPAttemptPlan, user identity.UserID) error {
	op := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.signin", SchemaID: "identity-otp-signin", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: spec.Operation.SubjectRequirement}
	if descriptor != (kernel.ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1}) || spec.Operation != op || b != spec.Binding || b.ValidateFor(op) != nil || plan.Mode != kernel.OTPConsume || b.UserID != "" && b.UserID != user {
		return invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return invalidAuthority()
	}
	return nil
}

func requireOTPSigninFactors(ctx context.Context, query factorAuthorityQuery, b identity.CommandBinding, spec identity.FeatureCommandSpec, descriptor kernel.ContributorDescriptor, plan kernel.OTPAttemptPlan, user identity.UserID, expectedVersion uint64) error {
	if err := validateOTPSigninFactorScope(b, spec, descriptor, plan, user); err != nil {
		return err
	}
	// Anonymous-flow bindings intentionally omit UserID. The native OTP owner
	// authenticates the actual recipient in its encrypted original signin custody;
	// the flow identifier is never an account whose factor row may be inferred.
	state, err := readFactorAuthorityQuery(ctx, query, b, user, expectedVersion)
	if err != nil {
		return err
	}
	return state.RequireEmailRecovery(b.TenantID, user)
}
