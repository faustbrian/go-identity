package mfapostgres

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// ReadEmailOTPFactors reads the current native known-empty generation for
// preparation of an authenticated user's email-verification OTP target. It is
// preliminary metadata, not an authentication proof, cached lease or permission
// to issue/consume. The same generation MUST be fenced by RequireEmailOTPFactors
// in issuance and completion Work. Missing/enrolled/corrupt state denies; this
// never initializes rows or falls back to another recovery path. The pool is
// borrowed; no transaction, retries or goroutines are owned. MaximumDuration is
// explicit, 1ms..5s; earlier cancellation wins and provider errors are redacted.
func ReadEmailOTPFactors(ctx context.Context, pool *database.Pool, tenant identity.TenantID, user identity.UserID, maximumDuration time.Duration) (mfa.FactorAuthority, error) {
	if ctx == nil || pool == nil || pool.Raw() == nil || maximumDuration < time.Millisecond || maximumDuration > 5*time.Second {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(tenant)); err != nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if _, err := identity.ParseIdentifierID(string(user)); err != nil {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	ctx, stop := context.WithTimeout(ctx, maximumDuration)
	defer stop()
	var version string
	var active int32
	err := pool.Raw().QueryRow(ctx, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2`, string(tenant), string(user)).Scan(&version, &active)
	if ctx.Err() != nil {
		return mfa.FactorAuthority{}, ctx.Err()
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return mfa.FactorAuthority{}, identity.ForbiddenError{}
	}
	if err != nil || active < 0 || active > 64 {
		return mfa.FactorAuthority{}, identity.UnavailableError{}
	}
	v, err := strconv.ParseUint(version, 10, 64)
	if err != nil || strconv.FormatUint(v, 10) != version {
		return mfa.FactorAuthority{}, identity.UnavailableError{}
	}
	state, err := mfa.NewFactorAuthority(mfa.AuthorityRecord{TenantID: tenant, UserID: user, Version: v, ActiveFactors: uint32(active)})
	if err != nil {
		return mfa.FactorAuthority{}, identity.UnavailableError{}
	}
	if err := state.RequireEmailRecovery(tenant, user); err != nil {
		return mfa.FactorAuthority{}, err
	}
	return state, nil
}

// RequireEmailOTPFactors fences the original known-empty factor generation for
// the exact registered authenticated-session OTP sender, native email-verify
// or email-change-confirm owner. It is valid in preparation, Apply and final
// checks. The factor lock
// remains held until the sole coordinator Work closes. It grants no session,
// code, address or mutation authority and never renews original validity.
func RequireEmailOTPFactors(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expectedVersion uint64) (mfa.FactorAuthority, error) {
	if ctx == nil || owner == nil || expectedVersion == 0 {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return mfa.FactorAuthority{}, err
	}
	s, ok := command.Feature()
	b, f, _, err := w.FeatureScope(owner)
	if err != nil || !ok || s.Binding != b || s.Operation != f.Operation || b.AnonymousFlowID != "" || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(b.UserID) {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	send := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.send", SchemaID: "identity-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	verify := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.email-verify", SchemaID: "identity.otp.email-verify.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	change := identity.FeatureOperation{Owner: "identity/otp", OperationID: "identity.otp.email-change-confirm", SchemaID: "identity.otp.email-change-confirm.managed-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
	valid := f.Operation == send && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1})
	valid = valid || f.Operation == verify && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1})
	valid = valid || f.Operation == change && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/otp/postgres", ContractID: "identity.otp.store", Version: 1})
	if !valid {
		return mfa.FactorAuthority{}, invalidAuthority()
	}
	return readKnownEmptyFactors(ctx, w, b, b.UserID, expectedVersion)
}
