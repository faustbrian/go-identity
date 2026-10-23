package mfapostgres

import (
	"context"
	"strconv"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireOTPSessionFactor fences the original confirmed OTP enrollment, current
// verified recipient and account-wide factor epoch inside native session-revoke-
// one or explicitly selected active-OTP MFA Work. It grants no OTP comparison,
// TOTP fallback or factor-mutation authority.
// Directory, primary credential and policy must already be fenced by that owner.
// Locks follow account, factor authority, then factor/recipient and remain owned
// by the coordinator until commit/rollback. Missing, stale or unavailable state
// denies; propagate every error to abort. Historical login-child expiry is not
// session validity, and this operation changes no OTP or replay counter.
func RequireOTPSessionFactor(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, user identity.UserID, factorID string, expected OTPSessionFactorState) error {
	if ctx == nil || expected.EnrollmentVersion == 0 || expected.AuthorityVersion == 0 {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, f, _, err := w.FeatureScope(owner)
	if err != nil || !nativeOTPSessionFactorConsumer(b, f) || b.UserID != user || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(user) {
		return invalidAuthority()
	}
	if _, err := identity.ParseCommandID(factorID); err != nil {
		return invalidAuthority()
	}
	rows, err := w.Query(ctx, `SELECT user_id FROM identity.users WHERE tenant_id=$1 AND user_id=$2 AND status='active' FOR SHARE`, string(b.TenantID), string(user))
	if err != nil {
		return identity.UnavailableError{}
	}
	var current string
	err = readSessionFactorRow(rows, &current)
	rows.Close()
	if err != nil {
		return err
	}
	state, err := readFactorAuthority(ctx, w, b, user, expected.AuthorityVersion)
	if err != nil {
		return err
	}
	if state.RequireEmailRecovery(b.TenantID, user) == nil {
		return identity.ForbiddenError{}
	}
	rows, err = w.Query(ctx, `SELECT f.enrollment_version::text
FROM identity_mfa.otp_factors f
JOIN identity.identifiers i ON i.tenant_id=f.tenant_id AND i.user_id=f.user_id AND i.identifier_id=f.identifier_id
WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.factor_id=$3 AND f.state=2 AND f.confirmed_at IS NOT NULL
AND i.verified AND i.verification_state=2 AND i.verified_at IS NOT NULL
AND i.version=f.identifier_version AND i.verification_version=f.verification_version
AND ((f.channel='email' AND i.kind='email') OR (f.channel='sms' AND i.kind='phone'))
FOR UPDATE OF f FOR SHARE OF i`, string(b.TenantID), string(user), factorID)
	if err != nil {
		return identity.UnavailableError{}
	}
	err = readSessionFactorRow(rows, &current)
	rows.Close()
	if err != nil {
		return err
	}
	if current != strconv.FormatUint(expected.EnrollmentVersion, 10) {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}

func nativeOTPSessionFactorConsumer(b identity.CommandBinding, f kernel.FeatureRegistration) bool {
	sessionOwner := b.OperationID == "identity.session.revoke-one" && f.Operation.Owner == "identity/session" && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1})
	mfaOwner := b.SchemaVersion == 1 && (b.OperationID == "identity.mfa.otp-send" && b.SchemaID == "mfa-otp-step-up-send" || b.OperationID == "identity.mfa.otp-verify" && b.SchemaID == "mfa-otp-step-up" || b.OperationID == "identity.mfa.factor-update" && b.SchemaID == "mfa-factor-update") && f.Operation.Owner == "identity/mfa" && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1})
	return sessionOwner || mfaOwner
}
