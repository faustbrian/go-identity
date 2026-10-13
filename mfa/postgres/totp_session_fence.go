package mfapostgres

import (
	"context"
	"strconv"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireTOTPSessionFactor fences the original confirmed TOTP enrollment and
// account-wide factor generation inside exact native session-revoke-one or
// authenticated MFA-action Work. Directory, primary and policy must already be fenced.
// Locks are account, factor authority, then selected factor; the coordinator
// owns their lifetime and rollback. No secret, child or replay counter is read
// or changed, and historical continuation expiry is not session validity.
// Missing, changed or unavailable authority denies; return any error to abort.
func RequireTOTPSessionFactor(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, user identity.UserID, factorID string, expected TOTPSessionFactorState) error {
	if ctx == nil || expected.EnrollmentVersion == 0 || expected.AuthorityVersion == 0 {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, f, _, err := w.FeatureScope(owner)
	sessionOwner := b.OperationID == "identity.session.revoke-one" && f.Operation.Owner == "identity/session" && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/session/postgres", ContractID: "identity.session.store", Version: 1})
	mfaOwner := b.SchemaVersion == 1 && (b.OperationID == "identity.mfa.totp-verify" && b.SchemaID == "mfa-totp-step-up" || b.OperationID == "identity.mfa.recovery-regenerate" && b.SchemaID == "mfa-recovery-regenerate" || b.OperationID == "identity.mfa.factor-update" && b.SchemaID == "mfa-factor-update") && f.Operation.Owner == "identity/mfa" && f.Contributor == (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1})
	if err != nil || b.UserID != user || b.ActorKind != authorization.SubjectUser || string(b.ActorID) != string(user) || !sessionOwner && !mfaOwner {
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
	rows, err = w.Query(ctx, `SELECT enrollment_version::text FROM identity_mfa.totp_factors WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=2 AND confirmed_at IS NOT NULL AND encrypted_secret IS NOT NULL FOR UPDATE`, string(b.TenantID), string(user), factorID)
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

func readSessionFactorRow(rows *kernel.WorkRows, value *string) error {
	if !rows.Next() {
		if rows.Err() != nil {
			return identity.UnavailableError{}
		}
		return identity.ForbiddenError{}
	}
	if rows.Scan(value) != nil || rows.Next() || rows.Err() != nil {
		return identity.UnavailableError{}
	}
	return nil
}
