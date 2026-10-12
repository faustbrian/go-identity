package mfapostgres

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math"
	"strconv"
	"time"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
	primitive "github.com/faustbrian/go-password"
)

func confirmationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.totp-verify", SchemaID: "mfa-totp-enrollment-confirm", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// The comparison scope is injective and purpose-separated from login. A code
// or matching counter never becomes authority outside the registered Work.
func enrollmentConfirmationScope(m PendingTOTPMetadata, command identity.CommandID, keyVersion uint32) ([]byte, error) {
	if keyVersion == 0 {
		return nil, invalidEnrollment()
	}
	return json.Marshal(struct {
		Profile, Tenant, User, Factor, Command string
		KeyVersion                             uint32
	}{"mfa-totp-enrollment-confirm-v1", string(m.TenantID), string(m.UserID), m.FactorID, string(command), keyVersion})
}

// activatePendingTOTP runs only in the native owner's already-admitted Work.
// Decryption belongs before locks; comparison uses primary database time here.
// The original SFA session is neither promoted nor implicitly replaced.
func activatePendingTOTP(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, c identity.Command, m PendingTOTPMetadata, rowVersion, authorityVersion uint64, encrypted []byte, secret primitive.Secret, code auth.OneTimeCode, verifier mfa.TOTPVerifier, keyVersion uint32) error {
	if ctx == nil {
		return invalidEnrollment()
	}
	if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
		return err
	}
	b, f, life, err := w.FeatureScope(owner)
	if err != nil || f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || f.Operation != confirmationOperation() || b.TenantID != m.TenantID || b.UserID != m.UserID || b.RecordID != m.FactorID || rowVersion == 0 || rowVersion == math.MaxUint64 || authorityVersion == 0 || authorityVersion == math.MaxUint64 || life != (kernel.LifecyclePlan{EventType: "factor.enrolled.v1", BeforeVersion: rowVersion, AfterVersion: rowVersion + 1}) || len(encrypted) == 0 || len(encrypted) > 4096 {
		return invalidEnrollment()
	}
	authority, err := readFactorAuthority(ctx, w, b, b.UserID, authorityVersion)
	if err != nil {
		return err
	}
	if err = authority.RequireEmailRecovery(b.TenantID, b.UserID); err != nil {
		return err
	}
	store := completionTOTPStore(w)
	var wire []byte
	var created, expires time.Time
	var algorithm, issuer string
	var digits, period, skew int16
	err = store.query(ctx, `SELECT encrypted_secret,created_at,enrollment_expires_at,algorithm,digits,period_seconds,skew_steps,issuer FROM identity_mfa.totp_factors
WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=1 AND enrollment_version=1 AND row_version=$4::numeric AND last_step IS NULL AND confirmed_at IS NULL FOR UPDATE`, []any{string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(rowVersion, 10)}, &wire, &created, &expires, &algorithm, &digits, &period, &skew, &issuer)
	defer clear(wire)
	if err != nil {
		return attemptStoreError(ctx, err)
	}
	if sha256.Sum256(wire) != sha256.Sum256(encrypted) || !created.Equal(m.CreatedAt) || !expires.Equal(m.ExpiresAt) || algorithm != m.Profile.Algorithm || uint32(digits) != m.Profile.Digits || time.Duration(period)*time.Second != m.Profile.Period || uint32(skew) != m.Profile.AllowedSkewSteps || issuer != m.Profile.Issuer {
		return identity.ForbiddenError{}
	}
	var recoveryCount int16
	err = store.query(ctx, `SELECT code_count FROM identity_mfa.recovery_sets WHERE tenant_id=$1 AND user_id=$2 AND set_id=$3 AND factor_id=$3 AND state=1 AND set_version=1 AND row_version=1 FOR UPDATE`, []any{string(b.TenantID), string(b.UserID), b.RecordID}, &recoveryCount)
	if err != nil {
		return attemptStoreError(ctx, err)
	}
	var total, unused int64
	err = store.query(ctx, `SELECT count(*),count(*) FILTER (WHERE consumed_command_id IS NULL AND consumed_purpose IS NULL AND consumed_at IS NULL) FROM identity_mfa.recovery_codes WHERE tenant_id=$1 AND set_id=$2`, []any{string(b.TenantID), b.RecordID}, &total, &unused)
	if err != nil {
		return err
	}
	if recoveryCount < 1 || recoveryCount > 64 || total != int64(recoveryCount) || unused != total {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(created) || !now.Before(expires) {
		return identity.ForbiddenError{}
	}
	scope, err := enrollmentConfirmationScope(m, b.CommandID, keyVersion)
	if err != nil {
		return err
	}
	step, err := verifier.Verify(ctx, secret, code, m.Profile, scope, now, mfa.TOTPReplayState{})
	if err != nil {
		return err
	}
	id, err := base64.RawURLEncoding.Strict().DecodeString(string(b.CommandID))
	if err != nil {
		return invalidEnrollment()
	}
	n, err := w.Exec(ctx, `UPDATE identity_mfa.totp_factors SET state=2,confirmed_at=$5,last_step=$6::numeric,row_version=row_version+1,activation_command_id=$7,activation_before_version=row_version,activation_authority_before=$8::numeric
WHERE tenant_id=$1 AND user_id=$2 AND factor_id=$3 AND state=1 AND row_version=$4::numeric AND enrollment_expires_at>clock_timestamp()`, string(b.TenantID), string(b.UserID), b.RecordID, strconv.FormatUint(rowVersion, 10), now, strconv.FormatUint(step, 10), id, strconv.FormatUint(authorityVersion, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	n, err = w.Exec(ctx, `UPDATE identity_mfa.recovery_sets SET state=2,row_version=row_version+1 WHERE tenant_id=$1 AND user_id=$2 AND set_id=$3 AND factor_id=$3 AND state=1 AND row_version=1`, string(b.TenantID), string(b.UserID), b.RecordID)
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	n, err = w.Exec(ctx, `UPDATE identity_mfa.factor_authorities SET version=version+1,active_factors=1 WHERE tenant_id=$1 AND user_id=$2 AND version=$3::numeric AND active_factors=0`, string(b.TenantID), string(b.UserID), strconv.FormatUint(authorityVersion, 10))
	if err != nil {
		return err
	}
	if n != 1 {
		return identity.ForbiddenError{}
	}
	return nil
}
