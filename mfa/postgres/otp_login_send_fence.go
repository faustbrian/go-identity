package mfapostgres

import (
	"context"
	"encoding/base64"
	"slices"
	"strconv"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/delivery"
	"github.com/faustbrian/go-identity/mfa"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// RequireOTPLoginSendFactor fences the native owner's original confirmed factor,
// verified recipient and live explicitly OTP-enabled continuation in its sole
// protected Work. expected/primary must originate from the actual reader/signed
// child and authenticated original preparation, never transport projections.
// Metadata is not proof: the owner separately checks original browser/password,
// directory, policy, child validity and risk. Locks follow account, factor
// authority, continuation, factor/identifier order and last until Work closes.
// No code, budget, child, session, timestamp or enrollment is mutated/renewed.
// Zero/foreign/returned ownership and changed authority deny; propagate errors.
func RequireOTPLoginSendFactor(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expected OTPFactorMetadata, primary identity.CommandID) error {
	if ctx == nil || owner == nil {
		return invalidAuthority()
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	b, feature, _, err := w.FeatureScope(owner)
	s, ok := command.Feature()
	op := identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-send", SchemaID: "mfa-otp-send", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
	if err != nil || !ok || s.Binding != b || s.Operation != op || feature.Operation != op || feature.Contributor != (kernel.ContributorDescriptor{Owner: "identity/mfa/postgres", ContractID: "identity.mfa", Version: 1}) || expected.TenantID != b.TenantID || expected.UserID == "" || expected.FactorID != b.RecordID || expected.EnrollmentVersion == 0 || expected.RowVersion == 0 || expected.FactorAuthorityVersion == 0 || expected.IdentifierVersion == 0 || expected.VerificationVersion == 0 || expected.ContinuationVersion == 0 || expected.ScopeDigest == ([32]byte{}) {
		return identity.ForbiddenError{}
	}
	if _, err := identity.ParseCommandID(string(primary)); err != nil || primary == b.CommandID {
		return identity.ForbiddenError{}
	}
	parent := ""
	for _, f := range s.Fields {
		if f.Name == "factor.parent-command" && f.Value.Kind == identity.FeatureText {
			parent = f.Value.Text
		}
	}
	if parent != string(primary) {
		return identity.ForbiddenError{}
	}
	store := completionTOTPStore(w)
	var status string
	if err := store.query(ctx, `SELECT status::text FROM identity.users WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`, []any{string(b.TenantID), string(expected.UserID)}, &status); err != nil {
		return attemptStoreError(ctx, err)
	}
	if status != "active" {
		return identity.ForbiddenError{}
	}
	var authority string
	var active int32
	if err := store.query(ctx, `SELECT version::text,active_factors FROM identity_mfa.factor_authorities WHERE tenant_id=$1 AND user_id=$2 FOR SHARE`, []any{string(b.TenantID), string(expected.UserID)}, &authority, &active); err != nil {
		return attemptStoreError(ctx, err)
	}
	if authority != strconv.FormatUint(expected.FactorAuthorityVersion, 10) || active <= 0 || active > 64 {
		return identity.ForbiddenError{}
	}
	var scope, digest, parentID []byte
	var state int16
	var version string
	var remaining int32
	if err := store.query(ctx, `SELECT CASE WHEN octet_length(original_scope)<=8192 THEN original_scope ELSE ''::bytea END,scope_digest,state,version::text,attempts_remaining,origin_command_id FROM identity_mfa.continuations WHERE tenant_id=$1 AND user_id=$2 AND continuation_id=$3 AND source_preauth_id=$4 FOR UPDATE`, []any{string(b.TenantID), string(expected.UserID), string(expected.ContinuationID), b.AnonymousFlowID}, &scope, &digest, &state, &version, &remaining, &parentID); err != nil {
		return attemptStoreError(ctx, err)
	}
	defer clear(scope)
	if len(digest) != 32 || string(digest) != string(expected.ScopeDigest[:]) || base64.RawURLEncoding.EncodeToString(parentID) != string(primary) || version != strconv.FormatUint(expected.ContinuationVersion, 10) || remaining <= 0 || (mfa.ContinuationState(state) != mfa.Pending && mfa.ContinuationState(state) != mfa.Challenged) {
		return identity.ForbiddenError{}
	}
	c, err := decodeContinuationScope(scope, expected.ScopeDigest, mfa.ContinuationState(state), expected.ContinuationVersion, uint32(remaining))
	if err != nil {
		return err
	}
	original, err := c.Bindings()
	if err != nil || original.SubjectID != identity.SubjectID(expected.UserID) || original.FactorVersion != expected.FactorAuthorityVersion || original.PolicyVersion != b.PolicyVersion || !slices.Contains(original.AllowedMethods, "otp") {
		return identity.ForbiddenError{}
	}
	channel := "email"
	if expected.Channel == delivery.ChannelSMS {
		channel = "sms"
	} else if expected.Channel != delivery.ChannelEmail {
		return identity.ForbiddenError{}
	}
	var found bool
	if err := store.query(ctx, `SELECT true FROM identity_mfa.otp_factors f JOIN identity.identifiers i ON i.tenant_id=f.tenant_id AND i.user_id=f.user_id AND i.identifier_id=f.identifier_id
WHERE f.tenant_id=$1 AND f.user_id=$2 AND f.factor_id=$3 AND f.state=2 AND f.confirmed_at IS NOT NULL
AND f.enrollment_version=$4::numeric AND f.row_version=$5::numeric AND f.identifier_id=$6 AND f.identifier_version=$7::numeric AND f.verification_version=$8::numeric AND f.channel=$9
AND i.verified AND i.verification_state=2 AND i.verified_at IS NOT NULL AND i.version=f.identifier_version AND i.verification_version=f.verification_version
AND ((f.channel='email' AND i.kind='email') OR (f.channel='sms' AND i.kind='phone')) FOR SHARE OF f,i`, []any{string(b.TenantID), string(expected.UserID), expected.FactorID, strconv.FormatUint(expected.EnrollmentVersion, 10), strconv.FormatUint(expected.RowVersion, 10), string(expected.IdentifierID), strconv.FormatUint(expected.IdentifierVersion, 10), strconv.FormatUint(expected.VerificationVersion, 10), channel}, &found); err != nil {
		return attemptStoreError(ctx, err)
	}
	if !found {
		return identity.ForbiddenError{}
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(original.IssuedAt) || !now.Before(original.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return ctx.Err()
}
