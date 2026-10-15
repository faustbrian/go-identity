package postgres

import (
	"context"
	"fmt"
	"reflect"
	"strconv"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

var _ mfapg.OTPEnrollmentConfirmationOwner = (*MFAEnrollmentIssuer)(nil)

// ValidateConfirmationKey checks the exact selected retained attempt key at
// construction. Missing/zero ownership fails closed without IO or generation.
func (s *MFAEnrollmentIssuer) ValidateConfirmationKey(version uint32) error {
	if s == nil || s.store == nil || s.store.codec == nil || version == 0 {
		return ErrInvalidConfiguration
	}
	if _, retained := s.store.codec.issuers[version]; !retained {
		return ErrInvalidConfiguration
	}
	return nil
}

// ConfirmationContributor lends the real native OTP participant for MFA's
// registry and code-free recovery. It supplies no comparison or admission.
func (s *MFAEnrollmentIssuer) ConfirmationContributor() kernel.OTPExecutionContributor {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store
}

type mfaEnrollmentConfirmation struct {
	issuer *MFAEnrollmentIssuer
	source identity.FeatureCommandSpec
	issued otp.ChallengeSpec
	owner  AttemptAuthority
}

func mfaEnrollmentConfirmationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify", SchemaID: "mfa-otp-enrollment-confirm", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// RestoreEnrollmentConfirmation restores the exact retained send without
// generation, comparison, delivery, admission, mutation or freshness renewal.
// The supplied root/input/output must be authenticated original MFA custody;
// changed parent, generation, bearer or configuration fails closed.
func (s *MFAEnrollmentIssuer) RestoreEnrollmentConfirmation(ctx context.Context, root identity.Command, inputWire []byte, generation uint64, output []byte) (mfapg.OTPEnrollmentConfirmation, error) {
	input, err := s.restoreEnrollmentInput(root, inputWire)
	if err != nil {
		return nil, err
	}
	prepared, err := s.Restore(ctx, root, input, generation, output)
	if err != nil {
		return nil, err
	}
	custody, _, err := s.store.authenticateIssuance(ctx, prepared.generated)
	if err != nil {
		return nil, err
	}
	issued, err := custody.challenge.Bindings()
	if err != nil {
		return nil, ErrInvalidCommand
	}
	return &mfaEnrollmentConfirmation{issuer: s, source: prepared.root, issued: issued, owner: custody.authority}, nil
}

func (p *mfaEnrollmentConfirmation) Contributor() kernel.OTPExecutionContributor {
	if p == nil || p.issuer == nil || p.issuer.store == nil {
		return nil
	}
	return p.issuer.store
}

func (p *mfaEnrollmentConfirmation) RestorePrepared(ctx context.Context, root identity.Command, code auth.OneTimeCode, retained identity.FeatureCommandSpec) (identity.Command, kernel.OTPAttemptPlan, error) {
	bad := func() (identity.Command, kernel.OTPAttemptPlan, error) {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	if ctx == nil || p == nil || p.issuer == nil || p.issuer.store == nil {
		return bad()
	}
	if err := ctx.Err(); err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, err
	}
	base, ok := root.Feature()
	bearer, token := root.SessionToken()
	static := retained
	static.Fields = nil
	var version uint32
	for _, field := range retained.Fields {
		if !otpField(field.Name) {
			static.Fields = append(static.Fields, field)
		} else if field.Name == "otp.digest-key-version" && field.Value.Kind == identity.FeatureUint64 && field.Value.Uint64 <= uint64(^uint32(0)) {
			version = uint32(field.Value.Uint64)
		}
	}
	if !ok || !token || !reflect.DeepEqual(base, static) || base.Operation != mfaEnrollmentConfirmationOperation() || base.Binding.RecordID != p.source.Binding.RecordID || base.Binding.TenantID != p.source.Binding.TenantID || base.Binding.UserID != p.source.Binding.UserID || base.Binding.CommandID == p.source.Binding.CommandID {
		return bad()
	}
	custody, err := p.issuer.store.codec.restoreCustody(retained)
	if err != nil || custody.authority == nil || !reflect.DeepEqual(*custody.authority, p.owner) {
		return bad()
	}
	plan, err := p.issuer.store.codec.recordPlan(custody.record, version)
	if err != nil || plan.Mode != kernel.OTPConsume || plan.ChallengeID != string(p.source.Binding.CommandID) {
		return bad()
	}
	scope, err := p.issued.Continuation.DigestScope()
	if err != nil {
		return bad()
	}
	digest, err := p.issuer.store.codec.verifier.ScopeDigest(scope, p.issued.Digest.KeyVersion)
	if err != nil || plan.DigestKeyVersion != p.issued.Digest.KeyVersion || plan.ScopeDigest != digest.Value {
		return bad()
	}
	command, err := identity.NewFeatureOneTimeCodeSessionCommand(retained, code, bearer)
	if err != nil || p.issuer.store.ValidateOTPAttemptCommand(command, plan) != nil {
		return bad()
	}
	if err := ctx.Err(); err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, err
	}
	return command, plan, nil
}

func (p *mfaEnrollmentConfirmation) Prepare(ctx context.Context, pool *database.Pool, root identity.Command, code auth.OneTimeCode, keyVersion uint32) (identity.Command, kernel.OTPAttemptPlan, error) {
	if ctx == nil || p == nil || p.issuer == nil || pool == nil || pool.Raw() == nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, p.issuer.store.codec.maximumDuration)
	defer stop()
	scope, err := p.issued.Continuation.DigestScope()
	if err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	digest, err := p.issuer.store.codec.verifier.ScopeDigest(scope, p.issued.Digest.KeyVersion)
	if err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	var text string
	schema := pgx.Identifier{p.issuer.store.schema}.Sanitize()
	err = pool.Raw().QueryRow(ctx, `SELECT version::text FROM `+schema+`.challenges WHERE tenant_id=$1 AND challenge_id=$2 AND digest_key_version=$3 AND scope_digest=$4`, string(p.source.Binding.TenantID), string(p.source.Binding.CommandID), int64(p.issued.Digest.KeyVersion), digest.Value[:]).Scan(&text)
	if err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, custodyFailure(ctx)
	}
	version, err := strconv.ParseUint(text, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != text {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrUnavailable
	}
	return p.prepare(ctx, root, code, version, keyVersion)
}

func (p *mfaEnrollmentConfirmation) prepare(ctx context.Context, root identity.Command, code auth.OneTimeCode, version uint64, keyVersion uint32) (identity.Command, kernel.OTPAttemptPlan, error) {
	bad := func(err error) (identity.Command, kernel.OTPAttemptPlan, error) {
		return identity.Command{}, kernel.OTPAttemptPlan{}, err
	}
	if ctx == nil || p == nil || p.issuer == nil || p.issuer.store == nil || version == 0 {
		return bad(ErrInvalidCommand)
	}
	spec, ok := root.Feature()
	bearer, token := root.SessionToken()
	_, submitted := root.OneTimeCode()
	b, source := spec.Binding, p.source.Binding
	if !ok || !token || submitted || spec.Operation != mfaEnrollmentConfirmationOperation() || b.CommandID == source.CommandID || b.TenantID != source.TenantID || b.UserID != source.UserID || b.ActorID != source.ActorID || b.ActorKind != source.ActorKind || b.RecordID != source.RecordID || b.PolicyID != source.PolicyID || b.PolicyVersion != source.PolicyVersion || b.LinkMode != source.LinkMode {
		return bad(ErrInvalidCommand)
	}
	issuer, retained := p.issuer.store.codec.issuers[keyVersion]
	if !retained {
		return bad(ErrInvalidCommand)
	}
	attempt, err := issuer.PrepareForCommand(ctx, b, spec.Operation, p.issued.Continuation, otp.AttemptModeConsume, version, code)
	if err != nil {
		return bad(err)
	}
	return p.issuer.store.codec.MapSessionWithAuthority(ctx, attempt, p.issued.Digest.KeyVersion, spec, bearer, p.owner)
}

func (*mfaEnrollmentConfirmation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.MFAEnrollmentConfirmation(redacted)"))
}
func (*mfaEnrollmentConfirmation) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
func (*mfaEnrollmentConfirmation) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
