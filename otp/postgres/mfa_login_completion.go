package postgres

import (
	"context"
	"fmt"
	"reflect"
	"strconv"

	auth "github.com/faustbrian/go-authentication"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

func mfaLoginCompletionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/mfa", OperationID: "identity.mfa.otp-verify", SchemaID: "mfa-otp-verify", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordOmitted, SubjectRequirement: identity.FeatureSubjectAnonymousFlow}
}

// MFALoginCompletion retains the actual original issued OTP at its native
// owner. It grants no comparison, allowance, child consumption or session.
// The MFA service must restore exact committed send custody, admit current
// original password/browser/child/factor/recipient/risk and enlist Contributor
// in its sole coordinator. Copies share immutable state and own no resources.
type MFALoginCompletion struct{ state func() *mfaLoginCompletion }
type mfaLoginCompletion struct {
	issuer *MFALoginIssuer
	source identity.FeatureCommandSpec
	issued otp.ChallengeSpec
	owner  AttemptAuthority
}

// RestoreLoginCompletion authenticates existing input/output and original
// generation without IO, generation, comparison or freshness renewal. The MFA
// owner must authenticate its existing encrypted preparation first. Another
// command/browser/configuration cannot adopt the original challenge.
func (s *MFALoginIssuer) RestoreLoginCompletion(ctx context.Context, root identity.Command, input []byte, generation uint64, output []byte) (MFALoginCompletion, error) {
	prepared, err := s.RestoreLoginSend(ctx, root, input, generation, output)
	if err != nil {
		return MFALoginCompletion{}, err
	}
	custody, _, err := s.store.authenticateIssuance(ctx, prepared.generated)
	if err != nil {
		return MFALoginCompletion{}, err
	}
	issued, err := custody.challenge.Bindings()
	if err != nil {
		return MFALoginCompletion{}, ErrInvalidCommand
	}
	p := &mfaLoginCompletion{issuer: s, source: prepared.root, issued: issued, owner: custody.authority}
	return MFALoginCompletion{state: func() *mfaLoginCompletion { return p }}, nil
}

// Contributor returns the actual native OTP reservation/check/finalize/recovery
// owner, not a comparison callback or user-written store. Zero returns nil.
func (c MFALoginCompletion) Contributor() kernel.OTPExecutionContributor {
	if c.state == nil {
		return nil
	}
	return c.state().issuer.store
}

// Prepare reads the exact original challenge version and maps one server-owned
// consuming attempt with borrowed submitted code/browser. It performs no code
// comparison, debit, reservation or mutation. Root must be an unchanged native
// anonymous OTP-completion command without an existing code; original user,
// child and recipient come only from the restored send. Pool remains borrowed;
// retained attempt keys and bounded primary IO are mandatory.
func (c MFALoginCompletion) Prepare(ctx context.Context, pool *database.Pool, root identity.Command, code auth.OneTimeCode, keyVersion uint32) (identity.Command, kernel.OTPAttemptPlan, error) {
	if ctx == nil || c.state == nil || pool == nil || pool.Raw() == nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	p := c.state()
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
	err = pool.Raw().QueryRow(ctx, `SELECT version::text FROM `+pgx.Identifier{p.issuer.store.schema}.Sanitize()+`.challenges WHERE tenant_id=$1 AND challenge_id=$2 AND digest_key_version=$3 AND scope_digest=$4 AND issue_command_purpose='identity.mfa.otp-send'`, string(p.source.Binding.TenantID), string(p.source.Binding.CommandID), int64(p.issued.Digest.KeyVersion), digest.Value[:]).Scan(&text)
	if err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, custodyFailure(ctx)
	}
	version, err := strconv.ParseUint(text, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != text {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrUnavailable
	}
	return c.prepare(ctx, root, code, version, keyVersion)
}

func (c MFALoginCompletion) prepare(ctx context.Context, root identity.Command, code auth.OneTimeCode, version uint64, keyVersion uint32) (identity.Command, kernel.OTPAttemptPlan, error) {
	bad := func(err error) (identity.Command, kernel.OTPAttemptPlan, error) {
		return identity.Command{}, kernel.OTPAttemptPlan{}, err
	}
	if ctx == nil || c.state == nil || version == 0 {
		return bad(ErrInvalidCommand)
	}
	if err := ctx.Err(); err != nil {
		return bad(err)
	}
	p := c.state()
	s, ok := root.Feature()
	bearer, cookie := root.PreAuthCookie()
	_, submitted := root.OneTimeCode()
	b, source := s.Binding, p.source.Binding
	if !ok || !cookie || submitted || s.Operation != mfaLoginCompletionOperation() || b.CommandID == source.CommandID || b.TenantID != source.TenantID || b.UserID != "" || b.AnonymousFlowID != source.AnonymousFlowID || b.ActorID != source.ActorID || b.ActorKind != source.ActorKind || b.PolicyID != source.PolicyID || b.PolicyVersion != source.PolicyVersion || b.LinkMode != source.LinkMode {
		return bad(ErrInvalidCommand)
	}
	issuer, retained := p.issuer.store.codec.issuers[keyVersion]
	if !retained {
		return bad(ErrInvalidCommand)
	}
	attempt, err := issuer.PrepareForCommand(ctx, b, s.Operation, p.issued.Continuation, otp.AttemptModeConsume, version, code)
	if err != nil {
		return bad(err)
	}
	return p.issuer.store.codec.MapPreAuthWithAuthority(ctx, attempt, p.issued.Digest.KeyVersion, s, bearer, p.owner)
}

// RestorePrepared authenticates original code-free mapped metadata, conserving
// its attempt/version and matching submitted code and browser independently.
// It performs no IO, comparison, debit, remapping or renewal. The MFA owner
// must authenticate retained metadata before calling; changed roots/scopes deny.
func (c MFALoginCompletion) RestorePrepared(ctx context.Context, root identity.Command, code auth.OneTimeCode, retained identity.FeatureCommandSpec) (identity.Command, kernel.OTPAttemptPlan, error) {
	bad := func() (identity.Command, kernel.OTPAttemptPlan, error) {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	if ctx == nil || c.state == nil {
		return bad()
	}
	if err := ctx.Err(); err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, err
	}
	p := c.state()
	base, ok := root.Feature()
	bearer, cookie := root.PreAuthCookie()
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
	if !ok || !cookie || !reflect.DeepEqual(base, static) || base.Operation != mfaLoginCompletionOperation() || base.Binding.TenantID != p.source.Binding.TenantID || base.Binding.AnonymousFlowID != p.source.Binding.AnonymousFlowID || base.Binding.ActorID != p.source.Binding.ActorID || base.Binding.ActorKind != p.source.Binding.ActorKind || base.Binding.CommandID == p.source.Binding.CommandID {
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
	command, err := identity.NewFeatureOneTimeCodePreAuthCommand(retained, code, bearer)
	if err != nil || p.issuer.store.ValidateOTPAttemptCommand(command, plan) != nil {
		return bad()
	}
	return command, plan, ctx.Err()
}

// Format redacts original challenge and native custody.
func (MFALoginCompletion) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.MFALoginCompletion(redacted)"))
}

// MarshalJSON denies implicit custody export.
func (MFALoginCompletion) MarshalJSON() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }

// MarshalText denies implicit textual custody export.
func (MFALoginCompletion) MarshalText() ([]byte, error) { return nil, otp.ErrSensitiveSerialization }
