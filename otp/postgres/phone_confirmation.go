package postgres

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
	"github.com/jackc/pgx/v5"
)

// PhoneEnrollmentConfirmation retains the original encrypted send's exact
// continuation, not authority to verify a phone. The native phone owner must
// authenticate committed preparation provenance before restoring it, admit its
// actual target/factors/risk/CSRF and execute the returned consuming participant
// in the sole coordinator Work. Zero denies; immutable copies support concurrent
// reads. No transaction, journal, sender or background resource is owned.
type PhoneEnrollmentConfirmation struct {
	read func() *phoneEnrollmentConfirmation
}

type phoneEnrollmentConfirmation struct {
	store       *Contributor
	source      identity.FeatureCommandSpec
	candidate   kernel.PhoneEnrollmentIntent
	issued      otp.ChallengeSpec
	original    AttemptAuthority
	factors     uint64
	replacement *kernel.PhoneChangeIntent
}

func (p *phoneEnrollmentConfirmation) operation() identity.FeatureOperation {
	if p != nil && p.replacement != nil {
		return phoneChangeConfirmationOperation()
	}
	return phoneConfirmationOperation()
}

func phoneConfirmationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.verify",
		SchemaID: "identity.phone.verify.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func (c PhoneEnrollmentConfirmation) state() *phoneEnrollmentConfirmation {
	if c.read == nil {
		return nil
	}
	return c.read()
}

// RestoreEnrollmentConfirmation authenticates the unchanged original encrypted
// SMS, candidate, session possession, configuration and generation. The supplied
// root/input/output must come from the native owner's committed preparation,
// never caller-provided fields. No IO, code comparison, entropy or freshness
// renewal occurs; mutable current state is not adopted as original evidence.
func (s *PhoneEnrollmentIssuer) RestoreEnrollmentConfirmation(ctx context.Context, root identity.Command, input PhoneEnrollmentSendInput, generation uint64, output []byte) (PhoneEnrollmentConfirmation, error) {
	if s.state() == nil || s.state().replacement {
		return PhoneEnrollmentConfirmation{}, ErrInvalidCommand
	}
	prepared, err := s.Restore(ctx, root, input, generation, output)
	if err != nil {
		return PhoneEnrollmentConfirmation{}, err
	}
	retained := prepared.state()
	storeOwner := s.state().store
	custody, _, err := storeOwner.authenticateIssuance(ctx, retained.generated)
	if err != nil || custody.recipient != nil {
		return PhoneEnrollmentConfirmation{}, ErrInvalidCommand
	}
	issued, err := custody.challenge.Bindings()
	if err != nil {
		return PhoneEnrollmentConfirmation{}, ErrInvalidCommand
	}
	var factors uint64
	for _, f := range retained.root.Fields {
		if f.Name == "phone.factor-version" {
			if factors != 0 || f.Value.Kind != identity.FeatureUint64 || f.Value.Uint64 == 0 {
				return PhoneEnrollmentConfirmation{}, ErrInvalidCommand
			}
			factors = f.Value.Uint64
		} else if strings.HasPrefix(f.Name, "phone.factor-") {
			return PhoneEnrollmentConfirmation{}, ErrInvalidCommand
		}
	}
	if factors == 0 {
		return PhoneEnrollmentConfirmation{}, ErrInvalidCommand
	}
	p := &phoneEnrollmentConfirmation{source: retained.root, candidate: input.state().Candidate, issued: issued, original: custody.authority, factors: factors}
	if _, err := p.intent(); err != nil {
		return PhoneEnrollmentConfirmation{}, err
	}
	store := *storeOwner
	store.send, store.phoneConfirmation = nil, p
	p.store = &store
	return PhoneEnrollmentConfirmation{read: func() *phoneEnrollmentConfirmation { return p }}, nil
}

func (p *phoneEnrollmentConfirmation) intent() (kernel.PhoneVerificationIntent, error) {
	if p == nil || p.factors == 0 || p.candidate.Change.ExpectedUserVersion >= ^uint64(0)-1 ||
		p.candidate.Change.ExpectedAuthorityVersion >= ^uint64(0)-1 ||
		p.original.IdentifierAuthorityVersion != p.candidate.Change.ExpectedAuthorityVersion {
		return kernel.PhoneVerificationIntent{}, ErrInvalidCommand
	}
	c := p.candidate.Change
	i := kernel.PhoneVerificationIntent{Change: identity.IdentifierChange{TenantID: c.TenantID, UserID: c.UserID, ID: c.ID,
		Action: identity.IdentifierVerify, ExpectedUserVersion: c.ExpectedUserVersion + 1, ExpectedAuthorityVersion: c.ExpectedAuthorityVersion + 1,
		ExpectedIdentifierVersion: 1, ExpectedVerificationVersion: 1}, CanonicalNumber: c.CanonicalValue,
		NormalizationProfile: c.NormalizationProfile, NormalizationVersion: c.NormalizationVersion, EnrollmentCommandID: p.source.Binding.CommandID}
	if _, err := kernel.PhoneVerificationFields(i); err != nil {
		return kernel.PhoneVerificationIntent{}, ErrInvalidCommand
	}
	return i, nil
}

// Intent derives only the authenticated enrollment's exact pending successor.
// The result is sensitive input, not current authority or verified possession.
func (c PhoneEnrollmentConfirmation) Intent() (kernel.PhoneVerificationIntent, error) {
	return c.state().intent()
}

// FactorVersion returns the original known-empty MFA generation to fence through
// its actual owner. It is not fresh observation or permission to bypass factors.
func (c PhoneEnrollmentConfirmation) FactorVersion() (uint64, error) {
	p := c.state()
	if p == nil || p.factors == 0 {
		return 0, ErrInvalidCommand
	}
	return p.factors, nil
}

// Lifetime returns the authenticated original challenge's exact issued duration,
// not its remaining time or current admission. Restoration cannot renew it.
// Zero or invalid retained metadata returns ErrInvalidCommand without values.
func (c PhoneEnrollmentConfirmation) Lifetime() (time.Duration, error) {
	p := c.state()
	if p == nil || !nativeTime(p.issued.IssuedAt) || !nativeTime(p.issued.ExpiresAt) {
		return 0, ErrInvalidCommand
	}
	profile, _, err := p.issued.Policy.Bindings()
	lifetime := p.issued.ExpiresAt.Sub(p.issued.IssuedAt)
	// Challenge issuance permits an earlier expiry, never an extension beyond
	// its frozen profile TTL (otp.NewChallenge); preserve that exact interval.
	if err != nil || lifetime <= 0 || lifetime > 24*time.Hour || lifetime > profile.TTL || lifetime%time.Microsecond != 0 {
		return 0, ErrInvalidCommand
	}
	return lifetime, nil
}

func (p *phoneEnrollmentConfirmation) fields() ([]identity.FeatureField, error) {
	if p != nil && p.replacement != nil {
		fields, err := kernel.PhoneChangeFields(*p.replacement)
		if err != nil || p.factors == 0 {
			return nil, ErrInvalidCommand
		}
		return append(fields, identity.FeatureField{Name: "phone.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.factors}}), nil
	}
	i, err := p.intent()
	if err != nil {
		return nil, err
	}
	f, err := kernel.PhoneVerificationFields(i)
	if err != nil {
		return nil, err
	}
	return append(f, identity.FeatureField{Name: "phone.factor-version", Value: identity.FeatureValue{Kind: identity.FeatureUint64, Uint64: p.factors}}), nil
}

// Fields returns owned frozen confirmation fields before native fingerprinting.
// This performs no IO, comparison or admission; retain exact values on retry.
func (c PhoneEnrollmentConfirmation) Fields() ([]identity.FeatureField, error) {
	return c.state().fields()
}

// Contributor returns this immutable continuation's exact consuming OTP owner
// for native registry selection. It cannot issue a new code or renew authority.
func (c PhoneEnrollmentConfirmation) Contributor() kernel.OTPExecutionContributor {
	p := c.state()
	if p == nil {
		return nil
	}
	return p.store
}

func (p *phoneEnrollmentConfirmation) matches(spec identity.FeatureCommandSpec) error {
	if p == nil || spec.Operation != p.operation() {
		return ErrInvalidCommand
	}
	b, source := spec.Binding, p.source.Binding
	target := source.RecordID
	if p.replacement != nil {
		target = string(p.replacement.Change.ID)
	}
	if b.ValidateFor(spec.Operation) != nil || b.CommandID == source.CommandID || b.TenantID != source.TenantID || b.UserID != source.UserID ||
		b.ActorID != source.ActorID || b.ActorKind != source.ActorKind || b.RecordID != target ||
		b.PolicyID != source.PolicyID || b.PolicyVersion != source.PolicyVersion || b.LinkMode != source.LinkMode {
		return ErrInvalidCommand
	}
	expected, err := p.fields()
	if err != nil {
		return err
	}
	static := make([]identity.FeatureField, 0, len(expected))
	for _, f := range spec.Fields {
		// Replacement has its own fresh action-primary proof, independent of
		// the send's proof. That native owner validates these additional fields;
		// OTP authenticates the whole command envelope but owns neither the
		// password proof nor its source-session projection. Enrollment keeps
		// its existing exact no-additional-fields grammar.
		if p.replacement != nil && (f.Name == "phone.profile" || strings.HasPrefix(f.Name, "source-session.") || strings.HasPrefix(f.Name, "password.action-primary.")) {
			continue
		}
		if p.replacement != nil && (f.Name == "counter.network" || f.Name == "counter.session" || f.Name == "counter.prepared-at" || f.Name == "counter.key-versions") {
			// These four fields have the registered command-counter owner. Its
			// complete projection/plan checks remain mandatory in native Work;
			// do not grant arbitrary counter.* extensions OTP admission.
			continue
		}
		if !otpField(f.Name) {
			static = append(static, f)
		}
	}
	// Command construction canonicalizes field order. Compare by exact name and
	// value rather than relying on the order supplied by the native owner.
	if len(static) != len(expected) {
		return ErrInvalidCommand
	}
	for _, want := range expected {
		matched := false
		for _, got := range static {
			if got.Name == want.Name && reflect.DeepEqual(got.Value, want.Value) {
				matched = true
				break
			}
		}
		if !matched {
			return ErrInvalidCommand
		}
	}
	return nil
}

func (p *phoneEnrollmentConfirmation) executionAuthority(spec identity.FeatureCommandSpec, original AttemptAuthority) (AttemptAuthority, error) {
	if err := p.matches(spec); err != nil || original != p.original {
		return AttemptAuthority{}, ErrInvalidCommand
	}
	if p.replacement != nil {
		if p.replacement.Change.ExpectedAuthorityVersion != original.IdentifierAuthorityVersion {
			return AttemptAuthority{}, ErrInvalidCommand
		}
		// Sending replacement SMS writes no identifier. Only the kernel's
		// eventual protected replacement may derive the +1 final expectation.
		return original, nil
	}
	i, err := p.intent()
	if err != nil {
		return AttemptAuthority{}, err
	}
	// Original session/OTP custody stays unchanged. This separate expectation
	// admits only the one identifier increment caused by committed enrollment.
	original.IdentifierAuthorityVersion = i.Change.ExpectedAuthorityVersion
	return original, nil
}

func (p *Contributor) executionAuthority(spec identity.FeatureCommandSpec, original AttemptAuthority) (AttemptAuthority, error) {
	if spec.Operation == phoneConfirmationOperation() || spec.Operation == phoneChangeConfirmationOperation() {
		if p == nil || p.phoneConfirmation == nil {
			return AttemptAuthority{}, ErrInvalidCommand
		}
		return p.phoneConfirmation.executionAuthority(spec, original)
	}
	if p != nil && p.phoneConfirmation != nil {
		return AttemptAuthority{}, ErrInvalidCommand
	}
	return original, nil
}

// Prepare reads the exact existing challenge's current version before one new
// server-issued logical submission. The native service first authenticates
// committed source/current authority and never uses this for ambiguity recovery.
// Pool is borrowed; bounded IO creates no private transaction or journal.
func (c PhoneEnrollmentConfirmation) Prepare(ctx context.Context, pool *database.Pool, root identity.Command, code auth.OneTimeCode, keyVersion uint32) (identity.Command, kernel.OTPAttemptPlan, error) {
	p := c.state()
	if ctx == nil || p == nil || p.store == nil || pool == nil || pool.Raw() == nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	ctx, stop := context.WithTimeout(ctx, p.store.codec.maximumDuration)
	defer stop()
	scope, err := p.issued.Continuation.DigestScope()
	if err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	digest, err := p.store.codec.verifier.ScopeDigest(scope, p.issued.Digest.KeyVersion)
	if err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	var encoded string
	err = pool.Raw().QueryRow(ctx, `SELECT version::text FROM `+pgx.Identifier{p.store.schema}.Sanitize()+`.challenges WHERE tenant_id=$1 AND challenge_id=$2 AND digest_key_version=$3 AND scope_digest=$4`,
		string(p.source.Binding.TenantID), string(p.source.Binding.CommandID), int64(p.issued.Digest.KeyVersion), digest.Value[:]).Scan(&encoded)
	if err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, custodyFailure(ctx)
	}
	version, err := strconv.ParseUint(encoded, 10, 64)
	if err != nil || version == 0 || strconv.FormatUint(version, 10) != encoded {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrUnavailable
	}
	return c.prepare(ctx, root, code, version, keyVersion)
}

func (c PhoneEnrollmentConfirmation) prepare(ctx context.Context, root identity.Command, code auth.OneTimeCode, version uint64, keyVersion uint32) (identity.Command, kernel.OTPAttemptPlan, error) {
	p := c.state()
	if ctx == nil || p == nil || p.store == nil || version == 0 {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	spec, ok := root.Feature()
	bearer, token := root.SessionToken()
	_, submitted := root.OneTimeCode()
	if !ok || !token || submitted || p.matches(spec) != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	issuer, retained := p.store.codec.issuers[keyVersion]
	if !retained {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	attempt, err := issuer.PrepareForCommand(ctx, spec.Binding, spec.Operation, p.issued.Continuation, otp.AttemptModeConsume, version, code)
	if err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, err
	}
	return p.store.codec.MapSessionWithAuthority(ctx, attempt, p.issued.Digest.KeyVersion, spec, bearer, p.original)
}

// Admit checks original directory/credential/authorization and actual stored
// session/family/time in this exact phone owner's synchronous invocation.
// First lock the original target through RequirePhoneVerificationTarget in input
// admission. Native factor/risk and selected CSRF checks remain mandatory.
func (c PhoneEnrollmentConfirmation) Admit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	return c.require(ctx, w, owner, command, false)
}

// Check repeats admission for the exact post-verification successor in the
// native final callback. It does not extend original lifetime or infer success;
// the kernel separately requires its own applied mutation and OTP finalization.
func (c PhoneEnrollmentConfirmation) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	return c.require(ctx, w, owner, command, true)
}

func (c PhoneEnrollmentConfirmation) require(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, final bool) error {
	p := c.state()
	if ctx == nil || p == nil || p.store == nil {
		return ErrInvalidCommand
	}
	b, f, _, err := w.FeatureScope(owner)
	spec, ok := command.Feature()
	if err != nil || !ok || spec.Binding != b || f.Operation != p.operation() ||
		f.Contributor != (kernel.ContributorDescriptor{Owner: "identity/phone/postgres", ContractID: "identity.phone", Version: 1}) {
		return ErrInvalidCommand
	}
	custody, err := p.store.codec.restoreCustody(spec)
	if err != nil || custody.authority == nil {
		return ErrInvalidCommand
	}
	a, err := p.executionAuthority(spec, *custody.authority)
	if err != nil {
		return err
	}
	if final {
		a.IdentifierAuthorityVersion++
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, a.Directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, owner, credentialAdmission(a)); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, owner, a.UserAuthorization); err != nil {
		return err
	}
	var version uint32
	for _, field := range spec.Fields {
		if field.Name == "otp.digest-key-version" && field.Value.Kind == identity.FeatureUint64 && field.Value.Uint64 <= uint64(^uint32(0)) {
			version = uint32(field.Value.Uint64)
		}
	}
	plan, err := p.store.codec.recordPlan(custody.record, version)
	if err != nil {
		return err
	}
	bearer, present := command.SessionToken()
	if !present {
		return ErrInvalidCommand
	}
	flow, err := p.store.authenticateFlowSpec(ctx, spec, plan, bearer)
	if err != nil {
		return err
	}
	if err := requireNativeFlow(ctx, w, p.store, flow, nil); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	return p.store.flowTime(flow, now)
}

// Format hides original encrypted and session/number correlation.
func (PhoneEnrollmentConfirmation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhoneEnrollmentConfirmation(redacted)"))
}

// MarshalJSON denies implicit continuation disclosure.
func (PhoneEnrollmentConfirmation) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText denies implicit continuation disclosure.
func (PhoneEnrollmentConfirmation) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
