package postgres

import (
	"context"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	kernel "github.com/faustbrian/go-identity/postgres"
	database "github.com/faustbrian/go-postgres"
)

// PhoneChangeConfirmation retains the exact committed new-number send's
// consuming continuation. It neither authorizes replacement nor validates its
// separate fresh action proof. The native owner must admit the original old
// target, fresh update proof, current factors/recovery/risk/session and CSRF
// before metering, then consume OTP and all required effects in one Work.
// Calls are concurrent-safe, immutable and bounded; no resources are owned.
type PhoneChangeConfirmation struct {
	read func() *phoneEnrollmentConfirmation
}

func (c PhoneChangeConfirmation) enrollment() PhoneEnrollmentConfirmation {
	return PhoneEnrollmentConfirmation{read: c.read}
}

func phoneChangeConfirmationOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/phone", OperationID: "identity.phone.update",
		SchemaID: "identity.phone.update.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

// RestoreChangeConfirmation authenticates the original native preparation's
// unchanged root/input/generation/output. Callers must obtain those from the
// committed native owner, never naked request fields. It performs no IO,
// comparison, entropy or freshness renewal. Sending has advanced no directory
// epoch: confirmation still requires the exact original verified predecessor.
func (s *PhoneChangeIssuer) RestoreChangeConfirmation(ctx context.Context, root identity.Command, input PhoneChangeSendInput, generation uint64, output []byte) (PhoneChangeConfirmation, error) {
	prepared, err := s.Restore(ctx, root, input, generation, output)
	if err != nil {
		return PhoneChangeConfirmation{}, err
	}
	retained := prepared.state().state()
	owner := s.state().state().store
	custody, _, err := owner.authenticateIssuance(ctx, retained.generated)
	if err != nil || custody.recipient != nil {
		return PhoneChangeConfirmation{}, ErrInvalidCommand
	}
	issued, err := custody.challenge.Bindings()
	if err != nil {
		return PhoneChangeConfirmation{}, ErrInvalidCommand
	}
	var factors uint64
	for _, field := range retained.root.Fields {
		if field.Name == "phone.factor-version" {
			if factors != 0 || field.Value.Kind != identity.FeatureUint64 || field.Value.Uint64 == 0 {
				return PhoneChangeConfirmation{}, ErrInvalidCommand
			}
			factors = field.Value.Uint64
		} else if strings.HasPrefix(field.Name, "phone.factor-") {
			return PhoneChangeConfirmation{}, ErrInvalidCommand
		}
	}
	if factors == 0 {
		return PhoneChangeConfirmation{}, ErrInvalidCommand
	}
	p := &phoneEnrollmentConfirmation{source: retained.root, issued: issued,
		original: custody.authority, factors: factors, replacement: input.state().state().replacement}
	if _, err := p.fields(); err != nil {
		return PhoneChangeConfirmation{}, err
	}
	store := *owner
	store.send, store.phoneConfirmation = nil, p
	p.store = &store
	return PhoneChangeConfirmation{read: func() *phoneEnrollmentConfirmation { return p }}, nil
}

// Intent explicitly projects original sensitive replacement input. It grants
// no current authority or ownership and must not be logged or reinterpreted.
func (c PhoneChangeConfirmation) Intent() (kernel.PhoneChangeIntent, error) {
	p := c.enrollment().state()
	if p == nil || p.replacement == nil {
		return kernel.PhoneChangeIntent{}, ErrInvalidCommand
	}
	if _, err := p.fields(); err != nil {
		return kernel.PhoneChangeIntent{}, err
	}
	return *p.replacement, nil
}

// Fields returns owned original target/factor fields before fingerprinting.
// The native proof owner separately supplies its fresh update-proof fields.
func (c PhoneChangeConfirmation) Fields() ([]identity.FeatureField, error) {
	return c.enrollment().Fields()
}

// FactorVersion is the original known-empty generation, not new observation.
func (c PhoneChangeConfirmation) FactorVersion() (uint64, error) {
	return c.enrollment().FactorVersion()
}

// Lifetime is the original issued interval, never renewed remaining validity.
func (c PhoneChangeConfirmation) Lifetime() (time.Duration, error) { return c.enrollment().Lifetime() }

// Contributor returns the exact original consuming OTP owner. The native
// registry must compose its distinct proof/domain/risk/delivery participants.
func (c PhoneChangeConfirmation) Contributor() kernel.OTPExecutionContributor {
	return c.enrollment().Contributor()
}

// Prepare creates one new logical consuming attempt against the original code.
// Native current authority must already be authenticated. It owns no private
// transaction or retry: ambiguous completion must use original recovery instead.
func (c PhoneChangeConfirmation) Prepare(ctx context.Context, pool *database.Pool, root identity.Command, code auth.OneTimeCode, keyVersion uint32) (identity.Command, kernel.OTPAttemptPlan, error) {
	return c.enrollment().Prepare(ctx, pool, root, code, keyVersion)
}

// RestorePrepared restores the original server-owned attempt from authenticated
// native request-key custody. It does not read a newer challenge version,
// allocate another attempt, compare the code or renew original validity. The
// native caller must authenticate that custody and retain current Work checks.
func (c PhoneChangeConfirmation) RestorePrepared(ctx context.Context, root identity.Command, code auth.OneTimeCode, retained identity.FeatureCommandSpec) (identity.Command, kernel.OTPAttemptPlan, error) {
	bad := func() (identity.Command, kernel.OTPAttemptPlan, error) {
		return identity.Command{}, kernel.OTPAttemptPlan{}, ErrInvalidCommand
	}
	p := c.enrollment().state()
	if ctx == nil || p == nil || p.store == nil || p.replacement == nil {
		return bad()
	}
	if err := ctx.Err(); err != nil {
		return identity.Command{}, kernel.OTPAttemptPlan{}, err
	}
	base, ok := root.Feature()
	bearer, present := root.SessionToken()
	static := retained
	static.Fields = slices.DeleteFunc(slices.Clone(retained.Fields), func(f identity.FeatureField) bool { return otpField(f.Name) })
	if !ok || !present || !reflect.DeepEqual(base, static) || p.matches(base) != nil {
		return bad()
	}
	var version uint32
	for _, field := range retained.Fields {
		if field.Name == "otp.digest-key-version" && field.Value.Kind == identity.FeatureUint64 && field.Value.Uint64 <= uint64(^uint32(0)) {
			version = uint32(field.Value.Uint64)
		}
	}
	custody, err := p.store.codec.restoreCustody(retained)
	if err != nil || custody.authority == nil || *custody.authority != p.original {
		return bad()
	}
	plan, err := p.store.codec.recordPlan(custody.record, version)
	if err != nil || plan.Mode != kernel.OTPConsume || plan.ChallengeID != string(p.source.Binding.CommandID) {
		return bad()
	}
	scope, err := p.issued.Continuation.DigestScope()
	if err != nil {
		return bad()
	}
	digest, err := p.store.codec.verifier.ScopeDigest(scope, p.issued.Digest.KeyVersion)
	if err != nil || plan.DigestKeyVersion != p.issued.Digest.KeyVersion || plan.ScopeDigest != digest.Value {
		return bad()
	}
	command, err := identity.NewFeatureOneTimeCodeSessionCommand(retained, code, bearer)
	if err != nil || p.store.ValidateOTPAttemptCommand(command, plan) != nil {
		return bad()
	}
	return command, plan, ctx.Err()
}

// Admit rechecks original directory/credential/authorization/session in the
// exact registered native Work. First require the kernel's original change
// target; fresh update proof, factors/recovery/risk/CSRF remain native-owned.
func (c PhoneChangeConfirmation) Admit(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	return c.enrollment().Admit(ctx, w, owner, command)
}

// Check conserves original limits after the kernel's exact +1 successor. It
// cannot independently mark replacement successful or renew proof/session time.
func (c PhoneChangeConfirmation) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	return c.enrollment().Check(ctx, w, owner, command)
}

// Format redacts original number, session and challenge correlation.
func (PhoneChangeConfirmation) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("otp.postgres.PhoneChangeConfirmation(redacted)"))
}

// MarshalJSON denies implicit original-continuation disclosure.
func (PhoneChangeConfirmation) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText denies implicit original-continuation disclosure.
func (PhoneChangeConfirmation) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
