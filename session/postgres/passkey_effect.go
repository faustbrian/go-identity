package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// PasskeySigninEffect stages initial session/family/issuance effects in the
// passkey owner's original Work. It does not verify WebAuthn or issue bearer
// custody. The native owner must first finalize the genuine opaque assertion,
// its one-use counter/backup transition, risk and mapping in this same Work,
// then repeat Check after all later effects. No independent transaction, pool,
// goroutine or command journal is created. Configuration supports concurrent
// calls with independently owned serial-use Work values; Authority is borrowed.
type PasskeySigninEffect struct {
	native    Repository
	config    Config
	profile   PasskeyAdmissionConfig
	authority PasskeySessionAuthority
}

// NewPasskeySigninEffect freezes explicit trusted native/RP composition without
// IO. Install the actual existing session history and passkey issuance suffix
// first. Authority must be the owned passkey adapter for this primary database;
// a metadata projection or application-written verifier is not a substitute.
func NewPasskeySigninEffect(c Config, p PasskeyAdmissionConfig, authority PasskeySessionAuthority) (*PasskeySigninEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !p.valid() || nilIssueDependency(authority) {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	return &PasskeySigninEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, config: c, profile: freezePasskeyProfile(p), authority: authority}, nil
}

func passkeyEffectScope(w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) (identity.CommandBinding, kernel.LifecyclePlan, error) {
	b, feature, transition, err := w.FeatureScope(owner)
	f, ok := command.Feature()
	if err != nil || !ok || f.Binding != b || f.Operation != passkeySessionOperation() || feature.Operation != f.Operation || transition != (kernel.LifecyclePlan{EventType: "session.created.v1", BeforeVersion: 0, AfterVersion: 1}) || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}) {
		return identity.CommandBinding{}, kernel.LifecyclePlan{}, session.ErrInvalidSessionCommand
	}
	return b, transition, nil
}

// Apply requires exact original command custody, all original current owners
// and the selected known-empty MFA/RP profile, then stages the complete initial
// session through the existing session SQL owner. Every error must abort Work.
// Success is provisional and cannot reveal a bearer or VerifiedAssertion.
func (e *PasskeySigninEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 || nilIssueDependency(e.authority) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, transition, err := passkeyEffectScope(w, owner, command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, err := PasskeySigninSession(command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requireAuthority(bounded, w, owner, b, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	spec, _ := record.Bindings()
	if err := e.native.requireIssueFamily(bounded, w, spec, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.writeIssuedSession(bounded, w, b, transition, record, spec); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := RequireSession(bounded, w, e.config, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: passkeySessionOperation(), AfterVersion: 1}, nil
}

// Check repeats original directory/credential/policy/RP/empty-factor authority,
// exact stored session and database-time freshness after downstream waits. It
// never adopts newer epochs or restarts the original assertion/proof lifetime.
func (e *PasskeySigninEffect) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command) error {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 || nilIssueDependency(e.authority) {
		return session.ErrInvalidSessionCommand
	}
	b, _, err := passkeyEffectScope(w, owner, command)
	if err != nil {
		return err
	}
	record, err := PasskeySigninSession(command)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requireAuthority(bounded, w, owner, b, record); err != nil {
		return err
	}
	if err := RequireSession(bounded, w, e.config, record); err != nil {
		return err
	}
	return requirePasswordIssueTime(bounded, w, record)
}

func (e *PasskeySigninEffect) requireAuthority(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, b identity.CommandBinding, record session.Session) error {
	directory, credential, policy, err := passkeySessionAdmission(e.profile, record, b)
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, directory); err != nil {
		return err
	}
	if _, err := w.RequireActiveCredential(ctx, owner, credential); err != nil {
		return err
	}
	if err := w.RequireActiveUserAuthorization(ctx, owner, policy); err != nil {
		return err
	}
	if err := e.authority.RequirePasskeySession(ctx, w, owner, e.profile.RPNamespace, record); err != nil {
		return err
	}
	return requirePasswordIssueTime(ctx, w, record)
}

// Recover reads immutable original issuance evidence in the exact registered
// recovery invocation. It discloses no bearer/session and grants no current
// access. The coordinator must reconcile protocol and every other participant;
// missing payload never proves rollback and cannot authorize a new assertion.
func (e *PasskeySigninEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, f, transition, err := w.FeatureScope(owner)
	if err != nil || f.Operation != passkeySessionOperation() || transition != (kernel.LifecyclePlan{EventType: "session.created.v1", AfterVersion: 1}) || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	_, status, err := readNativeIssuanceIdentity(bounded, w, e.native.schema, b, transition, passkeyIssuanceDigest)
	return status, err
}

func passkeyIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-passkey-issuance-v1\x00", binding, user, id, family, record)
}

// Format redacts correlated configuration and authority dependencies.
func (*PasskeySigninEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasskeySigninEffect(redacted)"))
}

// MarshalJSON rejects implicit configuration disclosure.
func (*PasskeySigninEffect) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText rejects implicit configuration disclosure.
func (*PasskeySigninEffect) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
