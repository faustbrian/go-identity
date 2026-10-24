package postgres

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	policy "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// PasskeySignupSessionAuthority is supplied by the owned native passkey adapter,
// never an application-written verifier. It must lock the exact current RP/key
// mapping and the MFA generation initialized by this original signup command,
// using the borrowed Work. Metadata or a missing factor row is not authority.
// Errors abort Work; success is provisional, without a renewable validity lease.
type PasskeySignupSessionAuthority interface {
	RequirePasskeySignupSession(context.Context, kernel.Work, kernel.PasskeyRegistrationContributor, identity.Command, string, session.Session) error
}

// PasskeySignupEffect writes the initial session/family and retained issuance
// binding for an actually created prospective account. It owns no transaction,
// pool, goroutine, pre-auth flow or cryptographic verifier. The native signup
// owner must first verify WebAuthn, initialize selected authorities, and admit
// original pre-auth cookie/remember/risk custody, then consume/finalize all
// required effects in the same Work. Immutable configuration supports concurrent
// independent calls; borrowed Work and dependencies must not be retained/closed.
type PasskeySignupEffect struct {
	native    Repository
	config    Config
	profile   PasskeyAdmissionConfig
	authority PasskeySignupSessionAuthority
}

// NewPasskeySignupEffect freezes trusted configuration without IO. Install the
// actual kernel, MFA, authorization and session histories, including the selected
// PasskeySignupMigrationSource, before use. This enables no public signup route.
func NewPasskeySignupEffect(c Config, p PasskeyAdmissionConfig, a PasskeySignupSessionAuthority) (*PasskeySignupEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !p.valid() || nilIssueDependency(a) {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	return &PasskeySignupEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, config: c, profile: freezePasskeyProfile(p), authority: a}, nil
}

func passkeySignupEffectScope(w kernel.Work, owner kernel.PasskeyRegistrationContributor, command identity.Command) (identity.CommandBinding, kernel.LifecyclePlan, error) {
	b, f, l, err := w.FeatureScope(owner)
	s, ok := command.Feature()
	if err != nil || !ok || s.Binding != b || s.Operation != passkeySignupSessionOperation() || f.Operation != s.Operation || l.EventType != "identity.passkey.create_credential" || l.BeforeVersion != 0 || l.AfterVersion != 1 || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}) {
		return identity.CommandBinding{}, kernel.LifecyclePlan{}, session.ErrInvalidSessionCommand
	}
	return b, l, nil
}

// Apply stages only the complete original command-mapped session after fencing
// this Work's actual newly created account/credential, current deployment and
// authorization, and native RP/known-empty factor ownership. It cannot turn an
// existing account or a changed generation into signup. Every error must abort
// the enclosing native command. Success neither commits nor reveals a bearer.
func (e *PasskeySignupEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.PasskeyRegistrationContributor, command identity.Command) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 || nilIssueDependency(e.authority) {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, l, err := passkeySignupEffectScope(w, owner, command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, err := PasskeySignupSession(command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requireAuthority(bounded, w, owner, command, b, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := record.Bindings()
	if err := e.native.requireIssueFamily(bounded, w, s, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.writeIssuedSession(bounded, w, b, l, record, s); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := RequireSession(bounded, w, e.config, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := requirePasswordIssueTime(bounded, w, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: passkeySignupSessionOperation(), AfterVersion: 1}, nil
}

// Check repeats original account/reference/RP/factor/authorization and session
// checks after later audit/outbox phases, with primary database time. It never
// refreshes the original proof, selects a newer generation or mints a session.
func (e *PasskeySignupEffect) Check(ctx context.Context, w kernel.Work, owner kernel.PasskeyRegistrationContributor, command identity.Command) error {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 || nilIssueDependency(e.authority) {
		return session.ErrInvalidSessionCommand
	}
	b, _, err := passkeySignupEffectScope(w, owner, command)
	if err != nil {
		return err
	}
	record, err := PasskeySignupSession(command)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requireAuthority(bounded, w, owner, command, b, record); err != nil {
		return err
	}
	if err := RequireSession(bounded, w, e.config, record); err != nil {
		return err
	}
	return requirePasswordIssueTime(bounded, w, record)
}

func (e *PasskeySignupEffect) requireAuthority(ctx context.Context, w kernel.Work, owner kernel.PasskeyRegistrationContributor, command identity.Command, b identity.CommandBinding, record session.Session) error {
	u, err := w.PasskeyRegistrationUser(ctx, owner, command)
	if err != nil {
		return err
	}
	s, _ := record.Bindings()
	if u.ID != s.UserID || u.TenantID != s.TenantID {
		return identity.ForbiddenError{}
	}
	// Derive selected-user scope keys only. The exact anonymous command/Work
	// remains unchanged; kernel custody above checks its actual created user.
	selected := b
	selected.UserID, selected.ActorID, selected.ActorKind = s.UserID, identity.ActorID(s.UserID), authorization.SubjectUser
	directory, _, authorization, err := passkeySessionAdmission(e.profile, record, selected)
	if err != nil {
		return err
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, directory); err != nil {
		return err
	}
	if err := policy.RequireAuthority(ctx, w, authorization.Scope, authorization.Version, e.config.MaximumDuration); err != nil {
		if errors.Is(err, policy.ErrAuthorityDenied) {
			return identity.ForbiddenError{}
		}
		return readError(ctx, err)
	}
	if err := e.authority.RequirePasskeySignupSession(ctx, w, owner, command, e.profile.RPNamespace, record); err != nil {
		return err
	}
	return requirePasswordIssueTime(ctx, w, record)
}

// Recover reads immutable original issuance evidence in the exact registered
// native recovery invocation. It returns neither bearer nor current authority;
// the coordinator still reconciles every participant. Missing session payload
// is not rollback, and a recovered result must not renew access or reveal again.
func (e *PasskeySignupEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.PasskeyRegistrationContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, f, l, err := w.FeatureScope(owner)
	if err != nil || f.Operation != passkeySignupSessionOperation() || l.EventType != "identity.passkey.create_credential" || l.BeforeVersion != 0 || l.AfterVersion != 1 || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "passkey/postgres", ContractID: "identity.passkey", Version: 1}) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	_, status, err := readNativeIssuanceIdentity(bounded, w, e.native.schema, b, l, passkeySignupIssuanceDigest)
	return status, err
}

func passkeySignupIssuanceDigest(b [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-passkey-signup-issuance-v1\x00", b, user, id, family, record)
}

// Format redacts correlated configuration and borrowed authorities.
func (*PasskeySignupEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.PasskeySignupEffect(redacted)"))
}

// MarshalJSON refuses implicit configuration export.
func (*PasskeySignupEffect) MarshalJSON() ([]byte, error) { return nil, session.ErrSecretSerialization }

// MarshalText refuses implicit configuration export.
func (*PasskeySignupEffect) MarshalText() ([]byte, error) { return nil, session.ErrSecretSerialization }
