package postgres

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	authority "github.com/faustbrian/go-authorization/v3/postgres"
	identity "github.com/faustbrian/go-identity"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	"github.com/jackc/pgx/v5"
)

// AnonymousAdmissionConfig selects the actual directory, unprivileged policy
// namespace and session audience. It contains no credential/method pairing:
// an anonymous principal has no verified credential. Configuration is trusted
// composition, not request input, and never grants policy permission itself.
type AnonymousAdmissionConfig struct {
	GlobalAuthorityID, PolicyNamespace, Audience string
}

func (c AnonymousAdmissionConfig) valid() bool {
	return (kernel.DirectoryAuthorityQuery{GlobalAuthorityID: c.GlobalAuthorityID, TenantID: "tenant"}).Validate() == nil &&
		(authority.AuthorityScope{TenantID: "tenant", PolicyNamespace: c.PolicyNamespace, SubjectID: "user"}).Validate() == nil &&
		len(c.Audience) <= 256 && visibleAdmissionText(c.Audience)
}

// AnonymousSigninEffect persists the anonymous session in its owning feature's
// sole kernel Work. It owns no pool, transaction, policy callback or goroutine.
// The anonymous owner must first admit risk, persist its actual lifecycle/TTL,
// apply kernel creation and explicitly initialize the guest policy authority.
// This effect neither bootstraps authority nor makes a verified proof. Immutable
// configuration permits concurrent calls with independently owned Work values.
type AnonymousSigninEffect struct {
	native  Repository
	config  Config
	profile AnonymousAdmissionConfig
}

func (*AnonymousSigninEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AnonymousSigninEffect(redacted)"))
}
func (*AnonymousSigninEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
func (*AnonymousSigninEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// NewAnonymousSigninEffect freezes an explicit anonymous-only profile without
// IO. Install the selected issuance suffix plus actual kernel/directory/policy
// histories before use. It accepts no application store or transaction engine.
func NewAnonymousSigninEffect(c Config, p AnonymousAdmissionConfig) (*AnonymousSigninEffect, error) {
	if !validSchema(c.Schema) || c.MaximumDuration <= 0 || c.MaximumDuration > time.Minute || !p.valid() {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience)
	return &AnonymousSigninEffect{native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, config: c, profile: p}, nil
}

func anonymousEffectScope(w kernel.Work, owner kernel.FeatureExecutionContributor) (identity.CommandBinding, error) {
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != anonymousSessionOperation() || transition != (kernel.LifecyclePlan{EventType: "anonymous.created.v1"}) || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}) {
		return identity.CommandBinding{}, session.ErrInvalidSessionCommand
	}
	return b, nil
}

// Apply requires the exact original command and actual staged anonymous kernel
// record, then writes the initial family/session and retained issuance evidence
// through the existing session owner. No credential reference is manufactured.
// Risk, anonymous expiry and all feature-owned effects remain the native
// anonymous owner's responsibility. Every error must abort Work; success is
// provisional and never discloses a bearer. The owner must call Check again
// after later phases before commitment, preserving the original record/epochs.
func (e *AnonymousSigninEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expected kernel.AnonymousAuthorityRecord) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, command); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, err := anonymousEffectScope(w, owner)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	record, err := AnonymousSigninSession(command)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requireAuthority(bounded, w, owner, b, record, expected); err != nil {
		return identity.FeatureReceipt{}, err
	}
	s, _ := record.Bindings()
	if err := e.native.requireIssueFamily(bounded, w, s, false); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.writeIssuedSession(bounded, w, b, kernel.LifecyclePlan{EventType: "anonymous.created.v1"}, record, s); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := RequireSession(bounded, w, e.config, record); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return identity.FeatureReceipt{Operation: anonymousSessionOperation()}, nil
}

// Check repeats original directory/kernel/policy/session and database-time
// admission during the same feature's final read-only invocation. It does not
// replace original epochs, renew freshness, write or restore command custody.
func (e *AnonymousSigninEffect) Check(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, command identity.Command, expected kernel.AnonymousAuthorityRecord) error {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return session.ErrInvalidSessionCommand
	}
	b, err := anonymousEffectScope(w, owner)
	if err != nil {
		return err
	}
	f, ok := command.Feature()
	if !ok || f.Binding != b || f.Operation != anonymousSessionOperation() {
		return session.ErrInvalidSessionCommand
	}
	record, err := AnonymousSigninSession(command)
	if err != nil {
		return err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requireAuthority(bounded, w, owner, b, record, expected); err != nil {
		return err
	}
	return RequireSession(bounded, w, e.config, record)
}

func (e *AnonymousSigninEffect) requireAuthority(ctx context.Context, w kernel.Work, owner kernel.FeatureExecutionContributor, b identity.CommandBinding, record session.Session, expected kernel.AnonymousAuthorityRecord) error {
	s, err := record.Bindings()
	if err != nil || expected.Validate() != nil || expected.User.Status != identity.StatusActive || s.TenantID != b.TenantID || s.UserID != expected.User.ID || expected.User.TenantID != b.TenantID || s.Audience != e.profile.Audience {
		return session.ErrInvalidSessionCommand
	}
	a, err := s.Authority.Bindings()
	if err != nil {
		return err
	}
	query := kernel.DirectoryAuthorityQuery{GlobalAuthorityID: e.profile.GlobalAuthorityID, TenantID: b.TenantID}
	keys, err := kernel.KernelAuthorityKeys(query, s.UserID)
	if err != nil {
		return err
	}
	sk, err := SessionAuthorityKeys(s.TenantID, s.UserID, s.FamilyID, s.SessionID)
	if err != nil {
		return err
	}
	scope := authority.AuthorityScope{TenantID: authorization.TenantID(s.TenantID), PolicyNamespace: e.profile.PolicyNamespace, SubjectID: authorization.SubjectID(s.UserID)}
	pk, err := scope.Key()
	if err != nil {
		return err
	}
	if a.Global.ScopeKey != keys.Global || a.Tenant.ScopeKey != keys.Tenant || a.User != (session.AuthorityBinding{ScopeKey: keys.User, Version: expected.UserAuthorityVersion}) || a.Identifier != (session.AuthorityBinding{ScopeKey: keys.Identifier, Version: expected.IdentifierAuthorityVersion}) || a.Credential != (session.AuthorityBinding{ScopeKey: keys.Credential, Version: expected.CredentialAuthorityVersion}) || a.Session != (session.AuthorityBinding{ScopeKey: sk.Session, Version: s.Version}) || a.SessionFamily != (session.AuthorityBinding{ScopeKey: sk.Family, Version: s.FamilyVersion}) || a.Authorization.ScopeKey != pk {
		return identity.ForbiddenError{}
	}
	if err := w.RequireActiveDirectoryAuthority(ctx, owner, kernel.DirectoryAuthorityAdmission{Query: query, GlobalVersion: a.Global.Version, TenantVersion: a.Tenant.Version}); err != nil {
		return err
	}
	if err := w.RequireAnonymousAuthority(ctx, owner, expected); err != nil {
		return err
	}
	if err := authority.RequireAuthority(ctx, w, scope, a.Authorization.Version, e.config.MaximumDuration); err != nil {
		return admissionError(ctx, err)
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	life, err := record.Lifetime(now)
	if err != nil || now.Before(s.IssuedAt) || !now.Before(life.ExpiresAt) {
		return identity.ForbiddenError{}
	}
	return nil
}

// Recover reads immutable original session evidence in the exact native recovery
// invocation. It grants no current access and returns no bearer/session; missing
// payload is not rollback. The coordinator reconciles every participant.
func (e *AnonymousSigninEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.FeatureExecutionContributor) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.config.MaximumDuration <= 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	b, feature, transition, err := w.FeatureScope(owner)
	if err != nil || feature.Operation != anonymousSessionOperation() || transition != (kernel.LifecyclePlan{EventType: "anonymous.created.v1"}) || owner.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}) {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	_, status, err := readNativeIssuanceIdentity(bounded, w, e.native.schema, b, transition, anonymousIssuanceDigest)
	return status, err
}

func anonymousIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-anonymous-issuance-v1\x00", binding, user, id, family, record)
}
