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

// AnonymousUpgradeEffect owns all guest-session revocation and exactly one
// permanent session issuance in the native upgrade owner's sole kernel Work.
// It owns no transaction, pool, callbacks, background work or authentication.
// The native owner must authenticate both original sessions, consume fresh
// target reauthentication and the one-use transition, and apply merge and guest
// disposal before this effect. Immutable configuration permits concurrent calls
// with independently owned, serial-use Work values.
type AnonymousUpgradeEffect struct {
	disposal *AnonymousDisposalEffect
	native   Repository
	config   Config
	profile  IssueAdmissionConfig
}

// NewAnonymousUpgradeEffect freezes the existing single-factor password owner
// profile without IO. Install AnonymousUpgradeMigrationSource after the actual
// anonymous signin/disposal histories; unsupported factors and optional authority
// deny rather than being omitted. The target's original authentication age and
// guest's resolved remember policy are preserved, never minted or renewed here.
func NewAnonymousUpgradeEffect(c Config, p IssueAdmissionConfig) (*AnonymousUpgradeEffect, error) {
	disposal, err := NewAnonymousDisposalEffect(c)
	if err != nil || !IdentifierAdmissionConfig(p).valid() || p.AuthenticationMethod != "password" || p.CredentialKind != identity.CredentialPassword || p.CredentialOwner != "identity/password" {
		return nil, session.ErrInvalidSessionCommand
	}
	c.Schema = strings.Clone(c.Schema)
	p.GlobalAuthorityID, p.PolicyNamespace, p.Audience, p.AuthenticationMethod, p.CredentialOwner = strings.Clone(p.GlobalAuthorityID), strings.Clone(p.PolicyNamespace), strings.Clone(p.Audience), strings.Clone(p.AuthenticationMethod), strings.Clone(p.CredentialOwner)
	return &AnonymousUpgradeEffect{disposal: disposal, native: Repository{schema: pgx.Identifier{c.Schema}.Sanitize(), maximumDuration: c.MaximumDuration}, config: c, profile: p}, nil
}

func anonymousUpgradeSessionOperation() identity.FeatureOperation {
	return identity.FeatureOperation{Owner: "identity/anonymous", OperationID: "identity.anonymous.upgrade", SchemaID: "identity.anonymous.upgrade.native-v1", SchemaVersion: 1, RecordRequirement: identity.FeatureRecordRequired}
}

func anonymousDisposalSessionScope(w kernel.Work, p kernel.FeatureExecutionContributor, c identity.Command, upgrade bool) (identity.CommandBinding, kernel.LifecyclePlan, error) {
	if !upgrade {
		return anonymousDeleteScope(w, p, c)
	}
	b, f, l, err := w.FeatureScope(p)
	s, ok := c.Feature()
	_, typed := p.(kernel.AnonymousUpgradeContributor)
	if err != nil || !ok || !typed || s.Binding != b || s.Operation != anonymousUpgradeSessionOperation() || f.Operation != s.Operation || b.RecordID == string(b.UserID) || b.RecordID == "" || string(b.ActorID) != string(b.UserID) || p.Descriptor() != (kernel.ContributorDescriptor{Owner: "identity/anonymous/postgres", ContractID: "identity.anonymous", Version: 1}) || l.EventType != "anonymous.upgraded.v1" || l.BeforeVersion == 0 || l.BeforeVersion == ^uint64(0) || l.AfterVersion != l.BeforeVersion+1 {
		return identity.CommandBinding{}, kernel.LifecyclePlan{}, session.ErrInvalidSessionCommand
	}
	return b, l, nil
}

// Apply requires exact original command custody, actual provisional one-use
// consumption and kernel guest disposal. It revokes every active-state guest
// session/family (including expired siblings), then persists the complete new
// permanent session and immutable issuance evidence. Propagate every error to
// abort all owners. A provisional receipt reveals no credential; Check must run
// again after downstream waits, and the issuer retains final delivery custody.
func (e *AnonymousUpgradeEffect) Apply(ctx context.Context, w kernel.Work, owner kernel.AnonymousUpgradeContributor, c identity.Command, guest, permanent session.Session, until time.Time) (identity.FeatureReceipt, error) {
	if ctx == nil || e == nil || e.disposal == nil || e.config.MaximumDuration <= 0 {
		return identity.FeatureReceipt{}, session.ErrInvalidSessionCommand
	}
	if err := w.RequireFeatureCommand(ctx, owner, c); err != nil {
		return identity.FeatureReceipt{}, err
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requireTarget(bounded, w, owner, c, guest, permanent, until); err != nil {
		return identity.FeatureReceipt{}, err
	}
	b, transition, _ := anonymousDisposalSessionScope(w, owner, c, true)
	s, _ := permanent.Bindings()
	// This profile promises a new permanent family, unlike ordinary issuance
	// which may add a sibling to an existing version-one family. The kernel's
	// tenant fence serializes all family writers; never adopt a random-ID clash.
	rows, err := w.Query(bounded, `SELECT EXISTS(SELECT 1 FROM `+e.native.schema+`.families WHERE tenant_id=$1 AND family_id=$2)`, string(s.TenantID), s.FamilyID)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	var occupied bool
	if !rows.Next() || rows.Scan(&occupied) != nil || rows.Next() || rows.Err() != nil {
		rows.Close()
		return identity.FeatureReceipt{}, ErrInvalidRecord
	}
	rows.Close()
	if occupied {
		return identity.FeatureReceipt{}, identity.ConflictError{}
	}
	receipt, err := e.disposal.apply(bounded, w, owner, c, guest, true)
	if err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := e.native.writeIssuedSession(bounded, w, b, transition, permanent, s); err != nil {
		return identity.FeatureReceipt{}, err
	}
	if err := RequireSession(bounded, w, e.config, permanent); err != nil {
		return identity.FeatureReceipt{}, err
	}
	return receipt, nil
}

func (e *AnonymousUpgradeEffect) requireTarget(ctx context.Context, w kernel.Work, owner kernel.AnonymousUpgradeContributor, c identity.Command, guest, permanent session.Session, until time.Time) error {
	if err := ValidateAnonymousUpgradeSessionIntent(c, guest, permanent); err != nil {
		return err
	}
	b, _, err := anonymousDisposalSessionScope(w, owner, c, true)
	if err != nil {
		return err
	}
	f, _ := c.Feature()
	fields := make([]identity.FeatureField, 0, len(f.Fields))
	for _, field := range f.Fields {
		if strings.HasPrefix(field.Name, "source-session.") {
			fields = append(fields, field)
		}
	}
	original, err := OriginalSessionFromFields(b.TenantID, b.UserID, fields)
	if err != nil {
		return err
	}
	o, _ := original.Bindings()
	s, _ := permanent.Bindings()
	oa, _ := o.Authority.Bindings()
	sa, _ := s.Authority.Bindings()
	// Only the new session/family identities change. The permanent credential,
	// owner epochs and historical authentication must remain the original ones.
	sa.Session, sa.SessionFamily = oa.Session, oa.SessionFamily
	if o.Authentication != s.Authentication || o.Audience != s.Audience || oa != sa || o.SessionID == s.SessionID || o.FamilyID == s.FamilyID {
		return session.ErrInvalidSessionCommand
	}
	directory, credential, policy, err := sessionAdmissionBindings(IdentifierAdmissionConfig(e.profile), permanent, b, s.SessionID, 1)
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
	if err := RequireSession(ctx, w, e.config, original); err != nil {
		return err
	}
	now, err := w.DatabaseTime(ctx)
	if err != nil {
		return err
	}
	if now.Before(s.IssuedAt) || !now.Before(until) || !until.After(s.IssuedAt) || until.After(s.IssuedAt.Add(20*time.Second)) {
		return identity.ForbiddenError{}
	}
	return nil
}

// Check repeats original target authority/session and the earliest unchanged
// deadline, proves no live guest session/family remains, and compares the exact
// persisted permanent session. It does not authenticate, refresh proof age or
// restore a guest. The enclosing native owner also fences its retention, factor,
// merge, risk and action-specific reauthentication owners before commitment.
func (e *AnonymousUpgradeEffect) Check(ctx context.Context, w kernel.Work, owner kernel.AnonymousUpgradeContributor, c identity.Command, guest, permanent session.Session, until time.Time) error {
	if ctx == nil || e == nil || e.disposal == nil || e.config.MaximumDuration <= 0 {
		return session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	if err := e.requireTarget(bounded, w, owner, c, guest, permanent, until); err != nil {
		return err
	}
	if err := e.disposal.check(bounded, w, owner, c, guest, until, true); err != nil {
		return err
	}
	return RequireSession(bounded, w, e.config, permanent)
}

// Recover reconciles BOTH retained guest-revocation and permanent-issuance
// evidence after live payload cleanup. Mixed/missing votes are unknown, not a
// claim of rollback or commitment. Success grants no current authority, token
// reconstruction or redelivery; the coordinator must reconcile every owner.
func (e *AnonymousUpgradeEffect) Recover(ctx context.Context, w kernel.RecoveryWork, owner kernel.AnonymousUpgradeContributor, guest session.Session) (kernel.RecoveryStatus, error) {
	if ctx == nil || e == nil || e.disposal == nil || e.config.MaximumDuration <= 0 {
		return kernel.RecoveryUnknown, session.ErrInvalidSessionCommand
	}
	bounded, stop := context.WithTimeout(ctx, e.config.MaximumDuration)
	defer stop()
	disposal, err := e.disposal.recover(bounded, w, owner, guest, true)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	b, _, transition, err := w.FeatureScope(owner)
	if err != nil {
		return kernel.RecoveryUnknown, err
	}
	_, issuance, err := readNativeIssuanceIdentity(bounded, w, e.native.schema, b, transition, anonymousUpgradeIssuanceDigest)
	if err != nil || disposal != issuance {
		return kernel.RecoveryUnknown, err
	}
	return disposal, nil
}

func anonymousUpgradeIssuanceDigest(binding [32]byte, user, id, family string, record []byte) [32]byte {
	return nativeIssuanceDigest("identity-session-anonymous-upgrade-issuance-v1\x00", binding, user, id, family, record)
}

// Format redacts deployment/authority correlation.
func (*AnonymousUpgradeEffect) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.AnonymousUpgradeEffect(redacted)"))
}

// MarshalJSON rejects configuration disclosure.
func (*AnonymousUpgradeEffect) MarshalJSON() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}

// MarshalText rejects configuration disclosure and implicit map keys.
func (*AnonymousUpgradeEffect) MarshalText() ([]byte, error) {
	return nil, session.ErrSecretSerialization
}
