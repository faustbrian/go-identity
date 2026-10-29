package apikey

import (
	"context"
	"fmt"
	"io"
	"slices"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// KeyStatus is terminal revocation versus active eligibility, not owner status.
type KeyStatus uint8

const (
	KeyStatusUnspecified KeyStatus = iota
	KeyActive
	KeyRevoked
)

// Record contains no secret or digest. Grants are immutable ceilings, bytewise
// sorted and duplicate-free. RootID is this credential's own ID and RootVersion
// equals its current AuthorityVersion. PreviousID records replacement/audit
// lineage, not an authorization dependency on a now-revoked predecessor. No raw
// key, authenticated human actor or OAuth delegation is inferred from them.
type Record struct {
	ID      KeyID
	Owner   Owner
	Version uint64
	// AuthorityVersion is exclusively this key's credential-security epoch.
	// ConfigurationAuthorityBinding owns the distinct tenant/configuration epoch.
	AuthorityVersion              uint64
	ConfigurationID               string
	ConfigurationRevision         uint64
	Name                          string
	Status                        KeyStatus
	Grant                         []string
	CreatedAt, ExpiresAt          time.Time
	RootID                        KeyID
	RootVersion                   uint64
	PreviousID                    KeyID
	Issuer, Environment, Audience string
}

func (r Record) Validate(c Configuration) error {
	if _, err := ParseKeyID(string(r.ID)); err != nil {
		return ErrInvalid
	}
	if _, err := ParseKeyID(string(r.RootID)); err != nil {
		return ErrInvalid
	}
	if r.PreviousID != "" {
		if _, err := ParseKeyID(string(r.PreviousID)); err != nil || r.PreviousID == r.ID {
			return ErrInvalid
		}
	}
	// Shared-issuer SI-07 preserves historical absolute times. A verification-
	// only import is not new issuance and cannot rebase an old creation time to
	// fit today's issuance ceiling; modern records keep the original bound.
	if c.Validate() != nil || r.Owner.Validate() != nil || r.Version == 0 || r.AuthorityVersion == 0 || r.RootID != r.ID || r.RootVersion != r.AuthorityVersion || r.ConfigurationID != c.spec.ID || r.ConfigurationRevision != c.spec.Revision || r.Issuer != c.spec.Issuer || r.Environment != c.spec.Environment || r.Audience != c.spec.Audience || r.Status < KeyActive || r.Status > KeyRevoked || !validPermissions(r.Grant) || len(r.Name) > 128 || r.CreatedAt.IsZero() || !r.ExpiresAt.After(r.CreatedAt) || c.spec.Algorithm == AlgorithmModernHMACSHA256 && r.ExpiresAt.Sub(r.CreatedAt) > c.spec.MaximumLifetime {
		return ErrInvalid
	}
	return nil
}

// CurrentAuthority is a trusted primary-policy projection, not caller proof.
// The adapter must read real owner/tenant/policy state and retain the original
// read start. A callback cannot supply missing domain storage or secret checks.
// Policy permissions may only intersect the immutable key grant.
type CurrentAuthority struct {
	Owner                                 Owner
	OwnerActive, TenantActive             bool
	Permissions                           []string
	PolicyVersion                         uint64
	ConfigurationAuthority                ConfigurationAuthorityBinding
	ReadStartedAt, VerifiedAt, ValidUntil time.Time
}

// ScopePolicy implements bounded intersection, never permission inheritance.
// It owns no store, clock, transaction, authority cache or authorization engine.
type ScopePolicy struct{}

func (ScopePolicy) EffectiveGrant(r Record, a CurrentAuthority, c Configuration, now time.Time) ([]string, error) {
	if r.Validate(c) != nil || !c.AllowsVerification() || r.Status != KeyActive || !now.Before(r.ExpiresAt) || !a.Owner.SameIdentity(r.Owner) || a.Owner.Version() < r.Owner.Version() || !a.OwnerActive || !a.TenantActive || a.PolicyVersion == 0 || a.ConfigurationAuthority.Validate(r.Owner.spec.TenantID, c.spec.ID) != nil || !validPermissions(a.Permissions) || a.ReadStartedAt.IsZero() || a.VerifiedAt.Before(a.ReadStartedAt) || a.VerifiedAt.After(now) || a.VerifiedAt.Sub(a.ReadStartedAt) > c.spec.MaximumRead || !a.ValidUntil.After(a.VerifiedAt) || a.ValidUntil.Sub(a.ReadStartedAt) > 20*time.Second || !now.Before(a.ValidUntil) {
		return nil, ErrDenied
	}
	grant := make([]string, 0, len(r.Grant))
	for _, permission := range r.Grant {
		if slices.Contains(a.Permissions, permission) {
			grant = append(grant, permission)
		}
	}
	return grant, nil
}

// Authorize denies missing required permissions before a narrowing write can
// complete. Persistence failure cannot bridge removed authority with old grants.
func (p ScopePolicy) Authorize(r Record, a CurrentAuthority, c Configuration, required []string, now time.Time) ([]string, error) {
	if !validPermissions(required) {
		return nil, ErrInvalid
	}
	grant, err := p.EffectiveGrant(r, a, c, now)
	if err != nil {
		return nil, err
	}
	for _, permission := range required {
		if !slices.Contains(grant, permission) {
			return nil, ErrDenied
		}
	}
	return grant, nil
}

// PermissionReductionDecision binds one original command to exact owner/key/
// policy epochs and a strict current subset. Store must compare all original
// inputs, advance key/API-key authority once, and emit the selected event.
type PermissionReductionDecision struct {
	CommandID                                                   identity.CommandID
	KeyID                                                       KeyID
	Owner                                                       Owner
	ExpectedKeyVersion, ExpectedAuthorityVersion, PolicyVersion uint64
	PriorGrant, EffectiveCurrentGrant, Grant                    []string
	Disposition                                                 PermissionReductionDisposition
	// ConfigurationAuthority is the independent pre-transition aggregate epoch,
	// not ExpectedAuthorityVersion, which is this credential's security epoch.
	ConfigurationAuthority ConfigurationAuthorityBinding
}

func (p ScopePolicy) DecidePermissionReduction(id identity.CommandID, r Record, a CurrentAuthority, c Configuration, now time.Time) (PermissionReductionDecision, error) {
	grant, err := p.EffectiveGrant(r, a, c, now)
	if err != nil {
		return PermissionReductionDecision{}, err
	}
	if slices.Equal(grant, r.Grant) {
		return PermissionReductionDecision{}, ErrNoReduction
	}
	d := PermissionReductionDecision{CommandID: id, KeyID: r.ID, Owner: a.Owner, ExpectedKeyVersion: r.Version, ExpectedAuthorityVersion: r.AuthorityVersion, PolicyVersion: a.PolicyVersion, ConfigurationAuthority: a.ConfigurationAuthority, PriorGrant: slices.Clone(r.Grant), EffectiveCurrentGrant: slices.Clone(grant), Grant: slices.Clone(grant), Disposition: c.spec.PermissionReduction}
	if d.Disposition == PermissionReductionRevoke {
		d.Grant = []string{}
	}
	if err := d.Validate(); err != nil {
		return PermissionReductionDecision{}, err
	}
	return d, nil
}

func (d PermissionReductionDecision) Validate() error {
	if _, err := identity.ParseCommandID(string(d.CommandID)); err != nil {
		return ErrInvalid
	}
	if _, err := ParseKeyID(string(d.KeyID)); err != nil {
		return ErrInvalid
	}
	if d.Owner.Validate() != nil || d.ExpectedKeyVersion == 0 || d.ExpectedKeyVersion == ^uint64(0) || d.ExpectedAuthorityVersion == 0 || d.ExpectedAuthorityVersion == ^uint64(0) || d.PolicyVersion == 0 || d.ConfigurationAuthority.Validate(d.Owner.spec.TenantID, d.ConfigurationAuthority.ConfigurationID) != nil || d.ConfigurationAuthority.Version == ^uint64(0) || !validPermissions(d.PriorGrant) || !validPermissions(d.EffectiveCurrentGrant) || !validPermissions(d.Grant) || len(d.EffectiveCurrentGrant) >= len(d.PriorGrant) {
		return ErrInvalid
	}
	for _, permission := range d.EffectiveCurrentGrant {
		if !slices.Contains(d.PriorGrant, permission) {
			return ErrInvalid
		}
	}
	switch d.Disposition {
	case PermissionReductionNarrow:
		if !slices.Equal(d.Grant, d.EffectiveCurrentGrant) {
			return ErrInvalid
		}
	case PermissionReductionRevoke:
		if len(d.Grant) != 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

type PermissionReductionReconcileQuery struct {
	CommandID   identity.CommandID
	TenantID    identity.TenantID
	Fingerprint [32]byte
}
type PermissionReductionResult struct {
	Decision PermissionReductionDecision
	Outcome  identity.CommitOutcome
	Record   *Record
	// ConfigurationAuthority is the proven committed successor of the shared
	// configuration aggregate. Unknown/noncommit results must leave it nil.
	ConfigurationAuthority *ConfigurationAuthorityBinding
}

// Validate preserves the decision's exact version-fenced transition. An unknown
// or noncommitted result must never carry an authoritative resulting record.
func (r PermissionReductionResult) Validate(c Configuration) error {
	d := r.Decision
	if d.Validate() != nil || c.Validate() != nil || d.Disposition != c.spec.PermissionReduction || d.ConfigurationAuthority.Validate(d.Owner.spec.TenantID, c.spec.ID) != nil {
		return ErrInvalid
	}
	if r.Outcome != identity.CommitOutcomeCommitted {
		if r.Record != nil || r.ConfigurationAuthority != nil || r.Outcome != identity.CommitOutcomeNotCommitted && r.Outcome != identity.CommitOutcomeUnknown && r.Outcome != identity.CommitOutcomeConflict && r.Outcome != identity.CommitOutcomeInProgress {
			return ErrInvalid
		}
		return nil
	}
	if r.Record == nil || r.ConfigurationAuthority == nil || r.ConfigurationAuthority.Validate(d.Owner.spec.TenantID, c.spec.ID) != nil || r.ConfigurationAuthority.Version != d.ConfigurationAuthority.Version+1 {
		return ErrInvalid
	}
	record := *r.Record
	if record.Validate(c) != nil || record.ID != d.KeyID || record.Owner != d.Owner || record.Version != d.ExpectedKeyVersion+1 || record.AuthorityVersion != d.ExpectedAuthorityVersion+1 || !slices.Equal(record.Grant, d.Grant) || d.Disposition == PermissionReductionNarrow && record.Status != KeyActive || d.Disposition == PermissionReductionRevoke && record.Status != KeyRevoked {
		return ErrInvalid
	}
	return nil
}

// Validate binds status inquiry to the original command, tenant and canonical
// coordinator fingerprint without carrying a secret or executing a decision.
func (q PermissionReductionReconcileQuery) Validate() error {
	if _, err := identity.ParseCommandID(string(q.CommandID)); err != nil {
		return ErrInvalid
	}
	if !scope(string(q.TenantID), 128) || q.Fingerprint == ([32]byte{}) {
		return ErrInvalid
	}
	return nil
}

// Store owns version-fenced reduction and original status inquiry. Application
// code must use an owned native implementation, not implement domain storage.
type Store interface {
	ApplyPermissionReduction(context.Context, PermissionReductionDecision) (PermissionReductionResult, error)
	ReconcilePermissionReduction(context.Context, PermissionReductionReconcileQuery) (PermissionReductionResult, error)
}

func validPermissions(permissions []string) bool {
	if len(permissions) > 64 {
		return false
	}
	for i, p := range permissions {
		if !scope(p, 128) || i > 0 && permissions[i-1] >= p {
			return false
		}
	}
	return true
}
func (Record) Format(s fmt.State, _ rune) { io.WriteString(s, "apikey.Record(redacted)") }
func (CurrentAuthority) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.CurrentAuthority(redacted)")
}
func (PermissionReductionDecision) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.PermissionReductionDecision(redacted)")
}
