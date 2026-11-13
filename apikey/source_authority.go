package apikey

import (
	"fmt"
	"io"
	"slices"
	"time"
)

// SourceAuthorityBinding retains the nonsecret immutable ceiling of an already
// authenticated user-owned key. It is not a bearer credential, human
// actor, session or authority proof. ConfigurationAuthority is the historical
// configuration epoch; an unrelated key mutation may advance the current
// aggregate without changing this key's independent security epoch.
// Callers must preserve the original verification timestamps separately.
type SourceAuthorityBinding struct {
	ConfigurationAuthority ConfigurationAuthorityBinding
	ConfigurationRevision  uint64
	KeyID                  KeyID
	Owner                  Owner
	AuthorityVersion       uint64
	RootID                 KeyID
	RootVersion            uint64
	Issuer                 string
	Environment            string
	Audience               string
	Grant                  []string
	ExpiresAt              time.Time
}

// NewSourceAuthorityBinding snapshots a structurally valid, still-fresh result.
// Only the real AtomicVerifier can authenticate the original bearer; this
// constructor cannot establish where a caller-provided result came from.
func NewSourceAuthorityBinding(r VerificationResult, c Configuration, now time.Time) (SourceAuthorityBinding, error) {
	if r.ValidateAt(c, now) != nil {
		return SourceAuthorityBinding{}, ErrDenied
	}
	b := sourceAuthorityBinding(r)
	if err := b.Validate(c); err != nil {
		return SourceAuthorityBinding{}, err
	}
	return b, nil
}

func sourceAuthorityBinding(r VerificationResult) SourceAuthorityBinding {
	record := r.Record
	return SourceAuthorityBinding{
		ConfigurationAuthority: r.ConfigurationAuthority,
		ConfigurationRevision:  record.ConfigurationRevision,
		KeyID:                  record.ID,
		Owner:                  record.Owner,
		AuthorityVersion:       record.AuthorityVersion,
		RootID:                 record.RootID,
		RootVersion:            record.RootVersion,
		Issuer:                 record.Issuer,
		Environment:            record.Environment,
		Audience:               record.Audience,
		Grant:                  slices.Clone(r.Grant),
		ExpiresAt:              record.ExpiresAt,
	}
}

// Validate checks user-only shape and exact modern or verify-only legacy
// configuration, not current storage, bearer authentication or permission.
// Mutable fields remain borrowed until their invoking bounded call returns.
func (b SourceAuthorityBinding) Validate(c Configuration) error {
	return b.validate(c, OwnerUser)
}

func (b SourceAuthorityBinding) validate(c Configuration, kind OwnerKind) error {
	profile := c.Spec()
	owner := b.Owner.Spec()
	modern := profile.Algorithm == AlgorithmModernHMACSHA256
	legacy := profile.Algorithm == AlgorithmLegacySHA256V1 && profile.State == ConfigurationVerifyOnly
	configurationSelected := c.Validate() == nil && c.AllowsVerification() && (modern || legacy)
	if !configurationSelected || b.ConfigurationRevision != profile.Revision {
		return ErrInvalid
	}
	if b.Owner.Validate() != nil || owner.Kind != kind || b.ConfigurationAuthority.Validate(owner.TenantID, profile.ID) != nil {
		return ErrInvalid
	}
	if _, err := ParseKeyID(string(b.KeyID)); err != nil {
		return err
	}
	if b.RootID != b.KeyID || b.RootVersion == 0 || b.RootVersion != b.AuthorityVersion {
		return ErrInvalid
	}
	profileMatches := b.Issuer == profile.Issuer && b.Environment == profile.Environment && b.Audience == profile.Audience
	if !profileMatches || !validPermissions(b.Grant) {
		return ErrInvalid
	}
	expiryRepresentable := !b.ExpiresAt.IsZero() && b.ExpiresAt.Year() >= 1 && b.ExpiresAt.Year() <= 9999 && b.ExpiresAt.Nanosecond()%1000 == 0
	if legacy && profile.AllowLegacyNoExpiry && b.ExpiresAt.IsZero() {
		expiryRepresentable = true
	}
	if !expiryRepresentable {
		return ErrInvalid
	}
	return nil
}

func sameSourceBinding(a, b SourceAuthorityBinding) bool {
	configurationMatches := a.ConfigurationAuthority == b.ConfigurationAuthority && a.ConfigurationRevision == b.ConfigurationRevision
	rootMatches := a.KeyID == b.KeyID && a.Owner == b.Owner && a.AuthorityVersion == b.AuthorityVersion && a.RootID == b.RootID && a.RootVersion == b.RootVersion
	profileMatches := a.Issuer == b.Issuer && a.Environment == b.Environment && a.Audience == b.Audience
	return configurationMatches && rootMatches && profileMatches && slices.Equal(a.Grant, b.Grant) && a.ExpiresAt.Equal(b.ExpiresAt)
}

// SourceAuthorityObservation is a distinct uncached primary observation of an
// already-bound source, not renewed bearer authentication. It never verifies a
// secret, debits quota, mutates permissions or creates a principal. Epochs bind
// the exact current native owners for a later protected Work fence. Grant only
// intersects the inherited binding. All failures return a zero observation.
// Copies/retries must retain these timestamps; the earliest contributing
// current deadline wins. Historical issuance timestamps and credential expiry
// are never changed by making a genuinely later observation.
type SourceAuthorityObservation struct {
	Binding                               SourceAuthorityBinding
	Record                                Record
	Owner                                 Owner
	Grant                                 []string
	PolicyVersion                         uint64
	ConfigurationAuthority                ConfigurationAuthorityBinding
	GlobalVersion                         uint64
	TenantVersion                         uint64
	UserVersion                           uint64
	UserAuthorityVersion                  uint64
	AuthorizationVersion                  uint64
	ReadStartedAt, VerifiedAt, ValidUntil time.Time
}

// Validate checks exact bindings and original observation freshness only. A
// trusted native owner must produce the facts and fence current storage before
// a protected operation; structural validation cannot grant authority.
func (o SourceAuthorityObservation) Validate(b SourceAuthorityBinding, c Configuration, now time.Time) error {
	if b.Validate(c) != nil || !sameSourceBinding(o.Binding, b) || o.Record.Validate(c) != nil {
		return ErrDenied
	}
	currentOwnerMatches := o.Owner.Validate() == nil && o.Owner.SameIdentity(b.Owner) && o.Owner.admitsEpoch(b.Owner) && o.Owner.admitsEpoch(o.Record.Owner) && o.Owner.Version() == o.UserAuthorityVersion
	recordedOwnerMatches := o.Record.Owner.SameIdentity(b.Owner) && o.Record.Owner.admitsEpoch(b.Owner)
	if !currentOwnerMatches || !recordedOwnerMatches {
		return ErrDenied
	}
	rootMatches := o.Record.ID == b.KeyID && o.Record.RootID == b.RootID && o.Record.RootVersion == b.RootVersion && o.Record.AuthorityVersion == b.AuthorityVersion
	if !rootMatches || o.Record.Status != KeyActive || !o.Record.ExpiresAt.Equal(b.ExpiresAt) {
		return ErrDenied
	}
	if o.ConfigurationAuthority.Validate(b.Owner.Spec().TenantID, b.ConfigurationAuthority.ConfigurationID) != nil || o.ConfigurationAuthority.Version < b.ConfigurationAuthority.Version {
		return ErrDenied
	}
	ownerEpochsPresent := o.GlobalVersion > 0 && o.TenantVersion > 0 && o.UserVersion > 0 && o.UserAuthorityVersion > 0 && o.AuthorizationVersion > 0
	if !ownerEpochsPresent || o.PolicyVersion == 0 || !validPermissions(o.Grant) {
		return ErrDenied
	}
	for _, permission := range b.Grant {
		if !slices.Contains(o.Record.Grant, permission) {
			return ErrDenied
		}
	}
	for _, permission := range o.Grant {
		if !slices.Contains(b.Grant, permission) {
			return ErrDenied
		}
	}
	profile := c.Spec()
	deadline := o.ReadStartedAt.Add(20*time.Second - profile.ClockUncertainty - profile.DecisionRaceBudget).Truncate(time.Microsecond)
	readTimesValid := !now.IsZero() && !o.ReadStartedAt.IsZero() && !o.VerifiedAt.Before(o.ReadStartedAt) && !o.VerifiedAt.After(now) && o.VerifiedAt.Sub(o.ReadStartedAt) <= profile.MaximumRead
	if !readTimesValid || !o.VerifiedAt.Before(o.ValidUntil) {
		return ErrDenied
	}
	exceedsSourceExpiry := !b.ExpiresAt.IsZero() && o.ValidUntil.After(b.ExpiresAt)
	if o.ValidUntil.After(deadline) || exceedsSourceExpiry || !now.Before(o.ValidUntil) {
		return ErrDenied
	}
	return nil
}

func (SourceAuthorityBinding) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.SourceAuthorityBinding(redacted)")
}
func (SourceAuthorityBinding) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (SourceAuthorityObservation) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.SourceAuthorityObservation(redacted)")
}
func (SourceAuthorityObservation) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
