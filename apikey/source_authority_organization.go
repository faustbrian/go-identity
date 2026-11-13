package apikey

import (
	"fmt"
	"io"
	"slices"
	"time"
)

// OrganizationSourceAuthorityBinding retains the nonsecret immutable ceiling of
// an already authenticated modern organization-owned key. Its underlying fields
// match SourceAuthorityBinding, but its distinct type cannot select the USER
// observation or silently turn the creator into a human principal. The actual
// AtomicVerifier authenticates the bearer; neither this value nor its validation
// grants authentication, permission, or current organization authority.
type OrganizationSourceAuthorityBinding SourceAuthorityBinding

// NewOrganizationSourceAuthorityBinding snapshots a still-fresh actual verifier
// result without retaining a bearer or borrowing its mutable grant. Configuration
// is server-selected; legacy organization exchange is not selected by this API.
// Invalid, expired or differently owned results return a zero binding and error.
func NewOrganizationSourceAuthorityBinding(r VerificationResult, c Configuration, now time.Time) (OrganizationSourceAuthorityBinding, error) {
	if r.ValidateAt(c, now) != nil {
		return OrganizationSourceAuthorityBinding{}, ErrDenied
	}
	b := OrganizationSourceAuthorityBinding(sourceAuthorityBinding(r))
	if err := b.Validate(c); err != nil {
		return OrganizationSourceAuthorityBinding{}, err
	}
	return b, nil
}

// Validate checks only modern organization-owner shape and the exact selected
// profile. It does not authenticate a secret or read current owner/key state.
// Mutable fields remain borrowed until the invoking bounded call returns.
func (b OrganizationSourceAuthorityBinding) Validate(c Configuration) error {
	if c.Spec().Algorithm != AlgorithmModernHMACSHA256 {
		return ErrInvalid
	}
	return SourceAuthorityBinding(b).validate(c, OwnerOrganization)
}

// OrganizationSourceAuthorityObservation is a distinct uncached primary read of
// a previously authenticated integration root. OrganizationVersion fences the
// current aggregate, independently of OrganizationCredentialVersion, whose exact
// match to the key owner prevents archive/restore from resurrecting credentials.
// A creator/member epoch is deliberately absent: human management/delegation
// needs its own actual member authority and is not granted by this observation.
// No bearer authentication, quota debit, principal issuance or mutation occurs.
// Organization timestamps retain that owner's original application-clock read;
// the outer timestamps belong to the native primary database clock. Preserve
// both domains without retiming or requiring exact interval nesting. Copying and
// retries cannot renew either window; the earliest original deadline wins.
type OrganizationSourceAuthorityObservation struct {
	Binding                                                                   OrganizationSourceAuthorityBinding
	Record                                                                    Record
	Owner                                                                     Owner
	Grant                                                                     []string
	PolicyVersion                                                             uint64
	ConfigurationAuthority                                                    ConfigurationAuthorityBinding
	GlobalVersion                                                             uint64
	TenantVersion                                                             uint64
	OrganizationVersion                                                       uint64
	OrganizationCredentialVersion                                             uint64
	ReadStartedAt, VerifiedAt, ValidUntil                                     time.Time
	OrganizationReadStartedAt, OrganizationVerifiedAt, OrganizationValidUntil time.Time
}

// Validate checks exact source bindings, non-expanding current grants and the
// original bounded read window. Only the trusted native owner can supply these
// facts and fence current storage in the protected Work. Structural validity
// alone never proves the observation's provenance or grants authority.
func (o OrganizationSourceAuthorityObservation) Validate(b OrganizationSourceAuthorityBinding, c Configuration, now time.Time) error {
	if b.Validate(c) != nil || !sameSourceBinding(SourceAuthorityBinding(o.Binding), SourceAuthorityBinding(b)) || o.Record.Validate(c) != nil {
		return ErrDenied
	}
	ownerMatches := o.Owner.Validate() == nil && o.Owner == b.Owner && o.Record.Owner == b.Owner && o.Owner.Version() == o.OrganizationCredentialVersion
	rootMatches := o.Record.ID == b.KeyID && o.Record.RootID == b.RootID && o.Record.RootVersion == b.RootVersion && o.Record.AuthorityVersion == b.AuthorityVersion
	if !ownerMatches || !rootMatches || o.Record.Status != KeyActive || !o.Record.ExpiresAt.Equal(b.ExpiresAt) {
		return ErrDenied
	}
	if o.ConfigurationAuthority.Validate(b.Owner.Spec().TenantID, b.ConfigurationAuthority.ConfigurationID) != nil || o.ConfigurationAuthority.Version < b.ConfigurationAuthority.Version {
		return ErrDenied
	}
	if o.GlobalVersion == 0 || o.TenantVersion == 0 || o.OrganizationVersion == 0 || o.OrganizationCredentialVersion == 0 || o.PolicyVersion == 0 || !validPermissions(o.Grant) {
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
	// The real owner validates its own clock at observation/fencing. Here check
	// its original interval and earliest-deadline cap, not wall/DB coincidence.
	ownerWindowValid := !o.OrganizationReadStartedAt.IsZero() && !o.OrganizationVerifiedAt.Before(o.OrganizationReadStartedAt) && o.OrganizationVerifiedAt.Before(o.OrganizationValidUntil) && !o.OrganizationValidUntil.After(o.OrganizationReadStartedAt.Add(20*time.Second)) && !o.ValidUntil.After(o.OrganizationValidUntil)
	if !ownerWindowValid {
		return ErrDenied
	}
	deadline := o.ReadStartedAt.Add(20*time.Second - profile.ClockUncertainty - profile.DecisionRaceBudget).Truncate(time.Microsecond)
	readTimesValid := !now.IsZero() && !o.ReadStartedAt.IsZero() && !o.VerifiedAt.Before(o.ReadStartedAt) && !o.VerifiedAt.After(now) && o.VerifiedAt.Sub(o.ReadStartedAt) <= profile.MaximumRead
	if !readTimesValid || !o.VerifiedAt.Before(o.ValidUntil) || o.ValidUntil.After(deadline) || o.ValidUntil.After(b.ExpiresAt) || !now.Before(o.ValidUntil) {
		return ErrDenied
	}
	return nil
}

func (OrganizationSourceAuthorityBinding) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.OrganizationSourceAuthorityBinding(redacted)")
}
func (OrganizationSourceAuthorityBinding) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }
func (OrganizationSourceAuthorityObservation) Format(s fmt.State, _ rune) {
	io.WriteString(s, "apikey.OrganizationSourceAuthorityObservation(redacted)")
}
func (OrganizationSourceAuthorityObservation) MarshalJSON() ([]byte, error) {
	return nil, ErrDisclosure
}
