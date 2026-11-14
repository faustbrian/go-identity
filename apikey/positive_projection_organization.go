package apikey

import (
	"context"
	"fmt"
	"io"
	"slices"

	identity "github.com/faustbrian/go-identity"
)

// OrganizationProjectionAuthorityReader observes an already authenticated
// organization credential through the real primary owner. It does not verify
// a bearer, debit quota or grant the creator human authority. Original source
// and organization read/deadline timestamps must remain unchanged.
type OrganizationProjectionAuthorityReader interface {
	ObserveOrganizationSourceAuthority(context.Context, OrganizationSourceAuthorityBinding) (OrganizationSourceAuthorityObservation, error)
}

// NewOrganizationPositiveProjectionCodec explicitly selects modern organization
// metadata. c.Authority must be nil; organization must be the nonnil real current
// organization source. All other configuration and borrowed ownership contracts
// are identical to NewPositiveProjectionCodec. Mixed reader selection fails;
// this never enables USER, legacy, cached authentication or quota authority.
func NewOrganizationPositiveProjectionCodec(c PositiveProjectionConfig, organization OrganizationProjectionAuthorityReader) (*PositiveProjectionCodec, error) {
	if projectionNil(organization) || !projectionNil(c.Authority) {
		return nil, ErrInvalid
	}
	return newPositiveProjectionCodec(c, organization)
}

// OrganizationPositiveProjectionLookup is nonsecret organization metadata from
// one actual source invocation. The aggregate and credential epochs are distinct:
// membership changes cannot fabricate a human or revoke integration ownership.
// It grants no authority. Transports must namespace/hash rather than log it.
type OrganizationPositiveProjectionLookup struct {
	TenantID                                                                   identity.TenantID
	ConfigurationID                                                            string
	ConfigurationRevision                                                      uint64
	KeyID, RootID                                                              KeyID
	KeyAuthorityVersion, RootVersion                                           uint64
	OwnerKind                                                                  OwnerKind
	OrganizationID                                                             OrganizationID
	OrganizationVersion, OrganizationCredentialVersion                         uint64
	ConfigurationAuthorityVersion, GlobalVersion, TenantVersion, PolicyVersion uint64
	Issuer, Environment, Audience                                              string
}

// Format emits a constant redacted label without owner, root or epoch values.
func (OrganizationPositiveProjectionLookup) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "apikey.OrganizationPositiveProjectionLookup(redacted)")
}

// MarshalJSON rejects implicit export; trusted transports own explicit projections.
func (OrganizationPositiveProjectionLookup) MarshalJSON() ([]byte, error) { return nil, ErrDisclosure }

// OrganizationLookup returns the exact organization metadata admitted by this
// invocation. Zero and USER admissions fail; Lookup separately remains USER-only.
func (a PositiveProjectionAdmission) OrganizationLookup() (OrganizationPositiveProjectionLookup, error) {
	if a.state == nil || a.state.organization == nil {
		return OrganizationPositiveProjectionLookup{}, ErrInvalid
	}
	return *a.state.organization, nil
}

type organizationProjectionLookupRecord OrganizationPositiveProjectionLookup

func sameOrganizationProjectionLookup(stored *organizationProjectionLookupRecord, current *OrganizationPositiveProjectionLookup) bool {
	if stored == nil || current == nil {
		return stored == nil && current == nil
	}
	return OrganizationPositiveProjectionLookup(*stored) == *current
}

func (c *PositiveProjectionCodec) admitOrganization(ctx context.Context, request AtomicVerificationRequest, out AtomicVerificationResult) (PositiveProjectionAdmission, AtomicVerificationResult, error) {
	result := *out.Result
	binding, err := NewOrganizationSourceAuthorityBinding(result, c.config.Configuration, result.VerifiedAt)
	if err != nil {
		out.Result = nil
		return PositiveProjectionAdmission{}, out, ErrDenied
	}
	observed, err := c.organizationAuthority.ObserveOrganizationSourceAuthority(ctx, binding)
	if err != nil || observed.Validate(binding, c.config.Configuration, observed.VerifiedAt) != nil {
		out.Result = nil
		return PositiveProjectionAdmission{}, out, ErrDenied
	}
	start := minProjectionTime(result.ReadStartedAt, minProjectionTime(observed.ReadStartedAt, observed.OrganizationReadStartedAt))
	until := minProjectionTime(result.ValidUntil, minProjectionTime(observed.ValidUntil, observed.OrganizationValidUntil))
	grant := projectionIntersection(result.Grant, observed.Grant)
	now := c.config.Clock.Now()
	if ctx.Err() != nil || now.Before(start) || !now.Before(until) || !until.After(result.VerifiedAt) || !projectionSubset(request.RequiredPermissions, grant) {
		out.Result = nil
		return PositiveProjectionAdmission{}, out, ErrDenied
	}
	// Begin itself is public. Once newer current authority is obtained it cannot
	// expose the earlier broader principal while waiting for optional Complete.
	// Keep the verifier's original receipt/quota/times and borrowed result intact.
	out = cloneProjectionResult(out)
	out.Result.Grant, out.Result.ValidUntil = slices.Clone(grant), until
	owner := observed.Owner.Spec()
	lookup := OrganizationPositiveProjectionLookup{TenantID: owner.TenantID, ConfigurationID: result.Record.ConfigurationID, ConfigurationRevision: result.Record.ConfigurationRevision, KeyID: result.Record.ID, RootID: result.Record.RootID, KeyAuthorityVersion: result.Record.AuthorityVersion, RootVersion: result.Record.RootVersion, OwnerKind: owner.Kind, OrganizationID: owner.OrganizationID, OrganizationVersion: observed.OrganizationVersion, OrganizationCredentialVersion: observed.OrganizationCredentialVersion, ConfigurationAuthorityVersion: observed.ConfigurationAuthority.Version, GlobalVersion: observed.GlobalVersion, TenantVersion: observed.TenantVersion, PolicyVersion: observed.PolicyVersion, Issuer: result.Record.Issuer, Environment: result.Record.Environment, Audience: result.Record.Audience}
	a := &positiveProjectionAdmission{owner: c, result: cloneProjectionResult(out), organization: &lookup, grant: grant, required: slices.Clone(request.RequiredPermissions), start: start, until: until}
	return PositiveProjectionAdmission{state: a}, out, nil
}
