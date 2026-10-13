package reference

import (
	"context"

	"github.com/faustbrian/go-authorization"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
)

func composeMFAListing(c StoreConfiguration, owner *mfaEnrollmentState, sessions *sessionState) error {
	if c.MFAEnrollment == nil || !c.MFAEnrollment.Listing {
		return nil
	}
	invalid := identity.InvalidInputError{Field: "reference_mfa_list"}
	if owner == nil || owner.enable == nil || sessions == nil || sessions.reader == nil {
		return invalid
	}
	reader, err := mfapg.NewTOTPListReader(owner.enable)
	if err != nil {
		return invalid
	}
	policy := c.MFAEnrollment.Native.Coordinator.QueryPolicy
	if policy == nil {
		return invalid
	}
	owner.listing, err = mfa.NewListService(sessions.reader, reader, mfa.ListConfig{Authorization: policy.Authorization, Clock: policy.Clock, PolicyRevision: authorization.Revision(policy.PolicyVersion), MaximumDuration: c.MFAEnrollment.Native.MaximumDuration})
	if err != nil {
		return invalid
	}
	return nil
}

// MFAListing returns explicitly selected native safe TOTP/recovery metadata.
// It borrows the graph's actual session owner, requires graph initialization and
// exact tenant selection on every call, and denies permanently after Close.
// This selects no HTTP route, security-key listing or trusted-device issuance.
func (f FeatureSet) MFAListing() (mfa.FactorListingService, error) {
	if err := f.mfaEnrollmentSelected(); err != nil {
		return nil, err
	}
	if f.state.features.mfaEnrollment.listing == nil {
		return nil, identity.UnavailableError{}
	}
	return composedMFAListing{state: f.state}, nil
}

type composedMFAListing struct{ state *storeState }

func (f composedMFAListing) List(ctx context.Context, r mfa.ListRequest) (mfa.ListResult, error) {
	w, done, err := (composedPasswordReset{state: f.state}).enter(ctx, r.TenantID)
	if err != nil {
		return mfa.ListResult{}, err
	}
	defer done()
	return f.state.features.mfaEnrollment.listing.List(w, r)
}
