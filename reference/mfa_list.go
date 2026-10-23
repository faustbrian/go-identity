package reference

import (
	"context"
	"time"

	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
)

// Both selections share one public inventory and one original session budget.
// Existing TOTP-only deployments retain their original policy/reader unchanged.
func mfaListingProfile(c StoreConfiguration) (*kernel.CommandQueryPolicy, time.Duration) {
	var policy *kernel.CommandQueryPolicy
	var budget time.Duration
	if c.MFAEnrollment != nil && c.MFAEnrollment.Listing {
		policy, budget = c.MFAEnrollment.Native.Coordinator.QueryPolicy, c.MFAEnrollment.Native.MaximumDuration
	}
	if c.MFAOTPEnrollment != nil && c.MFAOTPEnrollment.Listing {
		if budget == 0 {
			policy, budget = c.MFAOTPEnrollment.Native.Coordinator.QueryPolicy, c.MFAOTPEnrollment.Native.MaximumDuration
		} else {
			budget = min(budget, c.MFAOTPEnrollment.Native.MaximumDuration)
		}
	}
	return policy, budget
}

func composeMFAListing(c StoreConfiguration, owner *mfaEnrollmentState, otp *mfaOTPEnrollmentState, sessions *sessionState) (*mfa.ListService, error) {
	selectedTOTP := c.MFAEnrollment != nil && c.MFAEnrollment.Listing
	selectedOTP := c.MFAOTPEnrollment != nil && c.MFAOTPEnrollment.Listing
	if !selectedTOTP && !selectedOTP {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_mfa_list"}
	if sessions == nil || sessions.reader == nil || selectedTOTP && (owner == nil || owner.enable == nil) || selectedOTP && (otp == nil || otp.enable == nil) {
		return nil, invalid
	}
	var reader mfa.FactorListReader
	var err error
	if selectedOTP {
		reader, err = mfapg.NewOTPListReader(otp.enable)
		if owner != nil && owner.manage != nil {
			reader, err = mfapg.NewOTPManagementListReader(otp.enable, owner.manage)
		}
	} else {
		reader, err = mfapg.NewTOTPListReader(owner.enable)
		if owner.manage != nil {
			reader, err = mfapg.NewTOTPManagementListReader(owner.manage)
		}
	}
	if err != nil {
		return nil, invalid
	}
	policy, budget := mfaListingProfile(c)
	if policy == nil {
		return nil, invalid
	}
	listing, err := mfa.NewListService(sessions.reader, reader, mfa.ListConfig{Authorization: policy.Authorization, Clock: policy.Clock, PolicyRevision: authorization.Revision(policy.PolicyVersion), MaximumDuration: budget})
	if err != nil {
		return nil, invalid
	}
	return listing, nil
}

// MFAListing returns explicitly selected native safe factor/recovery metadata.
// It borrows the graph's actual session owner, requires graph initialization and
// exact tenant selection on every call, and denies permanently after Close.
// This selects no HTTP route, security-key listing or trusted-device issuance.
func (f FeatureSet) MFAListing() (mfa.FactorListingService, error) {
	if f.state == nil {
		return nil, identity.InvalidInputError{Field: "reference_mfa_list"}
	}
	f.state.mu.Lock()
	defer f.state.mu.Unlock()
	if f.state.closed || f.state.features == nil || !f.state.features.composed || f.state.features.mfaListing == nil {
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
	return f.state.features.mfaListing.List(w, r)
}
