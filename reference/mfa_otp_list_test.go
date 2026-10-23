package reference

import (
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/mfa"
)

func TestOTPListingRetainsSelectionAndGraphLifetime(t *testing.T) {
	c := StoreConfiguration{MFAOTPEnrollment: &MFAOTPEnrollmentConfiguration{Listing: true}}
	if _, err := composeMFAListing(c, nil, nil, nil); err == nil {
		t.Fatal("OTP listing invented missing native authority")
	}
	_, _, graph := serverFixture(t)
	if listing, err := graph.MFAListing(); err == nil || listing != nil {
		t.Fatal("unselected graph exported factor inventory")
	}
	graph.state.features.mfaListing = &mfa.ListService{}
	listing, err := graph.MFAListing()
	if err != nil {
		t.Fatal(err)
	}
	deny := func(tenant identity.TenantID) {
		t.Helper()
		if out, err := listing.List(t.Context(), mfa.ListRequest{TenantID: tenant}); err == nil || len(out.Factors) != 0 || out.RecoveryCodeCount != 0 {
			t.Fatal("unadmitted graph disclosed inventory")
		}
	}
	deny("tenant")
	graph.state.features.ready = true
	deny("foreign")
	graph.state.closed = true
	deny("tenant")
	if listing, err := graph.MFAListing(); err == nil || listing != nil {
		t.Fatal("closed graph exported inventory")
	}
}
