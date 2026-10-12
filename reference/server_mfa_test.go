package reference

import "testing"

func TestMFATransportRequiresExplicitNativeSelection(t *testing.T) {
	if h, err := composeMFAHTTP(StoreConfiguration{}, nil, nil); err != nil || h != nil {
		t.Fatal("unselected HTTP acquired owners", err)
	}
	c := StoreConfiguration{HTTPMFA: &HTTPMFAConfiguration{TOTPVerify: true}}
	if h, err := composeMFAHTTP(c, nil, nil); err == nil || h != nil {
		t.Fatal("unconfigured MFA HTTP exposed completion")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("selected MFA silently disappeared in recovery-only graph")
	}
}
