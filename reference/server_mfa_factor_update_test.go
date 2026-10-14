package reference

import "testing"

func TestFactorUpdateHTTPRequiresSelectedNativeOwners(t *testing.T) {
	if state, err := composeMFAFactorUpdateHTTP(StoreConfiguration{}, ReferenceDependencies{}, nil, nil); err != nil || state != nil {
		t.Fatal("unselected factor management acquired HTTP authority")
	}
	c := StoreConfiguration{HTTPMFAFactorUpdate: &HTTPMFAFactorUpdateConfiguration{}}
	if state, err := composeMFAFactorUpdateHTTP(c, ReferenceDependencies{}, nil, nil); err == nil || state != nil {
		t.Fatal("HTTP factor management invented native owners")
	}
	if err := (&storeState{}).composeFeatureStores(c, ReferenceDependencies{}); err == nil {
		t.Fatal("selected management disappeared in an incomplete graph")
	}
}
