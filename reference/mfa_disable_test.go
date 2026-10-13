package reference

import (
	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/risk"
	"testing"
)

func TestDisableSelectionCannotInventNativeOwners(t *testing.T) {
	if service, err := (FeatureSet{}).MFADisable(); err == nil || service != nil {
		t.Fatal("unselected graph invented disable")
	}
	c := StoreConfiguration{MFAEnrollment: &MFAEnrollmentConfiguration{Disable: &mfapg.DisableConfig{}}}
	if owner, err := composeMFAEnrollment(c, ReferenceDependencies{}, nil, risk.Evaluator{}, nil); err == nil || owner != nil {
		t.Fatal("disable selection invented native recovery/primary owners")
	}
	c = StoreConfiguration{HTTPMFADisable: &HTTPMFADisableConfiguration{}}
	if graph, err := ComposeStores(c, ReferenceDependencies{}); err == nil {
		_ = graph.Close(t.Context())
		t.Fatal("HTTP disable manufactured native dependencies")
	}
}
