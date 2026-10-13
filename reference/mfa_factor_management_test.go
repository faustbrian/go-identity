package reference

import (
	"testing"

	mfapg "github.com/faustbrian/go-identity/mfa/postgres"
	"github.com/faustbrian/go-identity/risk"
)

func TestMFAFactorManagementSelectionCannotInventOwners(t *testing.T) {
	if service, err := (FeatureSet{}).MFAFactorManagement(); err == nil || service != nil {
		t.Fatal("unselected graph acquired factor management")
	}
	c := StoreConfiguration{MFAEnrollment: &MFAEnrollmentConfiguration{FactorManagement: &mfapg.FactorUpdateConfig{}}}
	if owner, err := composeMFAEnrollment(c, ReferenceDependencies{}, nil, risk.Evaluator{}, nil); err == nil || owner != nil {
		t.Fatal("management selection invented primary or persistence owners")
	}
}
