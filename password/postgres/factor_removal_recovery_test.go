package passwordpostgres

import "testing"

func TestFactorRemovalRecoveryRequiresNativeRequestAndCompletion(t *testing.T) {
	for _, service := range []*ResetService{nil, {}, {request: &resetRequestRuntime{}}} {
		if source, err := NewFactorRemovalRecoverySource(service); err == nil || source != nil {
			t.Fatal("missing native email recovery became removal authority")
		}
	}
}
