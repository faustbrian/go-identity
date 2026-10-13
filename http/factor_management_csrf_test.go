package identityhttp

import (
	"net/http"
	"testing"
)

func TestFactorManagementStoredCSRFSelectionIsExact(t *testing.T) {
	config := CanonicalOperationConfig{Owner: "identity/mfa", OperationID: "identity.mfa.factor-update", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: CSRFPolicy{Mode: CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: RefererFallbackDeny}, MaximumSerializedBytes: 4096}
	if _, err := NewCanonicalOperation(config); err != nil {
		t.Fatal("owned stored-session CSRF profile rejected", err)
	}
	for _, policy := range []CSRFPolicy{{Mode: CSRFNone}, {Mode: CSRFExactOrigin, RefererFallback: RefererFallbackDeny}, {Mode: CSRFSessionState, TokenHeader: "X-Other", RefererFallback: RefererFallbackDeny}} {
		bad := config
		bad.CSRF = policy
		if _, err := NewCanonicalOperation(bad); err == nil {
			t.Fatal("MFA mutation accepted missing or alternate CSRF custody")
		}
	}
}
