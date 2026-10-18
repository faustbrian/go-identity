package identityhttp_test

import (
	"net/http"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestUsernameRenameSelectsOnlyNativeStoredSynchronizerProfile(t *testing.T) {
	for _, row := range []struct {
		name   string
		policy identityhttp.CSRFPolicy
		valid  bool
	}{
		{"original-state", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, true},
		{"no-csrf", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, false},
		{"origin-only", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, false},
		{"other-header", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "Other-Token", RefererFallback: identityhttp.RefererFallbackDeny}, false},
		{"independent-age", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", TokenMaximumAge: time.Minute, RefererFallback: identityhttp.RefererFallbackDeny}, false},
		{"referer", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackSameOriginHTTPS}, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/username", OperationID: "identity.username.update", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: row.policy, MaximumSerializedBytes: 16384})
			if err == nil {
				_, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/username", Operations: []identityhttp.OperationDescriptor{op}})
			}
			if (err == nil) != row.valid {
				t.Fatal("username rename selection accepted a weaker or rejected the original stored-token profile", err)
			}
		})
	}
}
