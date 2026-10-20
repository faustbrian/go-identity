package identityhttp_test

import (
	"net/http"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestPhoneEnrollmentSelectsNativeStoredSynchronizer(t *testing.T) {
	for _, operation := range []string{"identity.phone.send-verification", "identity.phone.verify", "identity.phone.verify.recover", "identity.phone.update", "identity.phone.update.recover"} {
		for _, row := range []struct {
			name  string
			csrf  identityhttp.CSRFPolicy
			valid bool
		}{
			{"stored", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, true},
			{"no-csrf", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, false},
			{"other-header", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "Other-Token", RefererFallback: identityhttp.RefererFallbackDeny}, false},
			{"independent-age", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", TokenMaximumAge: time.Minute, RefererFallback: identityhttp.RefererFallbackDeny}, false},
			{"referer", identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackSameOriginHTTPS}, false},
		} {
			t.Run(operation+"/"+row.name, func(t *testing.T) {
				op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/phone", OperationID: operation, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: row.csrf, MaximumSerializedBytes: 16384})
				if err == nil {
					_, err = identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/phone", Operations: []identityhttp.OperationDescriptor{op}})
				}
				if (err == nil) != row.valid {
					t.Fatal("phone selection lost native stored-token policy or admitted a weaker stored-token declaration", err)
				}
			})
		}
	}
}
