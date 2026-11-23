package identityhttp_test

import (
	"net/http"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestDeviceDecisionSelectionRequiresOriginalSessionSynchronizer(t *testing.T) {
	owned := identityhttp.CSRFPolicy{
		Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token",
		RefererFallback: identityhttp.RefererFallbackDeny,
	}
	for _, action := range []string{"device-approve", "device-deny"} {
		t.Run(action, func(t *testing.T) {
			c := identityhttp.CanonicalOperationConfig{
				Owner: "oauth-server/device", OperationID: "identity.oauth-server." + action,
				Handler: http.NotFoundHandler(), MaximumSerializedBytes: 4096, CSRF: owned,
			}
			op, err := identityhttp.NewCanonicalOperation(c)
			if err != nil || op.Route.CSRF != owned {
				t.Fatal("device decision cannot retain its original session synchronizer", err)
			}
			for _, alternate := range []identityhttp.CSRFPolicy{
				{Mode: identityhttp.CSRFNone},
				{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
				{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-Other", RefererFallback: identityhttp.RefererFallbackDeny},
				{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackSameOriginHTTPS},
			} {
				c.CSRF = alternate
				if _, err := identityhttp.NewCanonicalOperation(c); err == nil {
					t.Fatal("device decision admitted a different transport authority")
				}
			}
		})
	}
}
