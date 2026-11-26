package identityhttp_test

import (
	"net/http"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestSCIMConnectionCreateStrictBearerProfilePreservesCanonicalPolicy(t *testing.T) {
	const create = "identity.scim.connection-create"
	cfg := identityhttp.CanonicalOperationConfig{
		Owner: "scim", OperationID: create, Handler: http.NotFoundHandler(), MaximumSerializedBytes: 4096,
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionOriginAndToken, TokenHeader: "X-CSRF-Token", TokenMaximumAge: time.Minute, RefererFallback: identityhttp.RefererFallbackDeny},
	}
	cookie, err := identityhttp.NewCanonicalOperation(cfg)
	if err != nil || cookie.Route.CSRF != cfg.CSRF {
		t.Fatal("canonical cookie transport lost its original CSRF requirements", err)
	}
	cfg.CSRF = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}
	bearer, err := identityhttp.NewCanonicalOperation(cfg)
	if err != nil {
		t.Fatal("explicit strict-bearer Create profile unavailable", err)
	}
	if bearer.Route.CSRF != cfg.CSRF || bearer.Record.RatePolicy != "rate.admin" || bearer.Record.Idempotency != "keyed" || bearer.Record.Authorization != cookie.Record.Authorization || bearer.Route.Method != http.MethodPost || bearer.Route.Path != "/v1/scim/connection-create" {
		t.Fatal("explicit bearer transport changed Create admission, authority or request custody")
	}
	for _, name := range []string{"identity.scim.connection-update", "identity.scim.connection-rotate", "identity.scim.connection-delete"} {
		cfg.OperationID = name
		if _, err := identityhttp.NewCanonicalOperation(cfg); err == nil {
			t.Errorf("unrelated SCIM mutation %s accepted the Create-specific profile", name)
		}
	}
}
