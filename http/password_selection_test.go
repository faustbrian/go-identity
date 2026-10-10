package identityhttp_test

import (
	"net/http"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

// Risk plan: select only actual password-change bearer/stored-token variants;
// preserve canonical owner/key/rate/schema bindings and do not broaden other
// password/secret rows. Handler enforcement belongs to the optional factory,
// whose native composition is independently tested; metadata grants no authority.
func TestPasswordChangeAllowsExplicitCredentialProfiles(t *testing.T) {
	for _, policy := range []identityhttp.CSRFPolicy{
		{Mode: identityhttp.CSRFNone},
		{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny},
	} {
		c := identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.change", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: policy, MaximumSerializedBytes: 16384}
		op, err := identityhttp.NewCanonicalOperation(c)
		if err != nil {
			t.Fatalf("explicit password credential profile rejected: %v", err)
		}
		if op.Record.Idempotency != "keyed" || op.Record.RatePolicy != "rate.secret" || op.Record.CSRFOrigin != policy || op.Record.RequestSchema.Digest == ([32]byte{}) {
			t.Fatal("canonical mutation contract changed")
		}
		if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: c.Owner, Operations: []identityhttp.OperationDescriptor{op}}); err != nil {
			t.Fatal(err)
		}
		for _, id := range []string{"identity.password.verify", "identity.password.set", "identity.password.reset-complete"} {
			invalid := c
			invalid.OperationID = id
			if _, err := identityhttp.NewCanonicalOperation(invalid); err == nil {
				t.Fatalf("profile silently broadened %s", id)
			}
		}
		invalid := c
		invalid.Owner = "identity/session"
		if _, err := identityhttp.NewCanonicalOperation(invalid); err == nil {
			t.Fatal("foreign owner admitted")
		}
	}
	for _, policy := range []identityhttp.CSRFPolicy{
		{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
		{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", TokenMaximumAge: time.Minute, RefererFallback: identityhttp.RefererFallbackDeny},
		{Mode: identityhttp.CSRFSessionState, RefererFallback: identityhttp.RefererFallbackDeny},
	} {
		if _, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.change", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: policy, MaximumSerializedBytes: 16384}); err == nil {
			t.Fatal("unsupported password protection admitted")
		}
	}
}
