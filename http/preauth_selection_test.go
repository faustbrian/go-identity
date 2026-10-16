package identityhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestCanonicalConditionalSelectsExactOriginPreAuthOnly(t *testing.T) {
	c := identityhttp.CanonicalOperationConfig{Owner: "identity/otp", OperationID: "identity.otp.send", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }), CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384}
	op, err := identityhttp.NewCanonicalOperation(c)
	if err != nil {
		t.Fatal("pre-auth-only selection rejected", err)
	}
	if op.Record.CSRFOrigin.Mode != identityhttp.CSRFExactOrigin || op.Record.Idempotency != "keyed" || op.Record.RatePolicy != "rate.delivery" || op.Record.RequestSchema.Digest == ([32]byte{}) {
		t.Fatal("canonical contract rewritten")
	}
	f, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "identity/otp", Operations: []identityhttp.OperationDescriptor{op}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/otp/send", nil))
	if w.Code != 202 {
		t.Fatal("selected handler missing")
	}
	for _, policy := range []identityhttp.CSRFPolicy{{Mode: identityhttp.CSRFNone}, {Mode: identityhttp.CSRFSessionState, TokenHeader: "Wrong-Token", RefererFallback: identityhttp.RefererFallbackDeny}, {Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackSameOriginHTTPS}} {
		invalid := c
		invalid.CSRF = policy
		if _, err := identityhttp.NewCanonicalOperation(invalid); err == nil {
			t.Fatal("unsupported conditional substitution admitted")
		}
	}
	invalid := c
	invalid.OperationID = "identity.session.refresh"
	invalid.Owner = "identity/session"
	if _, err := identityhttp.NewCanonicalOperation(invalid); err == nil {
		t.Fatal("session mutation downgraded to origin-only")
	}
}
