package identityhttp_test

import (
	"net/http"
	"net/http/httptest"
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
		for _, id := range []string{"identity.password.set", "identity.password.reset-complete"} {
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

// Verification has a real bearer-only handler. This selection test exercises
// routing, not authentication: the optional factory owns credential validation.
func TestPasswordVerificationSelectsBearerOnly(t *testing.T) {
	calls := 0
	c := identityhttp.CanonicalOperationConfig{Owner: "identity/password", OperationID: "identity.password.verify", Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusAccepted)
	}), CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16384}
	op, err := identityhttp.NewCanonicalOperation(c)
	if err != nil {
		t.Fatalf("explicit verification bearer profile rejected: %v", err)
	}
	if op.Record.Idempotency != "none" || op.Record.RatePolicy != "rate.verify" || op.Record.CSRFOrigin != c.CSRF || op.Record.RequestSchema.Digest == ([32]byte{}) {
		t.Fatal("verification contract changed")
	}
	for _, mutate := range []func(*identityhttp.OperationDescriptor){
		func(v *identityhttp.OperationDescriptor) { v.Record.Idempotency = "keyed" },
		func(v *identityhttp.OperationDescriptor) { v.Record.RatePolicy = "rate.secret" },
		func(v *identityhttp.OperationDescriptor) { v.Record.Authorization.Policy = "anonymous" },
		func(v *identityhttp.OperationDescriptor) { v.Record.RequestSchema.Digest[0] ^= 1 },
		func(v *identityhttp.OperationDescriptor) { v.Record.HandlerOwner = "identity/session" },
	} {
		bad := op
		mutate(&bad)
		if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: c.Owner, Operations: []identityhttp.OperationDescriptor{bad}}); err == nil {
			t.Fatal("verification canonical contract override admitted")
		}
	}
	f, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: c.Owner, Operations: []identityhttp.OperationDescriptor{op}})
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/password/verify", nil))
	if w.Code != http.StatusAccepted || calls != 1 {
		t.Fatal("selected handler not dispatched exactly once")
	}
	disabled, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	disabled.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/password/verify", nil))
	if w.Code != http.StatusNotFound || calls != 1 {
		t.Fatal("disabled verification exposed handler")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/password/change", nil))
	if w.Code != http.StatusNotFound || calls != 1 {
		t.Fatal("verification selected sibling operation")
	}
	canonical := c
	canonical.CSRF = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionOriginAndToken, TokenHeader: "X-CSRF-Token", TokenMaximumAge: time.Minute, RefererFallback: identityhttp.RefererFallbackDeny}
	if _, err := identityhttp.NewCanonicalOperation(canonical); err != nil {
		t.Fatal("existing canonical metadata profile rejected")
	}
	for _, policy := range []identityhttp.CSRFPolicy{
		{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
		{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny},
		{Mode: identityhttp.CSRFNone, TokenHeader: "X-CSRF-Token"},
		{Mode: identityhttp.CSRFNone, TokenMaximumAge: time.Minute},
		{Mode: identityhttp.CSRFNone, RefererFallback: identityhttp.RefererFallbackDeny},
	} {
		invalid := c
		invalid.CSRF = policy
		if _, err := identityhttp.NewCanonicalOperation(invalid); err == nil {
			t.Fatal("unsupported verification profile admitted")
		}
	}
	invalid := c
	invalid.Owner = "identity/session"
	if _, err := identityhttp.NewCanonicalOperation(invalid); err == nil {
		t.Fatal("foreign verification owner admitted")
	}
}
