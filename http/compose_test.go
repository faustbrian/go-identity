package identityhttp_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestSelectedDispatchExactPathsAndMethods(t *testing.T) {
	var calls atomic.Int32
	op := extensionDescriptor(t, "selected", "read")
	op.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.Write([]byte("selected")) })
	f := feature(t, "selected", nil, op)
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", op.Route.Path, 200},
		{"HEAD", op.Route.Path, 405},
		{"POST", op.Route.Path, 405},
		{"OPTIONS", op.Route.Path, 405},
		{"GET", op.Route.Path + "/", 404},
		{"GET", "/extensions//selected/read", 404},
		{"GET", "/extensions/selected/./read", 404},
		{"GET", "/extensions/selected/%72ead", 404},
		{"GET", op.Route.Path + "extra", 404},
	} {
		before := calls.Load()
		w := httptest.NewRecorder()
		r := httptest.NewRequest(tc.method, tc.path, nil)
		h.ServeHTTP(w, r)
		if w.Code != tc.status || w.Header().Get("Location") != "" {
			t.Fatalf("dispatch status=%d wanted=%d", w.Code, tc.status)
		}
		if tc.status != 200 {
			if calls.Load() != before || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("dispatcher denial invoked handler or lost safe headers")
			}
			if tc.status == 405 && w.Header().Get("Allow") != "GET" {
				t.Fatal("wrong allowed methods")
			}
			if tc.method == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("implicit HEAD or HEAD error body")
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w := httptest.NewRecorder()
	before := calls.Load()
	h.ServeHTTP(w, httptest.NewRequest("GET", op.Route.Path, nil).WithContext(ctx))
	if w.Code != 503 || calls.Load() != before {
		t.Fatal("canceled dispatch invoked handler")
	}
	if h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{f, f}}); h != nil || err == nil {
		t.Fatal("duplicate selection returned partial handler")
	}
}

func TestCanonicalOperationOwnsPolicyAndDirectSchemaBindings(t *testing.T) {
	c := identityhttp.CanonicalOperationConfig{Owner: "identity/session", OperationID: "identity.session.get", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16384}
	op, err := identityhttp.NewCanonicalOperation(c)
	if err != nil || op.Record.RequestSchema.ID != "go:identity/session:GetRequest" || op.Record.RequestSchema.Digest == ([32]byte{}) || op.Record.HandlerOwner != "identity/session" || op.Record.RatePolicy != "rate.safe" || op.Record.Idempotency != "read" {
		t.Fatal("lost canonical direct contract")
	}
	for _, change := range []func(*identityhttp.CanonicalOperationConfig){
		func(c *identityhttp.CanonicalOperationConfig) { c.Owner = "other" },
		func(c *identityhttp.CanonicalOperationConfig) { c.OperationID = "identity.unknown" },
		func(c *identityhttp.CanonicalOperationConfig) {
			c.OperationID = "identity.platform.bootstrap-administrator"
		},
		func(c *identityhttp.CanonicalOperationConfig) { c.OperationID = strings.Repeat("a", 129) },
		func(c *identityhttp.CanonicalOperationConfig) { c.Handler = http.HandlerFunc(nil) },
		func(c *identityhttp.CanonicalOperationConfig) { c.CSRF = identityhttp.CSRFPolicy{} },
		func(c *identityhttp.CanonicalOperationConfig) { c.MaximumSerializedBytes = 0 },
	} {
		invalid := c
		change(&invalid)
		if got, err := identityhttp.NewCanonicalOperation(invalid); err == nil || got.Handler != nil {
			t.Fatal("invalid canonical operation admitted")
		}
	}
	for _, change := range []func(*identityhttp.OperationDescriptor){
		func(o *identityhttp.OperationDescriptor) {
			o.Record.RequestSchema.Digest[0] ^= 1
			o.Schemas[0].Schema = o.Record.RequestSchema
		},
		func(o *identityhttp.OperationDescriptor) { o.Record.Idempotency = "keyed" },
		func(o *identityhttp.OperationDescriptor) {
			o.Record.RatePolicy = "rate.admin"
			o.Route.RatePolicy = "rate.admin"
		},
	} {
		copy, _ := identityhttp.NewCanonicalOperation(c)
		change(&copy)
		if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: c.Owner, Operations: []identityhttp.OperationDescriptor{copy}}); err == nil {
			t.Fatal("tampered canonical contribution admitted")
		}
	}
}

func TestPhoneRemovalStoredSynchronizerContract(t *testing.T) {
	c := identityhttp.CanonicalOperationConfig{Owner: "identity/phone", OperationID: "identity.phone.remove", Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny}, MaximumSerializedBytes: 16384}
	op, err := identityhttp.NewCanonicalOperation(c)
	if err != nil || op.Route.CSRF != c.CSRF || op.Record.Idempotency != "keyed" || op.Record.RatePolicy != "rate.secret" {
		t.Fatal("original-session phone removal contract rejected", err)
	}
	for _, change := range []func(*identityhttp.CanonicalOperationConfig){
		func(c *identityhttp.CanonicalOperationConfig) { c.CSRF.Mode = identityhttp.CSRFNone },
		func(c *identityhttp.CanonicalOperationConfig) { c.CSRF.Mode = identityhttp.CSRFExactOrigin },
		func(c *identityhttp.CanonicalOperationConfig) { c.CSRF.TokenHeader = "X-Other-Token" },
		func(c *identityhttp.CanonicalOperationConfig) {
			c.CSRF.RefererFallback = identityhttp.RefererFallbackSameOriginHTTPS
		},
		func(c *identityhttp.CanonicalOperationConfig) { c.CSRF.TokenMaximumAge = 1 },
	} {
		bad := c
		change(&bad)
		if _, err := identityhttp.NewCanonicalOperation(bad); err == nil {
			t.Fatal("weaker or independently aged phone removal custody accepted")
		}
	}
}

func TestAPIKeyManagementSelectsOnlyExplicitBearerKeyedProfile(t *testing.T) {
	for _, action := range []string{"create", "rotate", "delete"} {
		t.Run(action, func(t *testing.T) {
			c := identityhttp.CanonicalOperationConfig{Owner: "identity/apikey", OperationID: "identity.apikey." + action, Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusAccepted) }), CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16384}
			op, err := identityhttp.NewCanonicalOperation(c)
			if err != nil || op.Record.Idempotency != "keyed" || op.Record.RatePolicy != "rate.secret" || op.Route.CSRF != c.CSRF {
				t.Fatal("native bearer/keyed management profile rejected", err)
			}
			f := feature(t, "identity/apikey", nil, op)
			h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/apikey/"+action, nil))
			if w.Code != http.StatusAccepted {
				t.Fatal("selected management handler is unreachable", w.Code)
			}
			for _, change := range []func(*identityhttp.OperationDescriptor){
				func(o *identityhttp.OperationDescriptor) { o.Record.Idempotency = "repeat" },
				func(o *identityhttp.OperationDescriptor) { o.Record.Idempotency = "rotate" },
			} {
				bad := op
				change(&bad)
				if _, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: c.Owner, Operations: []identityhttp.OperationDescriptor{bad}}); err == nil {
					t.Fatal("bearer management admitted without original keyed custody")
				}
			}
		})
	}
	for _, operation := range []string{"identity.apikey.update", "identity.password.reset-inspect"} {
		if _, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{Owner: "identity/apikey", OperationID: operation, Handler: http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 16384}); err == nil {
			t.Fatal("management exception broadened another operation", operation)
		}
	}
}
