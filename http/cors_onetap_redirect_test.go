package identityhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestOneTapRedirectNavigationSelectsOnlyBoundTenantFormPosts(t *testing.T) {
	const origin = "https://tenant.example"
	const path = "/v1/oauth/onetap-callback"
	var deliveries int
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-callback", MaximumSerializedBytes: 8192,
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFBoundOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			deliveries++
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatal("cannot select original-bound One Tap callback", err)
	}
	op.Wire = oneTapNavigationTestWire()
	policy := routerPolicy()
	policy.Network.TenantHosts = append(policy.Network.TenantHosts, identityhttp.TenantHost{Host: "other-tenant.example", TenantID: "tenant-b"})
	policy.CORS = []identityhttp.CORSRoutePolicy{{Method: http.MethodPost, Path: path, Credentials: identityhttp.CORSOneTapRedirectNavigation, Origins: []identityhttp.Origin{origin}}}
	h, _, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal("cannot compose explicit One Tap redirect navigation", err)
	}
	for _, tc := range []struct {
		name, method, path, origin, host, media string
		ambiguous, preflight                    bool
		forward                                 bool
	}{
		{name: "missing sender origin", method: "POST", path: path, host: "tenant.example", media: "application/x-www-form-urlencoded", forward: true},
		{name: "opaque sender origin", method: "POST", path: path, origin: "null", host: "tenant.example", media: "application/x-www-form-urlencoded", forward: true},
		{name: "foreign sender origin", method: "POST", path: path, origin: "https://sender.example", host: "tenant.example", media: "application/x-www-form-urlencoded", forward: true},
		{name: "same sender origin", method: "POST", path: path, origin: origin, host: "tenant.example", media: "application/x-www-form-urlencoded", forward: true},
		{name: "ambiguous sender", method: "POST", path: path, origin: origin, host: "tenant.example", media: "application/x-www-form-urlencoded", ambiguous: true},
		{name: "malformed sender", method: "POST", path: path, origin: "https://sender.example/extra", host: "tenant.example", media: "application/x-www-form-urlencoded"},
		{name: "wrong tenant destination", method: "POST", path: path, origin: origin, host: "other-tenant.example", media: "application/x-www-form-urlencoded"},
		{name: "public destination", method: "POST", path: path, origin: "null", host: "login.example", media: "application/x-www-form-urlencoded"},
		{name: "json callback", method: "POST", path: path, origin: "null", host: "tenant.example", media: "application/json"},
		{name: "query alias", method: "POST", path: path + "?state=untrusted", origin: "null", host: "tenant.example", media: "application/x-www-form-urlencoded"},
		{name: "escaped path alias", method: "POST", path: "/v1/oauth/%6fnetap-callback", origin: origin, host: "tenant.example", media: "application/x-www-form-urlencoded"},
		{name: "different method", method: "GET", path: path, origin: origin, host: "tenant.example", media: "application/x-www-form-urlencoded"},
		{name: "CORS preflight", method: "OPTIONS", path: path, origin: origin, host: "tenant.example", preflight: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := corsRequest(tc.method, tc.path, tc.origin)
			r.Host = tc.host
			if tc.media != "" {
				r.Header.Set("Content-Type", tc.media)
			}
			if tc.ambiguous {
				r.Header["origin"] = []string{tc.origin}
			}
			if tc.preflight {
				r.Header.Set("Access-Control-Request-Method", http.MethodPost)
			}
			before := deliveries
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Header().Get("Access-Control-Allow-Origin") != "" || w.Header().Get("Access-Control-Allow-Credentials") != "" {
				t.Fatal("navigation callback granted cross-origin script access")
			}
			if tc.forward && (w.Code != http.StatusNoContent || deliveries != before+1) || !tc.forward && (w.Code < 400 || deliveries != before) {
				t.Fatalf("status %d, reached original proof owner = %v; want forwarded = %v", w.Code, deliveries != before, tc.forward)
			}
		})
	}
}

func TestOneTapRedirectNavigationRequiresTheExplicitCanonicalProfile(t *testing.T) {
	const path = "/v1/oauth/onetap-callback"
	const origin = "https://tenant.example"
	for _, policyMode := range []identityhttp.CSRFMode{identityhttp.CSRFBoundOrigin, identityhttp.CSRFExactOrigin} {
		op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
			Owner: "identity/oauth/onetap", OperationID: "identity.oauth.onetap-callback", MaximumSerializedBytes: 8192,
			CSRF:    identityhttp.CSRFPolicy{Mode: policyMode, RefererFallback: identityhttp.RefererFallbackDeny},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		})
		if err != nil {
			t.Fatal(err)
		}
		op.Wire = oneTapNavigationTestWire()
		policy := routerPolicy()
		if policyMode == identityhttp.CSRFBoundOrigin {
			if _, _, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{op}, nil); err == nil {
				t.Fatal("bound callback was composed without its explicit navigation policy")
			}
			policy.CORS = []identityhttp.CORSRoutePolicy{{Method: http.MethodPost, Path: path, Credentials: identityhttp.CORSOneTapRedirectNavigation, Origins: []identityhttp.Origin{origin}, AllowedHeaders: []string{"Content-Type"}}}
			if _, _, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{op}, nil); err == nil {
				t.Fatal("navigation accepted a script/header grant")
			}
			continue
		}
		policy.CORS = []identityhttp.CORSRoutePolicy{{Method: http.MethodPost, Path: path, Credentials: identityhttp.CORSOneTapRedirectNavigation, Origins: []identityhttp.Origin{origin}}}
		if _, _, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{op}, nil); err == nil {
			t.Fatal("popup callback inherited redirect navigation policy")
		}
		policy.CORS = nil
		h, _, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{op}, nil)
		if err != nil {
			t.Fatal("popup profile could not compose as before", err)
		}
		for _, origin := range []string{"null", "https://sender.example"} {
			r := corsRequest(http.MethodPost, path, origin)
			r.Host = "tenant.example"
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatal("unchanged popup CORS admitted a cross-origin form", w.Code)
			}
		}
	}
}

func oneTapNavigationTestWire() *identityhttp.WireOperation {
	return &identityhttp.WireOperation{Definition: []byte(`{"operationId":"identity.oauth.onetap-callback","security":[],"responses":{"204":{"description":"Forwarded to the test handler"}}}`)}
}
