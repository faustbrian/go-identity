package identityhttp_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestCanonicalProviderPathDispatchUsesOnlySelectedExactIDs(t *testing.T) {
	const start = "identity.sso.oidc-logout"
	ids := []string{"installed", "second"}
	config := identityhttp.CanonicalOperationConfig{
		Owner: "sso/oidc", OperationID: start, MaximumSerializedBytes: 8192, ProviderPathIDs: ids,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }),
		CSRF:    identityhttp.CSRFPolicy{Mode: identityhttp.CSRFSessionState, TokenHeader: "X-CSRF-Token", RefererFallback: identityhttp.RefererFallbackDeny},
	}
	op, err := identityhttp.NewCanonicalOperation(config)
	if err != nil || op.Record.Path != "/sso/oidc/{provider_id}/logout" {
		t.Fatal("canonical operation lost its documentation template", err)
	}
	ids[0] = "mutated"
	selected, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "sso/oidc", Operations: []identityhttp.OperationDescriptor{op}})
	if err != nil {
		t.Fatal(err)
	}
	op.ProviderPathIDs[0] = "mutated"
	selected.Operations()[0].ProviderPathIDs[1] = "mutated"
	handler, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{selected}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"POST", "/sso/oidc/installed/logout", 204},
		{"POST", "/sso/oidc/second/logout", 204},
		{"GET", "/sso/oidc/installed/logout", 405},
		{"POST", "/sso/oidc/mutated/logout", 404},
		{"POST", "/sso/oidc/unconfigured/logout", 404},
		{"POST", "/sso/oidc/{provider_id}/logout", 404},
		{"POST", "/sso/oidc/%69nstalled/logout", 404},
		{"POST", "/sso/oidc/installed/logout/", 404},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.status || tc.status == 405 && w.Header().Get("Allow") != "POST" {
				t.Fatalf("expected %d, got %d", tc.status, w.Code)
			}
		})
	}
	for _, invalid := range [][]string{nil, {".."}, {"a/b"}, {"%61"}, {"{provider_id}"}, {"dup", "dup"}} {
		config.ProviderPathIDs = invalid
		if _, err := identityhttp.NewCanonicalOperation(config); err == nil {
			t.Fatal("accepted absent, duplicate or noncanonical provider path selection")
		}
	}
	for _, conflicting := range []string{"/sso/oidc/{provider_id}/logout", "/sso/oidc/installed/logout"} {
		t.Run("collision:"+conflicting, func(t *testing.T) {
			ext := extensionDescriptor(t, "mixed", "collision")
			ext.Record.Method, ext.Route.Method = http.MethodPost, http.MethodPost
			ext.Record.Path, ext.Route.Path = conflicting, conflicting
			other := feature(t, "mixed", nil, ext)
			if _, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{selected, other}}); err == nil {
				t.Fatal("accepted competing documentation or concrete dispatch routes")
			}
		})
	}
}

func TestSelectedSAMLProviderRoutesDoNotBecomeWildcards(t *testing.T) {
	const owner = "sso/saml"
	var ops []identityhttp.OperationDescriptor
	for _, id := range []string{"identity.sso.saml-start", "identity.sso.saml-acs", "identity.sso.saml-metadata"} {
		config := identityhttp.CanonicalOperationConfig{
			Owner: owner, OperationID: id, MaximumSerializedBytes: 8192, ProviderPathIDs: []string{"-selected"},
			CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFExactOrigin, RefererFallback: identityhttp.RefererFallbackDeny},
			Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusNoContent)
			}),
		}
		if id == "identity.sso.saml-metadata" {
			config.CSRF = identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}
		}
		op, err := identityhttp.NewCanonicalOperation(config)
		if err != nil {
			t.Fatalf("construct selected %s: %v", id, err)
		}
		config.ProviderPathIDs = nil
		if _, err := identityhttp.NewCanonicalOperation(config); err == nil {
			t.Fatalf("constructed %s without installed provider", id)
		}
		ops = append(ops, op)
	}
	feature, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: owner, Operations: ops})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method, path string
		status       int
	}{
		{"GET", "/saml2/-selected/login", 204},
		{"POST", "/saml2/-selected/acs", 204},
		{"GET", "/saml2/-selected/metadata", 204},
		{"POST", "/saml2/-selected/metadata", 405},
		{"GET", "/saml2/unknown/metadata", 404},
		{"GET", "/saml2/{provider_id}/metadata", 404},
		{"GET", "/saml2/%2dselected/metadata", 404},
		{"GET", "/saml2/-selected/acs", 405},
		{"POST", "/saml2/unknown/acs", 404},
		{"GET", "/saml2/%2dselected/login", 404},
		{"POST", "/saml2/{provider_id}/acs", 404},
		{"POST", "/saml2/-selected/idp-init", 404},
		{"POST", "/saml2/-selected/slo", 404},
	} {
		t.Run(tc.method+tc.path, func(t *testing.T) {
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, nil))
			if w.Code != tc.status {
				t.Fatalf("expected %d, got %d", tc.status, w.Code)
			}
		})
	}
}
