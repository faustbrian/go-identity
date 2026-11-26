package identityhttp_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestRouterOnlySelectedSCIMOwnsItsBodyEnvelope(t *testing.T) {
	policy := routerPolicy()
	policy.Network.Limits.MaximumBodyBytes = 1 << 20
	scimPath := "/scim/v2/Bulk"
	var entered int
	bulk, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "scim", OperationID: "identity.scim.bulk",
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 2 << 20,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			entered++
			if r.Header.Get("Content-Encoding") == "gzip" {
				w.WriteHeader(http.StatusUnsupportedMediaType)
				return
			}
			n, err := io.Copy(io.Discard, io.LimitReader(r.Body, (2<<20)+1))
			if err != nil {
				t.Error("generic stream cap intercepted the SCIM envelope", err)
				return
			}
			if n > 2<<20 {
				w.WriteHeader(http.StatusRequestEntityTooLarge)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	bulk.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"identity.scim.bulk","security":[],"responses":{"204":{"description":"fixture"}}}`)}
	ordinary := routerOperation(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	h, _, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{bulk, ordinary}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, path, encoding string
		size                         int
		chunked                      bool
		want                         int
	}{
		{"large SCIM request", "POST", scimPath, "", (1 << 20) + 33, false, 204},
		{"chunked SCIM overrun", "POST", scimPath, "", (2 << 20) + 1, true, 413},
		{"SCIM representation denial", "POST", scimPath, "gzip", 1, false, 415},
		{"ordinary route retains its maximum", "GET", ordinary.Route.Path, "", (1 << 20) + 33, false, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := corsRequest(tc.method, tc.path, "")
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", tc.size)))
			r.ContentLength = int64(tc.size)
			if tc.chunked {
				r.ContentLength = -1
				r.TransferEncoding = []string{"chunked"}
			}
			if tc.encoding != "" {
				r.Header.Set("Content-Encoding", tc.encoding)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("got status %d; want %d", w.Code, tc.want)
			}
		})
	}
	if entered != 3 {
		t.Fatalf("SCIM handler received %d requests, want 3", entered)
	}
}

func TestSCIMCredentialBoundaryKeepsOrdinaryJSONStrict(t *testing.T) {
	_, decoder, err := identityhttp.NewSCIMRequestBoundary(routerPolicy().Network)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/scim/v2/Bulk", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer fixture")
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Content-Encoding", "gzip")
	if _, ok, err := decoder.Bearer(r, identityhttp.HeaderRequired); err != nil || !ok {
		t.Fatal("credential syntax should not select SCIM's representation error", err)
	}
	if _, err := identityhttp.DecodeJSON[map[string]any](decoder, r); err == nil {
		t.Fatal("ordinary JSON decoder did not retain its content encoding check")
	}
}

func TestRouterDelegatesOnlySelectedSCIMCollectionRepresentation(t *testing.T) {
	t.Run("user list", func(t *testing.T) {
		assertRouterDelegatesSCIMCollectionRepresentation(t, "identity.scim.user-list", http.MethodGet, http.MethodPost)
	})
	t.Run("user create", func(t *testing.T) {
		assertRouterDelegatesSCIMCollectionRepresentation(t, "identity.scim.user-create", http.MethodPost, http.MethodGet)
	})
}

func assertRouterDelegatesSCIMCollectionRepresentation(t *testing.T, operation, method, otherMethod string) {
	t.Helper()
	var entered int
	collection := scimUserOperation(t, operation, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered++
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Fatal("router changed the feature-owned representation header")
		}
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(http.StatusUnsupportedMediaType)
	}))
	ordinary := routerOperation(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	selected, _, err := identityhttp.NewRouter(routerPolicy(), []identityhttp.OperationDescriptor{collection, ordinary}, nil)
	if err != nil {
		t.Fatal(err)
	}
	unselected, _, err := identityhttp.NewRouter(routerPolicy(), []identityhttp.OperationDescriptor{ordinary}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, path string
		handler            http.Handler
		duplicate          bool
		want               int
	}{
		{"exact selected route", method, scimUserCollection, selected, false, http.StatusUnsupportedMediaType},
		{"duplicate header stays malformed", method, scimUserCollection, selected, true, http.StatusBadRequest},
		{"ordinary stays strict", http.MethodGet, ordinary.Route.Path, selected, false, http.StatusBadRequest},
		{"disabled route stays strict", method, scimUserCollection, unselected, false, http.StatusBadRequest},
		{"wrong method stays strict", otherMethod, scimUserCollection, selected, false, http.StatusBadRequest},
		{"encoded alias stays strict", method, "/scim/v2/%55sers", selected, false, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := corsRequest(tc.method, tc.path, "")
			r.Header.Set("Content-Encoding", "gzip")
			if tc.duplicate {
				r.Header.Add("Content-Encoding", "identity")
			}
			w := httptest.NewRecorder()
			tc.handler.ServeHTTP(w, r)
			if w.Code != tc.want || (w.Header().Get("Content-Type") == "application/scim+json") != (tc.want == http.StatusUnsupportedMediaType) {
				t.Fatalf("got status %d and media type %q; want status %d with route-appropriate media type", w.Code, w.Header().Get("Content-Type"), tc.want)
			}
		})
	}
	if entered != 1 {
		t.Fatalf("collection handler received %d requests, want 1", entered)
	}
}

func TestRouterSCIMUserCreateRetainsOrdinaryStreamLimit(t *testing.T) {
	policy := routerPolicy()
	policy.Network.Limits.MaximumBodyBytes = 1 << 20
	create := scimUserOperation(t, "identity.scim.user-create", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			w.Header().Set("Set-Cookie", "fixture=discard")
			w.Header().Set("Location", "/discard")
			w.Header().Set("ETag", `"discard"`)
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	h, _, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{create}, nil)
	if err != nil {
		t.Fatal(err)
	}
	serve := func(size int) *httptest.ResponseRecorder {
		t.Helper()
		r := corsRequest(http.MethodPost, scimUserCollection, "")
		r.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", size)))
		r.ContentLength = -1
		r.TransferEncoding = []string{"chunked"}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	if w := serve(1 << 20); w.Code != http.StatusNoContent {
		t.Fatalf("at the ordinary stream limit, got %d", w.Code)
	}
	w := serve((1 << 20) + 1)
	const tooLarge = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:Error"],"status":"413"}` + "\n"
	if w.Code != http.StatusRequestEntityTooLarge || w.Header().Get("Content-Type") != "application/scim+json" || w.Body.String() != tooLarge {
		t.Fatalf("oversized Create must return a SCIM 413, got %d %q %q", w.Code, w.Header().Get("Content-Type"), w.Body.String())
	}
	for _, name := range []string{"Set-Cookie", "Location", "ETag"} {
		if w.Header().Get(name) != "" {
			t.Fatalf("oversized Create returned a discarded %s", name)
		}
	}
}

func TestRouterDelegatesOnlyCanonicalSelectedSCIMUserGetRepresentation(t *testing.T) {
	const id = "canonical-user-1"
	var entered int
	get := scimUserOperation(t, "identity.scim.user-get", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered++
		if r.Header.Get("Content-Encoding") != "gzip" || r.PathValue("resource_id") != id {
			t.Fatal("router lost the original header or its matched path value")
		}
		w.Header().Set("Content-Type", "application/scim+json")
		w.WriteHeader(http.StatusUnsupportedMediaType)
	}))
	ordinary := routerOperation(t, http.NotFoundHandler())
	selected, _, err := identityhttp.NewRouter(routerPolicy(), []identityhttp.OperationDescriptor{ordinary, get}, nil)
	if err != nil {
		t.Fatal(err)
	}
	unselected, _, err := identityhttp.NewRouter(routerPolicy(), []identityhttp.OperationDescriptor{ordinary}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, path string
		handler            http.Handler
		duplicate          bool
		want               int
	}{
		{"exact Get", http.MethodGet, scimUserCollection + "/" + id, selected, false, http.StatusUnsupportedMediaType},
		{"disabled Get", http.MethodGet, scimUserCollection + "/" + id, unselected, false, http.StatusBadRequest},
		{"wrong method", http.MethodPatch, scimUserCollection + "/" + id, selected, false, http.StatusBadRequest},
		{"collection", http.MethodGet, scimUserCollection, selected, false, http.StatusBadRequest},
		{"encoded alias", http.MethodGet, scimUserCollection + "/%63anonical-user-1", selected, false, http.StatusBadRequest},
		{"reserved search", http.MethodGet, scimUserCollection + "/.search", selected, false, http.StatusBadRequest},
		{"nested path", http.MethodGet, scimUserCollection + "/" + id + "/child", selected, false, http.StatusBadRequest},
		{"duplicate header", http.MethodGet, scimUserCollection + "/" + id, selected, true, http.StatusBadRequest},
		{"ordinary", http.MethodGet, ordinary.Route.Path, selected, false, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := corsRequest(tc.method, tc.path, "")
			r.Header.Set("Content-Encoding", "gzip")
			if tc.duplicate {
				r.Header.Add("Content-Encoding", "identity")
			}
			w := httptest.NewRecorder()
			tc.handler.ServeHTTP(w, r)
			if w.Code != tc.want || (w.Header().Get("Content-Type") == "application/scim+json") != (tc.want == http.StatusUnsupportedMediaType) {
				t.Fatalf("got status %d and media type %q, want %d with route-appropriate media", w.Code, w.Header().Get("Content-Type"), tc.want)
			}
		})
	}
	if entered != 1 {
		t.Fatalf("Get handler ran %d times, want 1", entered)
	}
}
