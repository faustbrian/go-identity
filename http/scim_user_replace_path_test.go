package identityhttp_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func scimUserReplacePathOperation(t *testing.T, handler http.Handler) identityhttp.OperationDescriptor {
	t.Helper()
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "scim", OperationID: "identity.scim.user-replace", Handler: handler,
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 8192,
	})
	if err != nil {
		t.Fatal(err)
	}
	op.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"identity.scim.user-replace","parameters":[{"name":"resource_id","in":"path","required":true,"schema":{"type":"string"}}],"security":[],"responses":{"200":{"description":"Test fixture"}}}`)}
	return op
}

func TestSCIMUserReplaceDispatchIsCanonicalAndIndependentlySelected(t *testing.T) {
	const id = "User_19-A.z~"
	const resource = scimUserCollection + "/" + id
	replace := scimUserReplacePathOperation(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.PathValue("resource_id")))
	}))
	read := scimUserOperation(t, "identity.scim.user-get", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("get")) }))
	patch := scimUserOperation(t, "identity.scim.user-patch", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("patch")) }))
	remove := scimUserOperation(t, "identity.scim.user-delete", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, transport := range []string{"selected", "router"} {
		t.Run(transport, func(t *testing.T) {
			build := func(operations ...identityhttp.OperationDescriptor) http.Handler {
				t.Helper()
				if transport == "selected" {
					f := feature(t, "scim", nil, operations...)
					h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
					if err != nil {
						t.Fatal(err)
					}
					return h
				}
				h, document, err := identityhttp.NewRouter(routerPolicy(), operations, nil)
				if err != nil {
					t.Fatal(err)
				}
				selected := false
				for _, op := range operations {
					selected = selected || op.Record.OperationID == "identity.scim.user-replace"
				}
				if bytes.Contains(document.JSON(), []byte(`"operationId":"identity.scim.user-replace"`)) != selected {
					t.Fatal("User Replace OpenAPI differs from actual selection")
				}
				return h
			}
			only, neighbors, combined := build(replace), build(read, patch, remove), build(replace, read, patch, remove)
			for _, tc := range []struct {
				handler                   http.Handler
				method, path, allow, body string
				status                    int
			}{
				{only, "PUT", resource, "", id, 200},
				{combined, "PUT", resource, "", id, 200},
				{combined, "GET", resource, "", "get", 200},
				{combined, "PATCH", resource, "", "patch", 200},
				{combined, "DELETE", resource, "", "", 204},
				{combined, "POST", resource, "DELETE, GET, PATCH, PUT", "", 405},
				{neighbors, "PUT", resource, "DELETE, GET, PATCH", "", 405},
				{only, "GET", resource, "PUT", "", 405},
				{only, "HEAD", resource, "PUT", "", 405},
				{only, "PUT", scimUserCollection, "", "", 404},
				{only, "PUT", scimUserCollection + "/.search", "", "", 404},
				{only, "PUT", resource + "/extra", "", "", 404},
				{only, "PUT", resource + "/", "", "", 404},
				{only, "PUT", scimUserCollection + "/%55ser", "", "", 404},
				{only, "PUT", "/scim/v2/users/" + id, "", "", 404},
			} {
				r := corsRequest(tc.method, tc.path, "")
				r.SetPathValue("resource_id", "caller")
				w := httptest.NewRecorder()
				tc.handler.ServeHTTP(w, r)
				if w.Code != tc.status || w.Header().Get("Allow") != tc.allow || r.PathValue("resource_id") != "caller" {
					t.Errorf("%s %s: status %d, Allow %q, caller path %q", tc.method, tc.path, w.Code, w.Header().Get("Allow"), r.PathValue("resource_id"))
				}
				if tc.status < 400 && w.Body.String() != tc.body {
					t.Errorf("%s changed selected handler output: %q", tc.method, w.Body.String())
				}
			}
		})
	}
}

func TestSCIMUserReplaceRetainsRouterBodyCapWithoutWideningOrdinaryStreams(t *testing.T) {
	for _, scimSelected := range []bool{true, false} {
		t.Run(map[bool]string{true: "scim-replace", false: "ordinary"}[scimSelected], func(t *testing.T) {
			policy := routerPolicy()
			var read []byte
			var readErr error
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				read, readErr = io.ReadAll(r.Body)
				w.WriteHeader(200)
			})
			op := routerOperation(t, handler)
			method, path, want := op.Route.Method, op.Route.Path, 400
			if scimSelected {
				op = scimUserReplacePathOperation(t, handler)
				method, path, want = http.MethodPut, scimUserCollection+"/bounded-user", 413
			}
			h, _, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{op}, nil)
			if err != nil {
				t.Fatal(err)
			}
			r := corsRequest(method, path, "")
			body := &countedBody{Reader: strings.NewReader(strings.Repeat("x", int(policy.Network.Limits.MaximumBodyBytes)+1))}
			r.Body, r.ContentLength = body, -1
			if scimSelected {
				r.Header.Set("Content-Type", "application/scim+json")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || readErr == nil || len(read) != int(policy.Network.Limits.MaximumBodyBytes) || body.closes != 0 || r.Body != body {
				t.Fatalf("selected Replace changed ordinary stream cap/custody: status %d want %d, read %d", w.Code, want, len(read))
			}
		})
	}
}
