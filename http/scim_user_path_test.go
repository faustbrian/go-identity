package identityhttp_test

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

const scimUserCollection = "/scim/v2/Users"

func scimUserOperation(t testing.TB, id string, handler http.Handler) identityhttp.OperationDescriptor {
	t.Helper()
	op, err := identityhttp.NewCanonicalOperation(identityhttp.CanonicalOperationConfig{
		Owner: "scim", OperationID: id, Handler: handler,
		CSRF: identityhttp.CSRFPolicy{Mode: identityhttp.CSRFNone}, MaximumSerializedBytes: 8192,
	})
	if err != nil {
		t.Fatal(err)
	}
	params := `[]`
	if id == "identity.scim.user-get" || id == "identity.scim.user-delete" {
		params = `[{"name":"resource_id","in":"path","required":true,"schema":{"type":"string"}}]`
	}
	status := "200"
	if id == "identity.scim.user-delete" {
		status = "204"
	}
	op.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"` + id + `","parameters":` + params + `,"security":[],"responses":{"` + status + `":{"description":"Test fixture"}}}`)}
	return op
}

func TestSCIMUserGetDispatchIsCanonicalAndOptIn(t *testing.T) {
	const id = "User_19-A.z~"
	get := scimUserOperation(t, "identity.scim.user-get", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Fixture-Query", r.URL.RawQuery)
		w.Write([]byte(r.PathValue("resource_id")))
	}))
	list := scimUserOperation(t, "identity.scim.user-list", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("list"))
	}))
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
				h, doc, err := identityhttp.NewRouter(routerPolicy(), operations, nil)
				if err != nil {
					t.Fatal(err)
				}
				wantTemplate := len(operations) == 2
				if bytes.Contains(doc.JSON(), []byte(scimUserCollection+"/{resource_id}")) != wantTemplate {
					t.Fatal("OpenAPI disagrees with route selection")
				}
				return h
			}
			selected, listOnly := build(get, list), build(list)
			for _, tc := range []struct {
				name, method, path string
				want, body         string
				status             int
			}{
				{"get", "GET", scimUserCollection + "/" + id, "", id, 200},
				{"query custody", "GET", scimUserCollection + "/" + id + "?attributes=userName", "", id, 200},
				{"maximum id", "GET", scimUserCollection + "/" + strings.Repeat("a", 128), "", strings.Repeat("a", 128), 200},
				{"list", "GET", scimUserCollection, "", "list", 200},
				{"no implicit head", "HEAD", scimUserCollection + "/" + id, "GET", "", 405},
				{"no write", "PATCH", scimUserCollection + "/" + id, "GET", "", 405},
				{"no implicit options", "OPTIONS", scimUserCollection + "/" + id, "GET", "", 405},
				{"literal template", "GET", scimUserCollection + "/{resource_id}", "", "", 404},
				{"reserved search", "GET", scimUserCollection + "/.search", "", "", 404},
				{"encoded segment", "GET", scimUserCollection + "/%55ser", "", "", 404},
				{"nested segment", "GET", scimUserCollection + "/" + id + "/child", "", "", 404},
				{"trailing slash", "GET", scimUserCollection + "/" + id + "/", "", "", 404},
				{"wrong case", "GET", "/scim/v2/users/" + id, "", "", 404},
				{"oversized id", "GET", scimUserCollection + "/" + strings.Repeat("a", 129), "", "", 404},
			} {
				t.Run(tc.name, func(t *testing.T) {
					w := httptest.NewRecorder()
					r := corsRequest(tc.method, tc.path, "")
					r.SetPathValue("resource_id", "unrelated")
					selected.ServeHTTP(w, r)
					wantStatus := tc.status
					if transport == "router" && tc.name == "literal template" {
						wantStatus = 400 // The full router rejects the raw URL before dispatch.
					}
					if w.Code != wantStatus || w.Header().Get("Allow") != tc.want || w.Header().Get("Location") != "" || r.PathValue("resource_id") != "unrelated" {
						t.Fatalf("got status %d, allow %q, path value %q; want %d, %q and unchanged request", w.Code, w.Header().Get("Allow"), r.PathValue("resource_id"), wantStatus, tc.want)
					}
					if (tc.status == 200 || tc.method == "HEAD") && w.Body.String() != tc.body {
						t.Fatalf("body %q does not match selected route value %q", w.Body, tc.body)
					}
					if tc.name == "query custody" && w.Header().Get("X-Fixture-Query") != "attributes=userName" {
						t.Fatal("dispatch changed the feature-owned query")
					}
				})
			}
			w := httptest.NewRecorder()
			listOnly.ServeHTTP(w, corsRequest("GET", scimUserCollection+"/"+id, ""))
			if w.Code != 404 {
				t.Fatal("List opted into Get", w.Code)
			}
			if transport == "selected" {
				ctx, cancel := context.WithCancel(t.Context())
				cancel()
				w = httptest.NewRecorder()
				selected.ServeHTTP(w, corsRequest("GET", scimUserCollection+"/"+id, "").WithContext(ctx))
				if w.Code != 503 {
					t.Fatal("cancelled read reached the handler", w.Code)
				}
			}
		})
	}
}

func TestSCIMUserDeleteDispatchIsCanonicalAndIndependentlySelected(t *testing.T) {
	const id = "User_19-A.z~"
	const resource = scimUserCollection + "/" + id
	remove := scimUserOperation(t, "identity.scim.user-delete", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Fixture-User", r.PathValue("resource_id"))
		w.WriteHeader(http.StatusNoContent)
	}))
	get := scimUserOperation(t, "identity.scim.user-get", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.PathValue("resource_id")))
	}))

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
				h, _, err := identityhttp.NewRouter(routerPolicy(), operations, nil)
				if err != nil {
					t.Fatal(err)
				}
				return h
			}
			onlyDelete, onlyGet, both := build(remove), build(get), build(remove, get)
			for _, tc := range []struct {
				name, method, path, allow, bound string
				handler                          http.Handler
				status                           int
			}{
				{"delete-only", "DELETE", resource, "", id, onlyDelete, 204},
				{"delete-with-get", "DELETE", resource, "", id, both, 204},
				{"get-with-delete", "GET", resource, "", "", both, 200},
				{"unselected-delete", "DELETE", resource, "GET", "", onlyGet, 405},
				{"unselected-get", "GET", resource, "DELETE", "", onlyDelete, 405},
				{"stable-allow", "PATCH", resource, "DELETE, GET", "", both, 405},
				{"collection", "DELETE", scimUserCollection, "", "", both, 404},
				{"reserved-search", "DELETE", scimUserCollection + "/.search", "", "", both, 404},
				{"encoded-alias", "DELETE", scimUserCollection + "/%55ser", "", "", both, 404},
			} {
				t.Run(tc.name, func(t *testing.T) {
					r := corsRequest(tc.method, tc.path, "")
					r.SetPathValue("resource_id", "unrelated")
					w := httptest.NewRecorder()
					tc.handler.ServeHTTP(w, r)
					if w.Code != tc.status || w.Header().Get("Allow") != tc.allow || w.Header().Get("X-Fixture-User") != tc.bound || r.PathValue("resource_id") != "unrelated" {
						t.Fatalf("status=%d allow=%q bound=%q caller_path=%q", w.Code, w.Header().Get("Allow"), w.Header().Get("X-Fixture-User"), r.PathValue("resource_id"))
					}
					if tc.status == 204 && w.Body.Len() != 0 || tc.status == 200 && w.Body.String() != id {
						t.Fatal("unexpected selected response body", w.Body.String())
					}
				})
			}
		})
	}
}

func TestSCIMUserGetDoesNotBindTemplateCORSOrInterceptSearch(t *testing.T) {
	get := scimUserOperation(t, "identity.scim.user-get", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("get"))
	}))
	search := scimUserOperation(t, "identity.scim.user-search", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("search"))
	}))
	ops := []identityhttp.OperationDescriptor{get, search}
	h, _, err := identityhttp.NewRouter(routerPolicy(), ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		method string
		status int
	}{
		{"POST", 200}, {"GET", 405},
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, corsRequest(tc.method, scimUserCollection+"/.search", ""))
		if w.Code != tc.status || tc.status == 200 && w.Body.String() != "search" || tc.status == 405 && w.Header().Get("Allow") != "POST" {
			t.Fatal("reserved Search route resolved to another handler", tc.method, w.Code)
		}
	}
	c := routerPolicy()
	c.CORS = []identityhttp.CORSRoutePolicy{{Method: "GET", Path: get.Route.Path, Credentials: identityhttp.CORSBearerCredentials, Origins: []identityhttp.Origin{"https://client.example"}, AllowedHeaders: []string{"Authorization"}}}
	if h, _, err := identityhttp.NewRouter(c, ops, nil); h != nil || err == nil {
		t.Fatal("dynamic template was accepted as an exact CORS route")
	}
}

func FuzzSelectedSCIMUserPath(f *testing.F) {
	op := scimUserOperation(f, "identity.scim.user-get", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(r.PathValue("resource_id")))
	}))
	selected, err := identityhttp.NewFeature(identityhttp.FeatureConfig{ID: "scim", Operations: []identityhttp.OperationDescriptor{op}})
	if err != nil {
		f.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{selected}})
	if err != nil {
		f.Fatal(err)
	}
	for _, id := range []string{"Ab-19_Z", ".", ".search", "a/b", "{resource_id}", "a%20b", strings.Repeat("x", 129)} {
		f.Add(id, false)
	}
	f.Add("Ab-19_Z", true)
	f.Fuzz(func(t *testing.T, id string, raw bool) {
		if len(id) > 256 {
			return
		}
		r := httptest.NewRequest("GET", scimUserCollection, nil)
		r.URL.Path += "/" + id
		if raw {
			r.URL.RawPath = r.URL.Path
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		allowed := !raw && len(id) >= 1 && len(id) <= 128 && id != "." && id != ".." && id != ".search" &&
			strings.Trim(id, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~") == ""
		if allowed && (w.Code != 200 || w.Body.String() != id) || !allowed && w.Code != 404 {
			t.Fatalf("path admission differs from single-segment contract: status %d", w.Code)
		}
	})
}
