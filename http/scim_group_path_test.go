package identityhttp_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestRouterSelectsOnlyCanonicalSCIMGroupReads(t *testing.T) {
	const collection = "/scim/v2/Groups"
	const id = "Group_1-a.~"
	protocol := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/scim+json")
		if r.URL.Path != collection {
			w.Header().Set("X-Test-Resource", r.PathValue("resource_id"))
		}
		if r.Header.Get("Content-Encoding") != "" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
		}
	})
	get := scimUserOperation(t, "identity.scim.group-get", protocol)
	get.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"identity.scim.group-get","parameters":[{"name":"resource_id","in":"path","required":true,"schema":{"type":"string"}}],"security":[],"responses":{"200":{"description":"Test fixture"}}}`)}
	list := scimUserOperation(t, "identity.scim.group-list", protocol)
	ordinary := routerOperation(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	const shadowed = collection + "/reserved"
	ordinary.Route.Path, ordinary.Record.Path = shadowed, shadowed
	build := func(ops ...identityhttp.OperationDescriptor) http.Handler {
		t.Helper()
		h, _, err := identityhttp.NewRouter(routerPolicy(), ops, nil)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	both := build(ordinary, get, list)
	listOnly := build(list)
	getOnly := build(get)
	for _, test := range []struct {
		name, method, path, id string
		router                 http.Handler
		encoded                bool
		status                 int
	}{
		{"get", "GET", collection + "/" + id + "?attributes=displayName", id, both, false, 200},
		{"get envelope", "GET", collection + "/" + id, id, both, true, 415},
		{"list envelope", "GET", collection, "", both, true, 415},
		{"list does not select get", "GET", collection + "/" + id, "", listOnly, false, 404},
		{"get does not select list", "GET", collection, "", getOnly, false, 404},
		{"static shadow wins", "GET", shadowed, "", both, false, 202},
		{"static shadow is not SCIM", "GET", shadowed, "", both, true, 400},
		{"encoded alias", "GET", collection + "/%47roup", "", both, true, 400},
		{"reserved search", "GET", collection + "/.search", "", both, false, 404},
		{"nested resource", "GET", collection + "/" + id + "/child", "", both, false, 404},
		{"no implicit head", "HEAD", collection + "/" + id, "", both, false, 405},
		{"no write envelope", "PATCH", collection + "/" + id, "", both, true, 400},
		{"no User route", "GET", "/scim/v2/Users/" + id, "", both, false, 404},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := corsRequest(test.method, test.path, "")
			r.SetPathValue("resource_id", "ignored")
			if test.encoded {
				r.Header.Set("Content-Encoding", "gzip")
			}
			w := httptest.NewRecorder()
			test.router.ServeHTTP(w, r)
			if w.Code != test.status || w.Header().Get("X-Test-Resource") != test.id || r.PathValue("resource_id") != "ignored" {
				t.Fatalf("status=%d resource=%q caller value=%q; want %d and resource=%q", w.Code, w.Header().Get("X-Test-Resource"), r.PathValue("resource_id"), test.status, test.id)
			}
			if test.status == http.StatusUnsupportedMediaType && w.Header().Get("Content-Type") != "application/scim+json" {
				t.Fatal("selected route lost its protocol response")
			}
		})
	}
	policy := routerPolicy()
	policy.CORS = []identityhttp.CORSRoutePolicy{{
		Method: http.MethodGet, Path: get.Route.Path, Credentials: identityhttp.CORSBearerCredentials,
		Origins: []identityhttp.Origin{"https://client.example"}, AllowedHeaders: []string{"Authorization"},
	}}
	if handler, _, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{get}, nil); handler != nil || err == nil {
		t.Fatal("Group resource template was accepted as an exact CORS route")
	}
}

func TestRouterAppliesSCIMBodyEnvelopeOnlyToSelectedGroupCreate(t *testing.T) {
	const collection = "/scim/v2/Groups"
	policy := routerPolicy()
	maximum := int64(policy.Network.Limits.MaximumBodyBytes)
	create := scimUserOperation(t, "identity.scim.group-create", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/scim+json")
		if r.Header.Get("Content-Encoding") != "" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	list := scimUserOperation(t, "identity.scim.group-list", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	selected, _, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{list, create}, nil)
	if err != nil {
		t.Fatal(err)
	}
	unselected, _, err := identityhttp.NewRouter(policy, []identityhttp.OperationDescriptor{list}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, method, path string
		router             http.Handler
		encoding           bool
		length             int64
		status             int
	}{
		{"plain selected", "POST", collection, selected, false, 1, 201},
		{"encoded selected", "POST", collection, selected, true, 1, 415},
		{"known overflow", "POST", collection, selected, false, maximum + 1, 413},
		{"unknown overflow", "POST", collection, selected, false, -1, 413},
		{"unselected write", "POST", collection, unselected, true, 1, 400},
		{"encoded alias", "POST", "/scim/v2/%47roups", selected, true, 1, 400},
		{"wrong method", "PUT", collection, selected, true, 1, 400},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := corsRequest(row.method, row.path, "")
			r.ContentLength = row.length
			size := row.length
			if size < 0 {
				size = maximum + 1
			}
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", int(size))))
			if row.encoding {
				r.Header.Set("Content-Encoding", "gzip")
			}
			w := httptest.NewRecorder()
			row.router.ServeHTTP(w, r)
			if w.Code != row.status {
				t.Fatalf("status %d, want %d", w.Code, row.status)
			}
			if row.status != 400 && w.Header().Get("Content-Type") != "application/scim+json" {
				t.Fatal("selected Group Create lost its SCIM media type")
			}
		})
	}
}

func TestRouterAppliesSCIMBodyEnvelopeOnlyToSelectedGroupReplace(t *testing.T) {
	const path = "/scim/v2/Groups/Group_1-a.~"
	policy := routerPolicy()
	maximum := int64(policy.Network.Limits.MaximumBodyBytes)
	replace := scimUserOperation(t, "identity.scim.group-replace", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/scim+json")
		w.Header().Set("X-Test-Resource", r.PathValue("resource_id"))
		if r.Header.Get("Content-Encoding") != "" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		if r.ContentLength > maximum {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		if _, err := io.Copy(io.Discard, r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	replace.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"identity.scim.group-replace","parameters":[{"name":"resource_id","in":"path","required":true,"schema":{"type":"string"}}],"security":[],"responses":{"200":{"description":"Test fixture"}}}`)}
	get := scimUserOperation(t, "identity.scim.group-get", http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	get.Wire = &identityhttp.WireOperation{Definition: []byte(`{"operationId":"identity.scim.group-get","parameters":[{"name":"resource_id","in":"path","required":true,"schema":{"type":"string"}}],"security":[],"responses":{"204":{"description":"Test fixture"}}}`)}
	build := func(ops ...identityhttp.OperationDescriptor) http.Handler {
		t.Helper()
		h, _, err := identityhttp.NewRouter(policy, ops, nil)
		if err != nil {
			t.Fatal(err)
		}
		return h
	}
	selected, replaceOnly, getOnly := build(get, replace), build(replace), build(get)
	for _, row := range []struct {
		name, method, path, wantID string
		router                     http.Handler
		encoding                   bool
		length                     int64
		status                     int
	}{
		{"selected", "PUT", path, "Group_1-a.~", selected, false, 1, 200},
		{"encoding", "PUT", path, "Group_1-a.~", selected, true, 1, 415},
		{"known overflow", "PUT", path, "Group_1-a.~", selected, false, maximum + 1, 413},
		{"streamed overflow", "PUT", path, "Group_1-a.~", selected, false, -1, 413},
		{"get still selected", "GET", path, "", selected, false, 1, 204},
		{"get not implied", "GET", path, "", replaceOnly, false, 1, 405},
		{"put not implied", "PUT", path, "", getOnly, true, 1, 400},
		{"encoded alias", "PUT", "/scim/v2/Groups/%47roup", "", selected, true, 1, 400},
		{"reserved search", "PUT", "/scim/v2/Groups/.search", "", selected, true, 1, 400},
		{"wrong collection", "PUT", "/scim/v2/Users/Group_1-a.~", "", selected, true, 1, 400},
	} {
		t.Run(row.name, func(t *testing.T) {
			r := corsRequest(row.method, row.path, "")
			r.ContentLength = row.length
			size := row.length
			if size < 0 {
				size = maximum + 1
			}
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", int(size))))
			if row.encoding {
				r.Header.Set("Content-Encoding", "gzip")
			}
			w := httptest.NewRecorder()
			row.router.ServeHTTP(w, r)
			if w.Code != row.status || w.Header().Get("X-Test-Resource") != row.wantID {
				t.Fatalf("status=%d resource=%q; want %d and %q", w.Code, w.Header().Get("X-Test-Resource"), row.status, row.wantID)
			}
			if row.method == "PUT" && row.status != 400 && w.Header().Get("Content-Type") != "application/scim+json" {
				t.Fatal("selected Group Replace lost its SCIM media type")
			}
		})
	}
}
