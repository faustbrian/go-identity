package oauthserverhttp

import (
	"bytes"
	"encoding/json"
	"mime"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestWorkloadHTTPComposedDenialsMatchWireSchema(t *testing.T) {
	for _, action := range []string{"token", "introspect", "revoke"} {
		for _, boundary := range []struct {
			name, media string
			status      int
			change      func(*http.Request)
		}{
			{"plaintext", "application/json", 403, func(r *http.Request) { r.TLS = nil }},
			{"unknown host", "application/json", 421, func(r *http.Request) { r.Host = "unselected.example" }},
			{"wrong method", "application/json", 405, func(r *http.Request) { r.Method = http.MethodGet }},
			{"malformed path", "application/json", 404, func(r *http.Request) { r.URL.Path = "/oauth2//" + action; r.RequestURI = r.URL.Path }},
			{"foreign origin", "text/plain", 403, func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") }},
		} {
			t.Run(action+"/"+boundary.name, func(t *testing.T) {
				c, store, basic := featureFixture(t)
				h, doc := documentedRouter(t, c)
				w := httptest.NewRecorder()
				r := wireRequest(action, "token=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", basic)
				boundary.change(r)
				h.ServeHTTP(w, r)
				media, _, err := mime.ParseMediaType(w.Header().Get("Content-Type"))
				if err != nil || media != boundary.media || w.Code != boundary.status || store.calls != 0 {
					t.Fatal("shared transport denial or custody changed", w.Code, media)
				}
				assertDocumentedResponse(t, doc, action, w)
			})
		}
	}
	c, store, basic := featureFixture(t)
	store.mode = "panic"
	h, doc := documentedRouter(t, c)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wireRequest("token", "grant_type=client_credentials", basic))
	if w.Code != 503 || store.calls != 1 {
		t.Fatal("router did not bound failed native callback", w.Code)
	}
	assertDocumentedResponse(t, doc, "token", w)
}

func documentedRouter(t *testing.T, c FeatureConfig) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	f, err := NewFeature(t.Context(), c)
	if err != nil {
		t.Fatal(err)
	}
	ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: c.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Workload OAuth", Version: "1"}}, ops, nil)
	if err != nil {
		t.Fatal(err)
	}
	return h, doc
}

func assertDocumentedResponse(t *testing.T, doc identityhttp.OpenAPIDocument, action string, w *httptest.ResponseRecorder) {
	t.Helper()
	parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	media, _, err := mime.ParseMediaType(w.Header().Get("Content-Type"))
	if err != nil {
		t.Fatal(err)
	}
	node := parsed.Raw()
	for _, name := range []string{"paths", "/oauth2/" + action, "post", "responses", strconv.Itoa(w.Code), "content", media, "schema"} {
		var ok bool
		node, ok = node.Lookup(name)
		if !ok {
			t.Fatal("actual response has no composed wire schema", w.Code, media, name)
		}
	}
	body := w.Body.Bytes()
	if media == "text/plain" {
		body, err = json.Marshal(w.Body.String())
		if err != nil {
			t.Fatal(err)
		}
	}
	instance, err := parse.JSON(t.Context(), bytes.NewReader(body), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
	if err != nil || !report.Valid() {
		t.Fatal("actual composed response violates its declared schema", w.Code, media, err)
	}
}
