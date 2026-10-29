package apikeyhttp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/faustbrian/go-identity/apikey"
	identityhttp "github.com/faustbrian/go-identity/http"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestMetadataDocumentMatchesActualSelectedRouterResponses(t *testing.T) {
	for _, variant := range []string{"get", "list", "absent-expiry", "denied", "plaintext"} {
		t.Run(variant, func(t *testing.T) {
			f, owner := metadataFixture(t)
			feature, err := NewFeature(f.config)
			if err != nil {
				t.Fatal(err)
			}
			ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: f.config.Network, HandlerTimeout: 3 * time.Second, Document: identityhttp.DocumentConfig{Title: "API key metadata", Version: "1"}}, ops, nil)
			if err != nil {
				t.Fatal("selected metadata router/document construction", err)
			}
			action := "get"
			if variant == "list" {
				action = "list"
			}
			r := metadataRequest(f, action)
			want := 200
			if variant == "absent-expiry" {
				owner.record.ExpiresAt = time.Time{}
			}
			if variant == "denied" {
				owner.err, want = apikey.ErrDenied, 403
			}
			if variant == "plaintext" {
				r.TLS, want = nil, 403
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want {
				t.Fatal("actual selected metadata response", w.Code)
			}
			parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			node := parsed.Raw()
			for _, name := range []string{"paths", r.URL.Path, "get", "responses", strconv.Itoa(w.Code), "content", "application/json", "schema"} {
				var present bool
				node, present = node.Lookup(name)
				if !present {
					t.Fatal("actual metadata response has no selected wire schema", w.Code)
				}
			}
			body, err := parse.JSON(t.Context(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
			if err != nil {
				t.Fatal("actual metadata response is not JSON")
			}
			report, err := validate.SchemaInstance(t.Context(), parsed, node, body, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatal("actual metadata response violates its selected wire schema", variant)
			}
			for _, path := range []string{"/v1/apikey/create", "/v1/apikey/rotate", "/v1/apikey/delete"} {
				request := metadataRequest(f, "get")
				request.Method, request.URL.Path, request.URL.RawQuery, request.RequestURI = http.MethodPost, path, "", path
				denied := httptest.NewRecorder()
				h.ServeHTTP(denied, request)
				if denied.Code != 404 {
					t.Fatal("read-only graph exposed a mutation route", path, denied.Code)
				}
			}
			if strings.Contains(string(doc.JSON()), `"Idempotency-Key"`) {
				t.Fatal("read-only document requires a mutation key")
			}
		})
	}
}
