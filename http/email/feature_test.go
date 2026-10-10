package emailhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	email "github.com/faustbrian/go-identity/email"
	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestConfirmationFeatureIsExplicitAndDocumented(t *testing.T) {
	c, s, body := fixture(t)
	f, err := emailhttp.NewConfirmationFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	var d map[string]any
	if json.Unmarshal(doc.JSON(), &d) != nil {
		t.Fatal("invalid OpenAPI")
	}
	paths := d["paths"].(map[string]any)
	if len(paths) != 1 || paths["/v1/email/verification-confirm"] == nil || s.calls != 0 || s.sources != 0 {
		t.Fatal("construction selected extra routes or ran owners")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, request(body))
	if w.Code != 200 || s.calls != 1 {
		t.Fatal("selected handler not real", w.Code)
	}
	off, offDoc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{})
	if err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	off.ServeHTTP(w, request(body))
	if w.Code != 404 || strings.Contains(string(offDoc.JSON()), "verification-confirm") || s.calls != 1 {
		t.Fatal("omission retained route or metadata")
	}
}

func TestConfirmationActualResponsesMatchWire(t *testing.T) {
	for _, mode := range []string{"fresh", "replay", "unknown", "input", "origin", "host", "method", "http"} {
		t.Run(mode, func(t *testing.T) {
			c, s, body := fixture(t)
			if mode == "fresh" || mode == "unknown" {
				s.result = func(r email.VerificationConfirmRequest) (email.VerificationConfirmResult, error) {
					if mode == "unknown" {
						return receipt(t, r, identity.CommitOutcomeUnknown, false, false), nil
					}
					return receipt(t, r, identity.CommitOutcomeCommitted, false, true), nil
				}
			}
			feature, err := emailhttp.NewConfirmationFeature(c)
			if err != nil {
				t.Fatal(err)
			}
			ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: c.Network, HandlerTimeout: c.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
			if err != nil {
				t.Fatal(err)
			}
			r := request(body)
			want := 200
			media := "application/json"
			switch mode {
			case "unknown":
				want = 503
			case "input":
				r = request(`{"userID":"other"}`)
				want = 400
			case "origin":
				r.Header.Set("Origin", "https://foreign.example")
				want = 403
				media = "text/plain"
			case "host":
				r.Host = "foreign.example"
				want = 421
			case "method":
				r.Method = "GET"
				want = 405
			case "http":
				r.TLS = nil
				r.URL.Scheme = "http"
				want = 403
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != want || !strings.HasPrefix(w.Header().Get("Content-Type"), media) {
				t.Fatal("wrong wire response", w.Code)
			}
			parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			node := parsed.Raw()
			for _, key := range []string{"paths", "/v1/email/verification-confirm", "post", "responses", strconv.Itoa(w.Code), "content", media, "schema"} {
				var ok bool
				node, ok = node.Lookup(key)
				if !ok {
					t.Fatal("actual response missing from schema")
				}
			}
			response := w.Body.Bytes()
			if media == "text/plain" {
				response, _ = json.Marshal(string(response))
			}
			instance, err := parse.JSON(context.Background(), bytes.NewReader(response), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatalf("wire response mismatch: %v %+v", err, report.Diagnostics())
			}
			if media == "application/json" {
				var bad map[string]any
				json.Unmarshal(response, &bad)
				bad["credential"] = "forbidden"
				encoded, _ := json.Marshal(bad)
				instance, _ = parse.JSON(context.Background(), bytes.NewReader(encoded), parse.DefaultLimits())
				report, err = validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{})
				if err != nil || report.Valid() {
					t.Fatal("wire permits credential-bearing response")
				}
			}
		})
	}
}
