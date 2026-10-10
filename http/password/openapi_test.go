package passwordhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestPasswordChangeDocumentMatchesActualWire(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		for _, scenario := range []string{"success", "unknown", "committed-error", "conflict", "busy", "proof-outage", "malformed", "inactive", "csrf", "host", "method", "plaintext", "origin"} {
			if mode == session.CredentialBearer && (scenario == "csrf" || scenario == "origin") {
				continue
			}
			t.Run(strconv.Itoa(int(mode))+"/"+scenario, func(t *testing.T) {
				f := newChange(t, mode)
				feature, err := passwordhttp.NewChangeFeature(f.config)
				if err != nil {
					t.Fatal(err)
				}
				ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
				if err != nil {
					t.Fatal(err)
				}
				h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: f.config.Network, HandlerTimeout: f.config.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"}}, ops, nil)
				if err != nil {
					t.Fatal(err)
				}
				var root struct {
					Paths map[string]map[string]struct {
						Security []map[string][]string `json:"security"`
					} `json:"paths"`
					Components struct {
						SecuritySchemes map[string]map[string]string `json:"securitySchemes"`
					} `json:"components"`
				}
				if json.Unmarshal(doc.JSON(), &root) != nil || doc.Version() != "3.1.1" || len(root.Paths) != 1 {
					t.Fatal("wrong selected document")
				}
				scheme := "PasswordChangeBearer"
				if mode == session.CredentialCookie {
					scheme = "PasswordChangeCookie"
				}
				security := root.Paths["/v1/password/change"]["post"].Security
				if len(security) != 1 || len(security[0]) != 1 || security[0][scheme] == nil || len(root.Components.SecuritySchemes) != 1 {
					t.Fatal("credential mode missing or anonymous fallback advertised")
				}
				definition := root.Components.SecuritySchemes[scheme]
				if mode == session.CredentialCookie {
					if definition["type"] != "apiKey" || definition["in"] != "cookie" || definition["name"] != "__Host-identity_session" {
						t.Fatal("wrong selected cookie name")
					}
				} else if definition["type"] != "http" || definition["scheme"] != "bearer" || strings.Contains(string(doc.JSON()), `"X-CSRF-Token"`) {
					t.Fatal("bearer borrowed cookie protection")
				}
				if strings.Contains(string(doc.JSON()), "tenant.example") || strings.Contains(string(doc.JSON()), "password-a") || strings.Contains(string(doc.JSON()), "lookupDigest") {
					t.Fatal("runtime custody/configuration exported")
				}
				r := changeRequest(f)
				want, media := 200, "application/json"
				switch scenario {
				case "unknown":
					f.work.result.Outcome, f.work.err = identity.CommitOutcomeUnknown, identity.UnknownCommitError{CommandID: f.work.result.CommandID}
					want = 503
				case "committed-error":
					f.work.err = context.DeadlineExceeded
					want = 503
				case "conflict":
					f.work.result.Outcome, f.work.result.CommandID, f.work.err = identity.CommitOutcomeConflict, "", identity.ConflictError{}
					want = 409
				case "busy":
					f.work.result.Outcome, f.work.err = identity.CommitOutcomeInProgress, identity.InProgressError{RetryAfter: time.Second}
					want = 409
				case "proof-outage":
					f.work.proofErr = context.DeadlineExceeded
					want = 503
				case "malformed":
					r.Header.Add("Idempotency-Key", "second")
					want = 400
				case "inactive":
					f.reader.observation.Active = false
					want = 401
				case "csrf":
					r.Header.Del("X-CSRF-Token")
					want = 403
				case "host":
					r.Host = "foreign.example"
					want = 421
				case "method":
					r.Method = http.MethodGet
					want = 405
				case "plaintext":
					r.TLS = nil
					r.URL.Scheme = "http"
					want = 403
				case "origin":
					r.Header.Set("Origin", "https://foreign.example")
					want, media = 403, "text/plain"
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				if w.Code != want || !strings.HasPrefix(w.Header().Get("Content-Type"), media) {
					t.Fatalf("wrong status/media: %d", w.Code)
				}
				if w.Header().Get("Cache-Control") != "no-store" || len(w.Header().Values("Set-Cookie")) != 0 || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatal("response leaked credential or cache permission")
				}
				parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "success" {
					requestSchema := parsed.Raw()
					for _, key := range []string{"paths", "/v1/password/change", "post", "requestBody", "content", "application/json", "schema"} {
						var ok bool
						requestSchema, ok = requestSchema.Lookup(key)
						if !ok {
							t.Fatalf("missing request schema: %s", key)
						}
					}
					for _, candidate := range []struct {
						body  string
						valid bool
					}{
						{`{"proofID":"abcdefghijklmnopqrstuv","newPassword":"synthetic-new-password"}`, true},
						{`{"proofID":"short","newPassword":"synthetic-new-password"}`, false},
						{`{"proofID":"abcdefghijklmnopqrstuv","newPassword":""}`, false},
						{`{"proofID":"abcdefghijklmnopqrstuv","newPassword":"synthetic-new-password","tenantID":"other"}`, false},
						{`{"proofID":"abcdefghijklmnopqrstuv","newPassword":"synthetic-new-password","revoke":false}`, false},
						{`{"proofID":"abcdefghijklmnopqrstuv","newPassword":"synthetic-new-password","idempotencyKey":"other"}`, false},
					} {
						instance, e := parse.JSON(context.Background(), strings.NewReader(candidate.body), parse.DefaultLimits())
						if e != nil {
							t.Fatal(e)
						}
						report, e := validate.SchemaInstance(context.Background(), parsed, requestSchema, instance, validate.InstanceOptions{Direction: validate.DirectionRequest})
						if e != nil || report.Valid() != candidate.valid {
							t.Fatal("request schema admitted override or rejected valid original input")
						}
					}
				}
				node := parsed.Raw()
				for _, key := range []string{"paths", "/v1/password/change", "post", "responses", strconv.Itoa(w.Code), "content", media, "schema"} {
					var ok bool
					node, ok = node.Lookup(key)
					if !ok {
						t.Fatalf("missing actual response schema: %s", key)
					}
				}
				body := w.Body.Bytes()
				if media == "text/plain" {
					body, _ = json.Marshal(w.Body.String())
				}
				instance, err := parse.JSON(context.Background(), bytes.NewReader(body), parse.DefaultLimits())
				if err != nil {
					t.Fatal(err)
				}
				report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
				if err != nil || !report.Valid() {
					t.Fatalf("actual response rejected: %v %+v", err, report.Diagnostics())
				}
				if media == "application/json" {
					var mutation map[string]any
					json.Unmarshal(body, &mutation)
					mutation["credential"] = "forbidden"
					badJSON, _ := json.Marshal(mutation)
					bad, _ := parse.JSON(context.Background(), bytes.NewReader(badJSON), parse.DefaultLimits())
					badReport, e := validate.SchemaInstance(context.Background(), parsed, node, bad, validate.InstanceOptions{})
					if e != nil || badReport.Valid() {
						t.Fatal("wire admitted credential/domain-only response field")
					}
				}
			})
		}
	}
}
