package sessionhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	sessionhttp "github.com/faustbrian/go-identity/http/session"
	"github.com/faustbrian/go-identity/session"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestSessionDocumentMatchesActualSelectedWire(t *testing.T) {
	for _, mode := range []session.CredentialKind{session.CredentialCookie, session.CredentialBearer} {
		f := newLogout(t, mode)
		feature, err := sessionhttp.NewFeature(f.config)
		if err != nil {
			t.Fatal(err)
		}
		h, doc, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		var document struct {
			Paths map[string]map[string]struct {
				Security []map[string][]string `json:"security"`
			} `json:"paths"`
			Components struct {
				SecuritySchemes map[string]map[string]string `json:"securitySchemes"`
			} `json:"components"`
		}
		if err := json.Unmarshal(doc.JSON(), &document); err != nil {
			t.Fatal(err)
		}
		schemeName := "SessionBearer"
		if mode == session.CredentialCookie {
			schemeName = "SessionCookie"
		}
		if len(document.Components.SecuritySchemes) != 1 || document.Components.SecuritySchemes[schemeName] == nil {
			t.Fatal("advertised the wrong credential transport")
		}
		scheme := document.Components.SecuritySchemes[schemeName]
		if mode == session.CredentialCookie {
			cookie, _ := f.config.Cookie.DeletionAttributes()
			if scheme["type"] != "apiKey" || scheme["in"] != "cookie" || scheme["name"] != cookie.Name {
				t.Fatal("incorrect cookie scheme")
			}
		} else if scheme["type"] != "http" || scheme["scheme"] != "bearer" {
			t.Fatal("incorrect bearer scheme")
		}
		for path, methods := range document.Paths {
			for _, operation := range methods {
				if len(operation.Security) != 2 || len(operation.Security[0]) != 0 || len(operation.Security[1]) != 1 {
					t.Fatalf("optional credentials not declared for %s", path)
				}
				if scopes, present := operation.Security[1][schemeName]; !present || len(scopes) != 0 {
					t.Fatal("operation advertises another credential transport")
				}
			}
		}
		assertResponse := func(r *http.Request) *httptest.ResponseRecorder {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			node := parsed.Raw()
			for _, key := range []string{"paths", r.URL.Path, strings.ToLower(r.Method), "responses", strconv.Itoa(w.Code), "content", "application/json", "schema"} {
				var ok bool
				node, ok = node.Lookup(key)
				if !ok {
					t.Fatalf("missing wire schema for %s status%d", r.URL.Path, w.Code)
				}
			}
			instance, err := parse.JSON(context.Background(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatalf("actual wire rejected: %v %+v", err, report.Diagnostics())
			}
			for _, mutation := range []string{`{"authenticated":"yes","needsRefresh":false}`, `{"signedOut":true,"clearBearer":false,"commitOutcome":"invented"}`, `{"error":"unavailable","credential":"secret"}`} {
				bad, _ := parse.JSON(context.Background(), strings.NewReader(mutation), parse.DefaultLimits())
				report, err := validate.SchemaInstance(context.Background(), parsed, node, bad, validate.InstanceOptions{})
				if err != nil || report.Valid() {
					t.Fatal("invalid/domain-only payload admitted")
				}
			}
			if r.URL.Path == "/v1/session/signout" && w.Code == 200 {
				wrong := strings.ReplaceAll(w.Body.String(), `"clearBearer":true`, `"clearBearer":false`)
				if mode == session.CredentialCookie {
					wrong = strings.ReplaceAll(w.Body.String(), `"clearBearer":false`, `"clearBearer":true`)
				}
				bad, _ := parse.JSON(context.Background(), strings.NewReader(wrong), parse.DefaultLimits())
				report, err := validate.SchemaInstance(context.Background(), parsed, node, bad, validate.InstanceOptions{})
				if err != nil || report.Valid() {
					t.Fatal("schema accepts clearing the wrong credential transport")
				}
			}
			return w
		}
		assertResponse(request(f.fixture, true))
		assertResponse(request(f.fixture, false))
		for _, tc := range []struct {
			outcome identity.CommitOutcome
			name    string
		}{
			{identity.CommitOutcomeUnknown, "unknown"},
			{identity.CommitOutcomeNotCommitted, "not_committed"},
			{identity.CommitOutcomeConflict, "conflict"},
			{identity.CommitOutcomeInProgress, "in_progress"},
			{identity.CommitOutcomeCommitted, "committed"},
		} {
			f.outcome, f.executionError, f.observation.Active = tc.outcome, nil, true
			if tc.outcome == identity.CommitOutcomeCommitted {
				f.executionError = errors.New("private backend diagnostic")
			}
			w := assertResponse(logoutRequest(f, true))
			var out sessionhttp.SignOutResponse
			if w.Code == 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.CommitOutcome != tc.name || out.SignedOut || out.ClearBearer || out.Recovery == nil || out.Recovery.CommandID != f.recovery.CommandID || out.Recovery.RecordID != f.recovery.RecordID || len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatalf("failed outcome %s lost original recovery or cleared credentials", tc.name)
			}
		}
		f.outcome, f.executionError, f.observation.Active = identity.CommitOutcomeCommitted, nil, true
		r := logoutRequest(f, true)
		if mode == session.CredentialCookie {
			r.Header.Del("X-CSRF-Token")
			assertResponse(r)
		}
		assertResponse(logoutRequest(f, true))
		r = logoutRequest(f, false)
		ctx, cancel := context.WithCancel(r.Context())
		cancel()
		assertResponse(r.WithContext(ctx))
		text := string(doc.JSON())
		if strings.Contains(text, "lookupDigest") || strings.Contains(text, "tenant.host_mapping") || strings.Contains(text, "trusted.example") {
			t.Fatal("runtime/private configuration exported")
		}
		if mode == session.CredentialBearer && strings.Contains(text, `"X-CSRF-Token"`) {
			t.Fatal("bearer advertises cookie CSRF")
		}
	}
}
