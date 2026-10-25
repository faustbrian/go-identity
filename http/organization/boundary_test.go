package organizationhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	organization "github.com/faustbrian/go-organization"
)

func TestOrganizationLateOwnerEvidenceAndInvalidProjectionDeny(t *testing.T) {
	for name, change := range map[string]func(*organization.View){
		"tenant":          func(v *organization.View) { v.Organization.TenantID = "other" },
		"actor":           func(v *organization.View) { v.Actor.UserID = "other" },
		"oversized-name":  func(v *organization.View) { v.Organization.Name = strings.Repeat("x", 257) },
		"inactive-member": func(v *organization.View) { v.Members[0].Active = false },
		"cursor":          func(v *organization.View) { v.NextCursor = "unrelated" },
	} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			f.port.changeRead = change
			w := serve(t, handler(t, f), request(f, "/v1/organization/member/list?organizationID=organization-a", "", false))
			if w.Code != 503 || strings.Contains(w.Body.String(), "Native organization") {
				t.Fatal("invalid native projection disclosed data", w.Code)
			}
		})
	}
	f := newFixture(t)
	f.port.beforeCall = func() { f.now = f.now.Add(time.Hour) }
	w := serve(t, handler(t, f), request(f, "/v1/organization/create", `{"name":"Name","slug":"slug"}`, true))
	if w.Code != 503 || !strings.Contains(w.Body.String(), `"commitOutcome":"committed"`) || !strings.Contains(w.Body.String(), `"committed":true`) {
		t.Fatal("late expiry fabricated rollback or discarded known original outcome", w.Code)
	}
	f = newFixture(t)
	f.port.changeMutation = func(out *organization.StoreResult) { out.Receipt.Feature.AfterVersion = 99 }
	w = serve(t, handler(t, f), request(f, "/v1/organization/create", `{"name":"Name","slug":"slug"}`, true))
	if w.Code != 503 || strings.Contains(w.Body.String(), `"committed":true`) || !strings.Contains(w.Body.String(), `"commitOutcome":"unknown"`) {
		t.Fatal("fabricated transition receipt became success", w.Code)
	}
}

func TestOrganizationRealMiddlewareCannotReplaceFrozenCustodyOrIssueCredentials(t *testing.T) {
	f := newFixture(t)
	seen := 0
	m := []identityhttp.MiddlewareDescriptor{{Owner: "organization", Middleware: identityhttp.Middleware{Name: "custody", Phase: identityhttp.MiddlewareBeforeHandler, Order: 1, Handler: func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			state, ok := identityhttp.PipelineValue[organizationhttp.State](r)
			tenant, user, authenticated := state.Principal()
			if !ok || !authenticated || tenant != "tenant-a" || user != "user-a" {
				t.Fatal("hook did not observe the real authenticated boundary")
			}
			seen++
			if _, err := json.Marshal(state); err == nil || !strings.Contains(fmt.Sprintf("%#v", state), "redacted") {
				t.Fatal("state disclosed immutable credentials")
			}
			r.Header.Set("Authorization", "Bearer replacement")
			r.Host = "other.example"
			w.Header()["sEt-CoOkIe"] = []string{"forbidden=credential"}
			w.Header().Set("Trailer", "Authorization")
			next.ServeHTTP(w, r)
			w.Header().Set("X-CSRF-Token", "forbidden")
			w.Header()[http.TrailerPrefix+"X-MFA-Token"] = []string{"forbidden"}
		})
	}}}}
	feature, err := organizationhttp.NewFeatureWithMiddleware(organizationhttp.FeatureConfig{Config: f.c, Create: true}, m)
	if err != nil {
		t.Fatal(err)
	}
	h, err := identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	w := serve(t, h, request(f, "/v1/organization/create", `{"name":"Name","slug":"slug"}`, true))
	if w.Code != 200 || seen != 1 || f.port.lastCreate.Authentication.Bearer.Token() != f.wire || f.port.lastCreate.Authentication.TenantID != "tenant-a" || w.Header().Get("Trailer") != "" {
		t.Fatal("hook replaced original operation custody", w.Code)
	}
	f = newFixture(t)
	m[0].Middleware.Handler = func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { f.now = f.now.Add(time.Hour); next.ServeHTTP(w, r) })
	}
	feature, err = organizationhttp.NewFeatureWithMiddleware(organizationhttp.FeatureConfig{Config: f.c, Create: true}, m)
	if err != nil {
		t.Fatal(err)
	}
	h, err = identityhttp.NewSelectedHandler(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	if w = serve(t, h, request(f, "/v1/organization/create", `{"name":"Name","slug":"slug"}`, true)); w.Code != 503 || f.port.calls != 0 {
		t.Fatal("hook extended original owner evidence", w.Code)
	}
}

func TestOrganizationActualResponsesConformToConcreteWire(t *testing.T) {
	for _, tc := range []struct {
		path, body string
		key        bool
		mode       int
	}{
		{"/v1/organization/create", `{"name":"Name","slug":"slug"}`, true, 0},
		{"/v1/organization/member/add", `{"organizationID":"organization-a","userID":"target-user","role":"member","organizationVersion":3,"memberVersion":0}`, true, 0},
		{"/v1/organization/member/remove", `{"organizationID":"organization-a","userID":"target-user","organizationVersion":4,"memberVersion":1}`, false, 0},
		{"/v1/organization/get?organizationID=organization-a", "", false, 0},
		{"/v1/organization/member/list?organizationID=organization-a", "", false, 0},
		{"/v1/organization/create", `{"name":"Name","slug":"slug"}`, true, 1},
		{"/v1/organization/create", `{"name":"Name","slug":"slug"}`, true, 2},
		{"/v1/organization/create", `{"name":"Name","slug":"slug","tenantID":"other"}`, true, 0},
	} {
		f := newFixture(t)
		if tc.mode == 1 {
			f.rate.mode = 1
		}
		if tc.mode == 2 {
			f.port.outcome = 3
		}
		feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, Create: true, Get: true, MemberList: true, MemberAdd: true, MemberRemove: true})
		if err != nil {
			t.Fatal(err)
		}
		h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
		if err != nil {
			t.Fatal(err)
		}
		r := request(f, tc.path, tc.body, tc.key)
		w := serve(t, h, r)
		parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		node := parsed.Raw()
		for _, key := range []string{"paths", r.URL.Path, strings.ToLower(r.Method), "responses", strconv.Itoa(w.Code), "content", "application/json", "schema"} {
			var ok bool
			node, ok = node.Lookup(key)
			if !ok {
				t.Fatal("actual response missing from concrete wire", w.Code)
			}
		}
		instance, err := parse.JSON(t.Context(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
		if err != nil {
			t.Fatal(err)
		}
		report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
		if err != nil || !report.Valid() {
			t.Fatal("actual response violates advertised wire", w.Code, err, report.Diagnostics())
		}
		var forbidden map[string]any
		json.Unmarshal(w.Body.Bytes(), &forbidden)
		forbidden["credential"] = "forbidden"
		body, _ := json.Marshal(forbidden)
		instance, _ = parse.JSON(t.Context(), bytes.NewReader(body), parse.DefaultLimits())
		report, err = validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{})
		if err != nil || report.Valid() {
			t.Fatal("wire permits credential-bearing response")
		}
	}
}

func FuzzOrganizationHTTPBoundary(f *testing.F) {
	fixture := newFixture(f)
	h := handler(f, fixture)
	f.Add(`{"name":"Name","slug":"slug"}`, "valid", "", uint8(0))
	f.Add(`{"organizationID":"organization-a","userID":"target-user","role":"member","organizationVersion":3,"memberVersion":0}`, "valid", "", uint8(1))
	f.Add(`{"organizationID":"organization-a","userID":"target-user","organizationVersion":4,"memberVersion":1}`, "valid", "", uint8(2))
	f.Add("", "valid", "organizationID=organization-a", uint8(3))
	f.Add(`{"name":"Name","Name":"duplicate","slug":"slug"}`, "Bearer  malformed", "tenantID=other", uint8(0))
	f.Fuzz(func(t *testing.T, body, auth, query string, kind uint8) {
		if len(body) > 16384 || len(auth) > 8192 || len(query) > 4096 {
			return
		}
		paths := []string{"/v1/organization/create", "/v1/organization/member/add", "/v1/organization/member/remove", "/v1/organization/get"}
		mode := kind % 4
		if mode == 3 {
			body = ""
		}
		r := request(fixture, paths[mode], body, mode < 2)
		r.URL.RawQuery = query
		if auth != "valid" {
			r.Header.Set("Authorization", auth)
		}
		if kind&4 != 0 {
			r.Header.Add("authorization", r.Header.Get("Authorization"))
		}
		if kind&8 != 0 {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			r = r.WithContext(ctx)
		}
		reads, calls := fixture.reads.Load(), fixture.port.calls
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if fixture.port.calls-calls > 1 || fixture.reads.Load()-reads > 1 {
			t.Fatal("hostile request repeated an owned stage")
		}
		if (w.Code == 400 || w.Code == 421) && (fixture.port.calls != calls || fixture.reads.Load() != reads) {
			t.Fatal("invalid envelope reached native owners")
		}
		if strings.Contains(w.Body.String(), fixture.wire) || w.Header().Get("Set-Cookie") != "" {
			t.Fatal("hostile request disclosed credentials")
		}
		if w.Body.Len() > 1<<20 {
			t.Fatal("response bound exceeded")
		}
	})
}
