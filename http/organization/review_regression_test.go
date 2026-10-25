package organizationhttp_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	organizationhttp "github.com/faustbrian/go-identity/http/organization"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
	organization "github.com/faustbrian/go-organization"
)

func documentedFixture(t *testing.T, f *fixture) (http.Handler, []byte) {
	t.Helper()
	feature, err := organizationhttp.NewFeature(organizationhttp.FeatureConfig{Config: f.c, Create: true, Get: true, MemberList: true, MemberAdd: true, MemberRemove: true})
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return h, doc.JSON()
}
func assertWireResponse(t *testing.T, document []byte, r *http.Request, w *httptest.ResponseRecorder) {
	t.Helper()
	parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(document), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	node := parsed.Raw()
	for _, key := range []string{"paths", r.URL.Path, strings.ToLower(r.Method), "responses", strconv.Itoa(w.Code), "content", "application/json", "schema"} {
		var ok bool
		node, ok = node.Lookup(key)
		if !ok {
			t.Fatal("actual response has no wire schema", w.Code)
		}
	}
	instance, err := parse.JSON(t.Context(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
	if err != nil || !report.Valid() {
		t.Fatal("valid native response violates wire", w.Code, err, report.Diagnostics())
	}
}

func requestConforms(t *testing.T, document []byte, path, body string) bool {
	t.Helper()
	parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(document), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	node := parsed.Raw()
	for _, key := range []string{"paths", path, "post", "requestBody", "content", "application/json", "schema"} {
		var ok bool
		node, ok = node.Lookup(key)
		if !ok {
			t.Fatal("selected request has no concrete wire schema")
		}
	}
	instance, err := parse.JSON(t.Context(), strings.NewReader(body), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionRequest})
	if err != nil {
		t.Fatal(err)
	}
	return report.Valid()
}

func TestOrganizationInvalidNativeOutcomeWithoutErrorDenies(t *testing.T) {
	f := newFixture(t)
	f.port.outcome = identity.CommitOutcomeInvalid
	h, document := documentedFixture(t, f)
	r := request(f, "/v1/organization/create", `{"name":"Name","slug":"slug"}`, true)
	w := serve(t, h, r)
	var out organizationhttp.MutationResponse
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || w.Code != 503 || out.Committed || out.CommitOutcome != "none" || out.Error != "unavailable" || out.CommandID == "" || out.Recovery == nil || out.Recovery.CommandID != out.CommandID {
		t.Fatal("invalid native outcome was accepted or lost safe original correlation", w.Code)
	}
	assertWireResponse(t, document, r, w)
}

func TestOrganizationTerminalVersionResponsesConform(t *testing.T) {
	for _, tc := range []struct {
		path, body string
		key        bool
	}{
		{"/v1/organization/member/add", fmt.Sprintf(`{"organizationID":"organization-a","userID":"target-user","role":"member","organizationVersion":%d,"memberVersion":0}`, uint64(math.MaxUint64-1)), true},
		{"/v1/organization/member/remove", fmt.Sprintf(`{"organizationID":"organization-a","userID":"target-user","organizationVersion":%d,"memberVersion":1}`, uint64(math.MaxUint64-1)), false},
		{"/v1/organization/get?organizationID=organization-a", "", false},
		{"/v1/organization/member/list?organizationID=organization-a", "", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			f := newFixture(t)
			f.port.changeRead = func(v *organization.View) {
				v.Organization.Version = math.MaxUint64
				v.Actor.Version = math.MaxUint64
				v.Members[0].Version = math.MaxUint64
			}
			h, document := documentedFixture(t, f)
			r := request(f, tc.path, tc.body, tc.key)
			w := serve(t, h, r)
			if w.Code != 200 || !strings.Contains(w.Body.String(), strconv.FormatUint(math.MaxUint64, 10)) {
				t.Fatal("terminal native version was refused or truncated", w.Code)
			}
			assertWireResponse(t, document, r, w)
			if r.Method == http.MethodPost {
				if !requestConforms(t, document, r.URL.Path, tc.body) {
					t.Fatal("advanceable predecessor violates request schema")
				}
				for _, field := range []string{"organizationVersion", "memberVersion"} {
					var submitted map[string]json.RawMessage
					if err := json.Unmarshal([]byte(tc.body), &submitted); err != nil {
						t.Fatal(err)
					}
					submitted[field] = json.RawMessage(strconv.FormatUint(math.MaxUint64, 10))
					body, err := json.Marshal(submitted)
					if err != nil {
						t.Fatal(err)
					}
					if requestConforms(t, document, r.URL.Path, string(body)) {
						t.Fatal("terminal version became an advanceable request", field)
					}
					calls, reads := f.port.calls, f.reads.Load()
					denied := serve(t, h, request(f, tc.path, string(body), tc.key))
					if denied.Code != 400 || f.port.calls != calls || f.reads.Load() != reads {
						t.Fatal("terminal expected version reached native owners", field, denied.Code)
					}
				}
			}
		})
	}
}
