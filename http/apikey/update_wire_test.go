package apikeyhttp

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestUpdateSelectedDocumentMatchesActualResponse(t *testing.T) {
	for _, variant := range []string{"committed", "empty", "organization", "unknown", "denied"} {
		t.Run(variant, func(t *testing.T) {
			f, o := updateFixture(t)
			body := updateJSON
			if variant != "denied" {
				o.result, o.err = committedUpdate(t, f, variant == "organization"), nil
			}
			if variant == "organization" {
				f.config.OrganizationOwned = true
				body = strings.TrimSuffix(body, "}") + `,"organizationID":"org-a"}`
			}
			if variant == "empty" {
				o.result.Record.Grant = []string{}
				body = strings.Replace(body, `["read"]`, `[]`, 1)
			}
			if variant == "unknown" {
				o.result.Receipt.Outcome = identity.CommitOutcomeUnknown
				o.result.Receipt.AuditEventID = ""
				o.result.Receipt.Feature.BeforeVersion, o.result.Receipt.Feature.AfterVersion = 0, 0
				o.result.Record, o.result.ConfigurationAuthority = nil, nil
			}
			feature, err := NewFeature(f.config)
			if err != nil {
				t.Fatal(err)
			}
			ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil {
				t.Fatal(err)
			}
			h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{Network: f.config.Network, HandlerTimeout: 3 * time.Second, Document: identityhttp.DocumentConfig{Title: "API key update", Version: "1"}}, ops, nil)
			if err != nil {
				t.Fatal(err)
			}
			r := f.request("update", body)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := 200
			if variant == "unknown" {
				want = 503
			}
			if variant == "denied" {
				want = 403
			}
			if w.Code != want {
				t.Fatal("selected update response", w.Code)
			}
			parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			node := parsed.Raw()
			for _, part := range []string{"paths", r.URL.Path, "post", "responses", strconv.Itoa(w.Code), "content", "application/json", "schema"} {
				var ok bool
				node, ok = node.Lookup(part)
				if !ok {
					t.Fatal("selected response schema missing", part)
				}
			}
			instance, err := parse.JSON(t.Context(), bytes.NewReader(w.Body.Bytes()), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(t.Context(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
			if err != nil || !report.Valid() {
				t.Fatal("actual update violates OpenAPI", variant, err)
			}
			var document struct {
				Paths map[string]json.RawMessage `json:"paths"`
			}
			if json.Unmarshal(doc.JSON(), &document) != nil || len(document.Paths) != 1 || document.Paths["/v1/apikey/update"] == nil || strings.Contains(string(doc.JSON()), `"secret"`) {
				t.Fatal("selection advertises unselected route or secret output")
			}
		})
	}
}
