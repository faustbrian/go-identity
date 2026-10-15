package emailhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	emailhttp "github.com/faustbrian/go-identity/http/email"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestRemovalSchemaRequiresReplacementOnlyWhenSelected(t *testing.T) {
	c, _, r := removalFixture(t)
	wire, _ := io.ReadAll(r.Body)
	f, err := emailhttp.NewFeature(emailhttp.FeatureConfig{AddressRemove: &c})
	if err != nil {
		t.Fatal(err)
	}
	_, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Removal", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	schema := parsed.Raw()
	for _, key := range []string{"paths", "/v1/email/address-remove", "post", "requestBody", "content", "application/json", "schema"} {
		var ok bool
		schema, ok = schema.Lookup(key)
		if !ok {
			t.Fatal("selected removal schema unavailable")
		}
	}
	for _, mode := range []string{"legacy", "replacement", "missing-id", "missing-version", "unknown", "extraneous"} {
		t.Run(mode, func(t *testing.T) {
			var body map[string]string
			_ = json.Unmarshal(wire, &body)
			if mode != "legacy" {
				body["primaryDisposition"] = "replace-primary"
				body["replacementAddressID"] = "remaining-address"
				body["expectedReplacementIdentifierVersion"] = "5"
				body["expectedReplacementVerificationVersion"] = "7"
			}
			switch mode {
			case "missing-id":
				delete(body, "replacementAddressID")
			case "missing-version":
				delete(body, "expectedReplacementIdentifierVersion")
			case "unknown":
				body["tenantID"] = "foreign"
			case "extraneous":
				body["primaryDisposition"] = "leave-unassigned"
			}
			encoded, _ := json.Marshal(body)
			instance, err := parse.JSON(context.Background(), bytes.NewReader(encoded), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(t.Context(), parsed, schema, instance, validate.InstanceOptions{})
			want := mode == "legacy" || mode == "replacement"
			if err != nil || report.Valid() != want {
				t.Fatal("replacement wire shape differs from selected handler", mode, err)
			}
		})
	}
}
