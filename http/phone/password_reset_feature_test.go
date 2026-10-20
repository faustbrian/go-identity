package phonehttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	phonehttp "github.com/faustbrian/go-identity/http/phone"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func TestPasswordResetFeatureSelectsOnlyDocumentedReset(t *testing.T) {
	c, o, r := resetTransportFixture(t)
	feature, err := phonehttp.NewPasswordResetFeature(c)
	if err != nil {
		t.Fatal(err)
	}
	h, doc, err := identityhttp.NewDocumentedHandler(t.Context(), identityhttp.DocumentConfig{Title: "Identity", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Paths map[string]json.RawMessage `json:"paths"`
	}
	if json.Unmarshal(doc.JSON(), &raw) != nil || len(raw.Paths) != 2 || raw.Paths["/v1/phone/password-reset-request"] == nil || raw.Paths["/v1/phone/password-reset-complete"] == nil {
		t.Fatal("feature advertised unrelated or missing phone operations")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 202 || len(o.events) != 2 {
		t.Fatal("documented operation did not use actual handler", w.Code)
	}
	parsed, err := openapi.ParseJSON(t.Context(), bytes.NewReader(doc.JSON()), parse.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []string{"request", "complete"} {
		node := parsed.Raw()
		for _, key := range []string{"paths", "/v1/phone/password-reset-" + operation, "post", "requestBody", "content", "application/json", "schema"} {
			var ok bool
			node, ok = node.Lookup(key)
			if !ok {
				t.Fatal("request schema absent")
			}
		}
		body := `{"commandID":"AgICAgICAgICAgICAgICAg","riskIssuanceCommandID":"AwMDAwMDAwMDAwMDAwMDAw","flowID":"BAQEBAQEBAQEBAQEBAQEBA","number":"+12025550123"}`
		if operation == "complete" {
			_, _, original := resetTransportFixture(t)
			original = resetCompleteTransportRequest(t, original, c.Now())
			var b bytes.Buffer
			_, _ = b.ReadFrom(original.Body)
			body = b.String()
		}
		for _, tc := range []struct {
			body  string
			valid bool
		}{{body, true}, {strings.TrimSuffix(body, "}") + `,"userID":"override"}`, false}, {strings.TrimSuffix(body, "}") + `,"remember":false}`, false}} {
			input, err := parse.JSON(context.Background(), strings.NewReader(tc.body), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			report, err := validate.SchemaInstance(context.Background(), parsed, node, input, validate.InstanceOptions{Direction: validate.DirectionRequest})
			if err != nil || report.Valid() != tc.valid {
				t.Fatal("reset wire accepted alternate authority or rejected selected request", operation, err)
			}
		}
	}
}

func TestPasswordResetFeatureRequiresAllExplicitOwners(t *testing.T) {
	if _, err := phonehttp.NewPasswordResetFeature(phonehttp.PasswordResetConfig{}); err == nil {
		t.Fatal("zero config exposed reset")
	}
	c, _, _ := resetTransportFixture(t)
	for _, mode := range []string{"service", "risk", "source", "number", "delivery-rate", "completion-rate"} {
		other := c
		switch mode {
		case "service":
			other.Service = nil
		case "risk":
			other.Risk = nil
		case "source":
			other.Source = nil
		case "number":
			other.NumberPolicy = nil
		case "delivery-rate":
			other.DeliveryRate = nil
		case "completion-rate":
			other.CompletionRate = nil
		}
		if _, err := phonehttp.NewPasswordResetFeature(other); err == nil {
			t.Fatal("missing owner exposed reset", mode)
		}
	}
}
