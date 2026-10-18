package mfahttp

import (
	"encoding/json"
	"slices"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestVerificationWirePreservesEverySelectedOriginAndCallback(t *testing.T) {
	password, _, _, _ := handlerFixture(t)
	password.CallbackURL = string(password.Origin) + "/reset"
	verification := password
	verification.Origin = "https://verification.example"
	verification.CallbackURL = string(verification.Origin) + "/confirm"
	enrollment := EnrollmentConfirmationConfig{Cookie: password.SessionCookie, TrustedOrigins: []identityhttp.Origin{"https://enrollment.example"}}
	wire := selectedBaseVerifyWire(FeatureConfig{PasswordTOTPVerify: &password, VerificationTOTPVerify: &verification, EnrollmentConfirmation: &enrollment})
	var document map[string]any
	if json.Unmarshal(wire.Definition, &document) != nil {
		t.Fatal("selected wire is not JSON")
	}
	var origins, callbacks []string
	for _, parameter := range document["parameters"].([]any) {
		p := parameter.(map[string]any)
		if p["name"] == "Origin" {
			for _, value := range p["schema"].(map[string]any)["enum"].([]any) {
				origins = append(origins, value.(string))
			}
		}
	}
	for _, expected := range []string{string(password.Origin), string(verification.Origin), string(enrollment.TrustedOrigins[0])} {
		if !slices.Contains(origins, expected) {
			t.Fatal("a selected owner's accepted origin is absent from the shared wire")
		}
	}
	var visit func(any)
	visit = func(value any) {
		switch v := value.(type) {
		case map[string]any:
			if properties, ok := v["properties"].(map[string]any); ok {
				if callback, ok := properties["callbackURL"].(map[string]any); ok {
					for _, allowed := range callback["enum"].([]any) {
						callbacks = append(callbacks, allowed.(string))
					}
				}
			}
			for _, child := range v {
				visit(child)
			}
		case []any:
			for _, child := range v {
				visit(child)
			}
		}
	}
	visit(document["requestBody"])
	if !slices.Contains(callbacks, password.CallbackURL) || !slices.Contains(callbacks, verification.CallbackURL) {
		t.Fatal("verification replaced another selected primary's callback")
	}
	wire = selectedBaseVerifyWire(FeatureConfig{VerificationTOTPVerify: &verification})
	if json.Unmarshal(wire.Definition, &document) != nil {
		t.Fatal("verification-only wire is not JSON")
	}
	for _, parameter := range document["parameters"].([]any) {
		p := parameter.(map[string]any)
		if p["name"] == "X-MFA-Variant" {
			if p["required"] != true || !slices.Equal(p["schema"].(map[string]any)["enum"].([]any), []any{"verification"}) {
				t.Fatal("verification-only wire advertises a default or foreign variant")
			}
			return
		}
	}
	t.Fatal("verification-only wire omitted its explicit variant")
}
