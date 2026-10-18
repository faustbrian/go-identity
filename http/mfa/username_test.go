package mfahttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
)

func TestUsernameTOTPRequiresExactSelectedVariant(t *testing.T) {
	for _, variant := range []string{"username", "", "password", "verification", "unknown", "duplicate", "unselected"} {
		t.Run(variant, func(t *testing.T) {
			c, owner, body, device := handlerFixture(t)
			selection := FeatureConfig{UsernameTOTPVerify: &c}
			if variant == "unselected" {
				selection = FeatureConfig{PasswordTOTPVerify: &c}
			}
			feature, err := NewFeature(selection)
			if err != nil {
				t.Fatal(err)
			}
			ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
			if err != nil || len(ops) != 1 {
				t.Fatal("selected verification operation missing", err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/totp-verify", strings.NewReader(body))
			r.RequestURI = r.URL.RequestURI()
			r.RemoteAddr = "127.0.0.1:4242"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", string(c.Origin))
			if variant != "" {
				r.Header.Set("X-MFA-Variant", variant)
			}
			if variant == "duplicate" {
				r.Header["X-MFA-Variant"] = []string{"username", "username"}
			}
			if variant == "unselected" {
				r.Header.Set("X-MFA-Variant", "username")
			}
			r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
			r.AddCookie(device)
			w := httptest.NewRecorder()
			ops[0].Handler.ServeHTTP(w, r)
			if variant == "username" {
				if w.Code != http.StatusConflict || owner.calls != 1 || owner.reads != 1 {
					t.Fatal("explicit username owner was not reached", w.Code, owner.calls, owner.reads)
				}
			} else if w.Code != http.StatusBadRequest || owner.calls != 0 || owner.reads != 0 || owner.rate.calls != 0 {
				t.Fatal("missing/foreign variant fell back to authentication", w.Code)
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
				t.Fatal("rejected/replayed completion delivered credentials")
			}
			if variant == "username" {
				var document map[string]any
				if json.Unmarshal(ops[0].Wire.Definition, &document) != nil {
					t.Fatal("invalid selected wire")
				}
				found := false
				for _, parameter := range document["parameters"].([]any) {
					p := parameter.(map[string]any)
					if p["name"] == "X-MFA-Variant" {
						values := p["schema"].(map[string]any)["enum"].([]any)
						found = p["required"] == true && len(values) == 1 && values[0] == "username"
					}
				}
				if !found {
					t.Fatal("username-only wire advertises fallback or omits explicit variant")
				}
			}
		})
	}
}
