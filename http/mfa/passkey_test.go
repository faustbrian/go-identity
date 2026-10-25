package mfahttp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/mfa"
)

func TestTOTPDeliveryNeverSubstitutesPasskeyPasswordOrMagicPrimary(t *testing.T) {
	for _, selected := range []string{"passkey", "password", "magic"} {
		for _, returned := range []string{"passkey", "password", "magic"} {
			t.Run(selected+"/"+returned, func(t *testing.T) {
				c, owner, body, device := handlerFixture(t)
				c.PasskeyPrimary, c.PasswordPrimary = selected == "passkey", selected == "password"
				owner.result = func(r mfa.TotpVerifyRequest) (mfa.TotpVerifyResult, error) {
					profile := c
					profile.PasskeyPrimary, profile.PasswordPrimary = returned == "passkey", returned == "password"
					return issuance(t, profile, r), nil
				}
				h, err := NewTOTPVerifyHandler(c)
				if err != nil {
					t.Fatal(err)
				}
				r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/totp-verify", strings.NewReader(body))
				r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "127.0.0.1:4242"
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", string(c.Origin))
				r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
				r.AddCookie(device)
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				var out TOTPVerifyResponse
				if json.Unmarshal(w.Body.Bytes(), &out) != nil {
					t.Fatal("completion response malformed")
				}
				if selected == returned {
					if w.Code != 200 || !out.SignedIn || w.Header().Get("Set-Cookie") == "" || w.Header().Get("X-CSRF-Token") == "" {
						t.Fatal("matching original MFA provenance lost delivery", w.Code)
					}
				} else if w.Code == 200 || out.SignedIn || out.SessionID != "" || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
					t.Fatal("completion substituted another primary's MFA session", w.Code)
				}
			})
		}
	}
	c, _, _, _ := handlerFixture(t)
	c.PasskeyPrimary, c.PasswordPrimary = true, true
	if h, err := NewTOTPVerifyHandler(c); err == nil || h != nil {
		t.Fatal("ambiguous primary delivery policy was selected")
	}
}

func TestPasskeyTOTPFeatureRequiresExactExplicitVariant(t *testing.T) {
	for _, variant := range []string{"passkey", "", "password", "verification", "duplicate", "case-duplicate"} {
		t.Run(variant, func(t *testing.T) {
			c, owner, body, device := handlerFixture(t)
			f, err := NewFeature(FeatureConfig{PasskeyTOTPVerify: &c})
			if err != nil {
				t.Fatal(err)
			}
			ops, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: []identityhttp.Feature{f}})
			if err != nil || len(ops) != 1 {
				t.Fatal("selected passkey completion operation missing", err)
			}
			r := httptest.NewRequest(http.MethodPost, "https://tenant.example/v1/mfa/totp-verify", strings.NewReader(body))
			r.RequestURI, r.RemoteAddr = r.URL.RequestURI(), "127.0.0.1:4242"
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Origin", string(c.Origin))
			if variant != "" {
				r.Header.Set("X-MFA-Variant", variant)
			}
			if variant == "duplicate" {
				r.Header["X-MFA-Variant"] = []string{"passkey", "passkey"}
			}
			if variant == "case-duplicate" {
				r.Header["X-MFA-Variant"], r.Header["x-mfa-variant"] = []string{"passkey"}, []string{"passkey"}
			}
			r.AddCookie(&http.Cookie{Name: "__Host-identity_flow", Value: strings.Repeat("A", 43)})
			r.AddCookie(device)
			w := httptest.NewRecorder()
			ops[0].Handler.ServeHTTP(w, r)
			if variant == "passkey" {
				if w.Code != 409 || owner.calls != 1 {
					t.Fatal("explicit passkey variant did not reach its native replay observation", w.Code)
				}
			} else if w.Code != 400 || owner.calls != 0 || owner.reads != 0 || owner.rate.calls != 0 {
				t.Fatal("unselected primary or ambiguous variant reached native authority", w.Code)
			}
		})
	}
}
