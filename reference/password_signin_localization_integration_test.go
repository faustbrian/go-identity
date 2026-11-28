//go:build integration

package reference_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/i18n"
)

const referenceFinnishSigninDenied = "Kirjautuminen evättiin."

func TestReferencePostgresLocalizedPasswordSignin(t *testing.T) {
	proveReferenceSignupGraphExtensions(t, false, signupGraphExtensions{postgresBaseline: true, passwordSigninLocalization: true})
}

func referencePasswordSigninLocalization(t *testing.T) *passwordhttp.SigninLocalizationConfig {
	t.Helper()
	var english []i18n.Message
	for _, message := range []struct {
		code string
		text string
	}{
		{"invalid_request", "Invalid request."},
		{"origin_denied", "Request origin denied."},
		{"https_required", "A secure connection is required."},
		{"not_found", "Not found."},
		{"method_not_allowed", "Method not allowed."},
		{"misdirected_request", "Misdirected request."},
		{"rate_limited", "Too many requests."},
		{"rate_limiter_unavailable", "Sign-in is temporarily unavailable."},
		{"denied", "Sign-in denied."},
		{"unavailable", "Sign-in is temporarily unavailable."},
		{"conflict", "Sign-in conflicts with an existing request."},
		{"in_progress", "Sign-in is already in progress."},
	} {
		english = append(english, i18n.Message{ID: i18n.MessageID("identity.password.signin." + message.code), Template: message.text})
	}
	en, err := i18n.NewCatalog("en", english)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := i18n.NewCatalog("fi", []i18n.Message{{ID: "identity.password.signin.denied", Template: referenceFinnishSigninDenied}})
	if err != nil {
		t.Fatal(err)
	}
	return &passwordhttp.SigninLocalizationConfig{DefaultLocale: "en", Catalogs: []i18n.Catalog{en, fi}}
}

func assertReferenceLocalizedPasswordSigninDenial(t *testing.T, response *http.Response, body []byte) {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal("localized native password denial is not JSON", err)
	}
	if response.StatusCode != http.StatusForbidden || out["error"] != "denied" || out["signedIn"] != false || out["commitOutcome"] != "not_committed" {
		t.Fatal("localization changed native password denial or commit classification", response.StatusCode)
	}
	if out["message"] != referenceFinnishSigninDenied || response.Header.Get("Content-Language") != "fi" {
		t.Fatal("native password denial did not use the selected Finnish translation")
	}
	var variesByLanguage bool
	for _, value := range response.Header.Values("Vary") {
		for _, field := range strings.Split(value, ",") {
			variesByLanguage = variesByLanguage || strings.EqualFold(strings.TrimSpace(field), "Accept-Language")
		}
	}
	if !variesByLanguage {
		t.Fatal("localized native password denial omitted Accept-Language from Vary")
	}
	if len(response.Header.Values("Set-Cookie")) != 0 || response.Header.Get("X-CSRF-Token") != "" || response.Header.Get("X-MFA-Token") != "" {
		t.Fatal("localized native password denial delivered authentication credentials")
	}
	if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("Retry-After") != "" {
		t.Fatal("localization changed native denial cache or retry policy")
	}
	for _, field := range []string{"sessionID", "credential", "csrfToken", "challengeID"} {
		if _, exists := out[field]; exists {
			t.Fatal("localized native password denial exposed credential or challenge fields", field)
		}
	}
}

func assertReferenceUnlocalizedPasswordSigninSuccess(t *testing.T, response *http.Response, body []byte) {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal("verified native password signin is not JSON", err)
	}
	sessionID, _ := out["sessionID"].(string)
	if response.StatusCode != http.StatusOK || out["signedIn"] != true || out["commitOutcome"] != "committed" || sessionID == "" {
		t.Fatal("localization changed verified native password signin", response.StatusCode)
	}
	for _, field := range []string{"message", "error", "credential", "csrfToken"} {
		if _, exists := out[field]; exists {
			t.Fatal("successful native password signin acquired an error or credential field", field)
		}
	}
	if len(response.Header.Values("Content-Language")) != 0 {
		t.Fatal("successful native password signin acquired localized language metadata")
	}
	cookies := response.Cookies()
	csrf := response.Header.Get("X-CSRF-Token")
	if len(cookies) != 1 || len(response.Header.Values("Set-Cookie")) != 1 || csrf == "" {
		t.Fatal("localization changed native session cookie or synchronizer delivery")
	}
	cookie := cookies[0]
	if cookie.Name != "__Host-session" || cookie.Value == "" || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.MaxAge != 0 || !cookie.Expires.IsZero() {
		t.Fatal("localization changed original browser-session cookie attributes")
	}
	if bytes.Contains(body, []byte(cookie.Value)) || bytes.Contains(body, []byte(csrf)) || response.Header.Get("X-MFA-Token") != "" || response.Header.Get("Cache-Control") != "no-store" {
		t.Fatal("localization changed successful native password credential custody")
	}
}
