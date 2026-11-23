package oauthserverhttp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
	oauth "github.com/faustbrian/go-oauth-server"
	"github.com/faustbrian/go-oauth-server/device"
)

type consentTransportStore struct {
	oauth.DeviceStore
	policy device.Config
}

func (s consentTransportStore) DevicePolicy() oauth.DevicePolicy { return s.policy }

// The transport fixture deliberately has no native session owner: syntactic
// cookie custody must never manufacture a current human session.
func consentConfig(t *testing.T) DeviceConsentConfig {
	t.Helper()
	c, _, _ := featureFixture(t)
	policy := device.Config{Enabled: true, TenantID: "tenant", VerificationURI: "https://issuer.example/device", TokenEndpoint: "https://issuer.example/oauth2/token", AuthorizationEndpoint: "https://issuer.example/oauth2/device_authorization", TTL: time.Minute, PollInterval: 5 * time.Second, VerificationURICompleteBytes: 512, LookupLimit: 32}
	service, err := device.NewService(c.Service, policy, consentTransportStore{policy: policy})
	if err != nil {
		t.Fatal(err)
	}
	cookie, err := session.NewCookiePolicy(session.CookieConfig{Name: "__Host-session", SameSite: http.SameSiteLaxMode})
	if err != nil {
		t.Fatal(err)
	}
	return DeviceConsentConfig{Service: service, Network: c.Network, SessionCookie: cookie, Origin: "https://issuer.example", Now: c.Now, MaximumDuration: time.Second}
}

func consentRequest(action, body string) *http.Request {
	method := http.MethodPost
	path := "/v1/oauth-server/" + action
	if action == "device-inspect" {
		method, path = http.MethodGet, path+"?user_code=BCDF-GHJK"
	}
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if body == "" {
		r.Body = http.NoBody
	}
	r.Host, r.RemoteAddr = "issuer.example", "198.51.100.7:1234"
	r.TLS = &tls.ConnectionState{}
	r.AddCookie(&http.Cookie{Name: "__Host-session", Value: strings.Repeat("A", 43)})
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Origin", "https://issuer.example")
		r.Header.Set("X-CSRF-Token", strings.Repeat("A", 43))
	}
	return r
}

func TestDeviceConsentSyntacticCookieCannotBecomeHumanAuthority(t *testing.T) {
	c := consentConfig(t)
	for _, action := range []string{"device-inspect", "device-approve", "device-deny"} {
		t.Run(action, func(t *testing.T) {
			h, err := newDeviceConsentHandler(c, action)
			if err != nil {
				t.Fatal(err)
			}
			body := `{"user_code":"BCDF-GHJK"}`
			if action == "device-inspect" {
				body = ""
			} else if action == "device-approve" {
				body = `{"user_code":"BCDF-GHJK","confirmed_user_code":"BCDF-GHJK"}`
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, consentRequest(action, body))
			assertDeviceResponse(t, w, 400, map[string]any{"error": "access_denied"})
			if w.Header().Get("Set-Cookie") != "" {
				t.Fatal("consent route issued session custody")
			}
		})
	}
}

func TestDeviceConsentRejectsClosedInputBeforeNativeSessionAdmission(t *testing.T) {
	c := consentConfig(t)
	for _, tc := range []struct {
		name, action, body string
		status             int
		change             func(*http.Request)
	}{
		{name: "approval requires explicit comparison", action: "device-approve", body: `{"user_code":"BCDF-GHJK"}`, status: 400},
		{name: "subject override", action: "device-deny", body: `{"user_code":"BCDF-GHJK","subject_id":"other"}`, status: 400},
		{name: "proof override", action: "device-deny", body: `{"user_code":"BCDF-GHJK","authentication_proof":"proof"}`, status: 400},
		{name: "device code", action: "device-deny", body: `{"user_code":"BCDF-GHJK","device_code":"private"}`, status: 400},
		{name: "duplicate code", action: "device-deny", body: `{"user_code":"BCDF-GHJK","user_code":"BCDF-GHJK"}`, status: 400},
		{name: "case alias", action: "device-deny", body: `{"USER_CODE":"BCDF-GHJK"}`, status: 400},
		{name: "malformed code", action: "device-deny", body: `{"user_code":"ABCD-EFGH"}`, status: 400},
		{name: "query alternative", action: "device-deny", body: `{"user_code":"BCDF-GHJK"}`, status: 400, change: func(r *http.Request) { r.URL.RawQuery = "user_code=BCDF-GHJK"; r.RequestURI = r.URL.RequestURI() }},
		{name: "proprietary key", action: "device-deny", body: `{"user_code":"BCDF-GHJK"}`, status: 400, change: func(r *http.Request) { r.Header.Set("Idempotency-Key", "key") }},
		{name: "missing csrf", action: "device-deny", body: `{"user_code":"BCDF-GHJK"}`, status: 403, change: func(r *http.Request) { r.Header.Del("X-CSRF-Token") }},
		{name: "foreign origin", action: "device-deny", body: `{"user_code":"BCDF-GHJK"}`, status: 403, change: func(r *http.Request) { r.Header.Set("Origin", "https://other.example") }},
		{name: "bearer alternative", action: "device-deny", body: `{"user_code":"BCDF-GHJK"}`, status: 400, change: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 43)) }},
		{name: "duplicate cookie", action: "device-deny", body: `{"user_code":"BCDF-GHJK"}`, status: 400, change: func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-session", Value: strings.Repeat("A", 43)})
		}},
		{name: "inspect query override", action: "device-inspect", status: 400, change: func(r *http.Request) { r.URL.RawQuery += "&subject_id=other"; r.RequestURI = r.URL.RequestURI() }},
		{name: "inspect body", action: "device-inspect", body: `{"user_code":"BCDF-GHJK"}`, status: 400},
		{name: "inspect csrf channel", action: "device-inspect", status: 400, change: func(r *http.Request) { r.Header.Set("X-CSRF-Token", strings.Repeat("A", 43)) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, err := newDeviceConsentHandler(c, tc.action)
			if err != nil {
				t.Fatal(err)
			}
			r := consentRequest(tc.action, tc.body)
			if tc.change != nil {
				tc.change(r)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			code := "invalid_request"
			if tc.status == 403 {
				code = "origin_or_csrf_denied"
			}
			assertDeviceResponse(t, w, tc.status, map[string]any{"error": code})
			if strings.Contains(w.Body.String(), "BCDF") || strings.Contains(w.Body.String(), "private") {
				t.Fatal("input leaked in denial")
			}
		})
	}
}

func TestDeviceConsentPromptProjectsOnlySafeNativeMetadata(t *testing.T) {
	now := time.Unix(1800000000, 0)
	out := oauth.DevicePrompt{ClientID: "client", ClientDisplay: "Living room", UserCode: "BCDF-GHJK", Resource: "https://resource.example", Scopes: []string{"identity:read"}, ExpiresAt: now.Add(time.Minute)}
	w := httptest.NewRecorder()
	writeDevicePrompt(w, consentRequest("device-inspect", ""), now, out, nil)
	assertDeviceResponse(t, w, 200, map[string]any{"canonical_user_code": "BCDF-GHJK", "client_display_name": "Living room", "resources": []any{"https://resource.example"}, "scopes": []any{"identity:read"}, "expires_at": out.ExpiresAt.Format(time.RFC3339)})
	for _, bad := range []oauth.DevicePrompt{{}, {UserCode: out.UserCode, ClientDisplay: out.ClientDisplay, Resource: out.Resource, Scopes: out.Scopes, ExpiresAt: now}} {
		w = httptest.NewRecorder()
		writeDevicePrompt(w, consentRequest("device-inspect", ""), now, bad, nil)
		assertDeviceResponse(t, w, 503, map[string]any{"error": "temporarily_unavailable"})
	}
}

func TestDeviceConsentCompletionDoesNotInventSubjectOrConsentVersion(t *testing.T) {
	for _, action := range []string{"device-approve", "device-deny"} {
		completion := oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: "AAAAAAAAAAAAAAAAAAAAAg"}
		w := httptest.NewRecorder()
		writeDeviceConsentCompletion(w, consentRequest(action, ""), action, completion, nil)
		state := "approved"
		if action == "device-deny" {
			state = "denied"
		}
		assertDeviceResponse(t, w, 200, map[string]any{"state": state, "completion": map[string]any{"outcome": "committed", "command_id": "AAAAAAAAAAAAAAAAAAAAAg", "replayed": false}})
		completion.Outcome = identity.CommitOutcomeUnknown
		w = httptest.NewRecorder()
		writeDeviceConsentCompletion(w, consentRequest(action, ""), action, completion, nil)
		assertDeviceResponse(t, w, 503, map[string]any{"error": "temporarily_unavailable"})
	}
}

func TestDeviceConsentFormPreservesExistingCSRFChannelRules(t *testing.T) {
	c := consentConfig(t)
	h, err := newDeviceConsentHandler(c, "device-approve")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, body string
		header     bool
		status     int
		code       string
	}{
		{"form csrf", "user_code=BCDF-GHJK&confirmed_user_code=BCDF-GHJK&csrf_token=" + strings.Repeat("A", 43), false, 400, "access_denied"},
		{"header csrf", "user_code=BCDF-GHJK&confirmed_user_code=BCDF-GHJK", true, 400, "access_denied"},
		{"mixed channels", "user_code=BCDF-GHJK&confirmed_user_code=BCDF-GHJK&csrf_token=" + strings.Repeat("A", 43), true, 403, "origin_or_csrf_denied"},
		{"duplicate field", "user_code=BCDF-GHJK&user_code=BCDF-GHJK&confirmed_user_code=BCDF-GHJK", true, 403, "origin_or_csrf_denied"},
		{"unknown selector", "user_code=BCDF-GHJK&confirmed_user_code=BCDF-GHJK&subject_id=other", true, 400, "invalid_request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := consentRequest("device-approve", tc.body)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			if !tc.header {
				r.Header.Del("X-CSRF-Token")
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assertDeviceResponse(t, w, tc.status, map[string]any{"error": tc.code})
		})
	}
}

func TestDeviceConsentCompletionPreservesReplayAndCancellationBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name, action string
		completion   oauth.Completion
		cancel       bool
		status       int
	}{
		{"approval replay", "device-approve", oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: "AAAAAAAAAAAAAAAAAAAAAg", Replayed: true}, false, 503},
		{"idempotent native denial", "device-deny", oauth.Completion{Outcome: identity.CommitOutcomeCommitted, Replayed: true}, false, 200},
		{"idempotent denial omits any original command", "device-deny", oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: "AAAAAAAAAAAAAAAAAAAAAg", Replayed: true}, false, 200},
		{"missing acknowledgment", "device-deny", oauth.Completion{Outcome: identity.CommitOutcomeCommitted}, false, 503},
		{"malformed acknowledgment", "device-deny", oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: "not-a-command"}, false, 503},
		{"cancelled", "device-deny", oauth.Completion{Outcome: identity.CommitOutcomeCommitted, CommandID: "AAAAAAAAAAAAAAAAAAAAAg"}, true, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := consentRequest(tc.action, "")
			if tc.cancel {
				ctx, stop := context.WithCancel(r.Context())
				stop()
				r = r.WithContext(ctx)
			}
			w := httptest.NewRecorder()
			writeDeviceConsentCompletion(w, r, tc.action, tc.completion, nil)
			if tc.status == 200 {
				assertDeviceResponse(t, w, 200, map[string]any{"state": "denied", "completion": map[string]any{"outcome": "committed", "replayed": true}})
			} else {
				assertDeviceResponse(t, w, tc.status, map[string]any{"error": "temporarily_unavailable"})
			}
		})
	}
}

func TestDeviceConsentPrivateValuesRejectImplicitSerialization(t *testing.T) {
	for _, value := range []any{consentConfig(t), deviceConsentInput{verification: device.Verification{UserCode: "BCDF-GHJK"}}} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("private input serialized")
		}
		if strings.Contains(fmt.Sprintf("%#v", value), "BCDF") {
			t.Fatal("private input formatted")
		}
	}
}
