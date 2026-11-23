package oauthserverhttp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-oauth-server/device"
	ratelimit "github.com/faustbrian/go-rate-limit/v2"
)

func deviceAuthorizationFixture(t *testing.T) (http.Handler, *device.Service, *protocolRate, *rateBackend) {
	t.Helper()
	c := consentConfig(t)
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		t.Fatal(err)
	}
	rate, backend := rateFixture(t)
	h, err := newDeviceAuthorizationHandler(c.Service, c.Now, c.MaximumDuration, string(c.Origin), network, decoder, rate)
	if err != nil {
		t.Fatal(err)
	}
	return h, c.Service, rate, backend
}

func deviceAuthorizationRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/oauth2/device_authorization", strings.NewReader(body))
	r.Host, r.RemoteAddr = "issuer.example", "198.51.100.7:1234"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestDeviceAuthorizationPreservesNativeClientRejection(t *testing.T) {
	h, service, _, _ := deviceAuthorizationFixture(t)
	for _, tc := range []struct {
		name, client, code string
		status             int
		native             error
	}{
		{"workload has no device authority", "machine", "access_denied", 400, device.ErrAccessDenied},
		{"unknown client", "unknown", "invalid_request", 400, device.ErrInvalidRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := service.Authorize(t.Context(), device.DeviceRequest{ClientID: tc.client, Network: "198.51.100.7"})
			if !errors.Is(err, tc.native) {
				t.Fatal("native prerequisite rejection changed", err)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, deviceAuthorizationRequest("client_id="+tc.client))
			assertDeviceResponse(t, w, tc.status, map[string]any{"error": tc.code})
			if w.Header().Get("Set-Cookie") != "" {
				t.Fatal("protocol route issued browser authority")
			}
		})
	}
}

func TestDeviceAuthorizationRejectsConflictingEnvelopeAndCredentials(t *testing.T) {
	h, _, _, _ := deviceAuthorizationFixture(t)
	for _, tc := range []struct {
		name, body string
		status     int
		change     func(*http.Request)
	}{
		{name: "missing client", body: "scope=identity%3Aread", status: 400},
		{name: "client secret body", body: "client_id=machine&client_secret=private", status: 400},
		{name: "subject selector", body: "client_id=machine&subject=other", status: 400},
		{name: "device code on issuance", body: "client_id=machine&device_code=" + strings.Repeat("A", 43), status: 400},
		{name: "grant on issuance", body: "client_id=machine&grant_type=client_credentials", status: 400},
		{name: "duplicate client", body: "client_id=machine&client_id=machine", status: 400},
		{name: "body key", body: "client_id=machine&idempotency_key=key", status: 400},
		{name: "json body", body: `{"client_id":"machine"}`, status: 400, change: func(r *http.Request) { r.Header.Set("Content-Type", "application/json") }},
		{name: "header key", body: "client_id=machine", status: 400, change: func(r *http.Request) { r.Header.Set("Idempotency-Key", "key") }},
		{name: "proxy credential", body: "client_id=machine", status: 400, change: func(r *http.Request) { r.Header.Set("Proxy-Authorization", "Basic private") }},
		{name: "empty authorization", body: "client_id=machine", status: 400, change: func(r *http.Request) { r.Header["Authorization"] = nil }},
		{name: "multiple authorization", body: "client_id=machine", status: 400, change: func(r *http.Request) { r.Header["Authorization"] = []string{"Basic first", "Basic second"} }},
		{name: "bearer credential", body: "scope=identity%3Aread", status: 401, change: func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+strings.Repeat("A", 43)) }},
		{name: "mixed client channels", body: "client_id=machine", status: 400, change: func(r *http.Request) {
			r.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("machine:secret")))
		}},
		{name: "query alternative", body: "client_id=machine", status: 400, change: func(r *http.Request) { r.URL.RawQuery = "client_id=other"; r.RequestURI = r.URL.RequestURI() }},
		{name: "empty query marker", body: "client_id=machine", status: 400, change: func(r *http.Request) { r.URL.ForceQuery = true; r.RequestURI = r.URL.RequestURI() }},
		{name: "wrong method", body: "client_id=machine", status: 405, change: func(r *http.Request) { r.Method = http.MethodGet }},
		{name: "wrong path", body: "client_id=machine", status: 404, change: func(r *http.Request) { r.URL.Path += "/"; r.RequestURI = r.URL.RequestURI() }},
		{name: "plain transport", body: "client_id=machine", status: 421, change: func(r *http.Request) { r.TLS = nil }},
		{name: "unselected host", body: "client_id=machine", status: 421, change: func(r *http.Request) { r.Host = "other.example" }},
		{name: "oversized form", body: "client_id=machine&future=" + strings.Repeat("x", 16384), status: 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := deviceAuthorizationRequest(tc.body)
			if tc.change != nil {
				tc.change(r)
			}
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			code := "invalid_request"
			if tc.status == 401 {
				code = "invalid_client"
			}
			assertDeviceResponse(t, w, tc.status, map[string]any{"error": code})
			if tc.status == 405 && w.Header().Get("Allow") != http.MethodPost {
				t.Fatal("method denial omitted allowed method")
			}
			if strings.Contains(w.Body.String(), "private") || strings.Contains(w.Body.String(), "machine") {
				t.Fatal("credential input escaped protocol denial")
			}
		})
	}
}

func TestDeviceAuthorizationUsesIsolatedProtocolIPBudget(t *testing.T) {
	h, _, rate, _ := deviceAuthorizationFixture(t)
	for attempt := range 241 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, deviceAuthorizationRequest("client_id=machine"))
		if attempt < 240 {
			assertDeviceResponse(t, w, 400, map[string]any{"error": "access_denied"})
		} else {
			assertDeviceResponse(t, w, 429, map[string]any{"error": "temporarily_unavailable"})
			if w.Header().Get("Retry-After") == "" {
				t.Fatal("rate rejection omitted bounded retry")
			}
		}
	}
	facts := rateFacts(t, "198.51.100.7", "")
	if _, err := rate.admitIP(t.Context(), facts, "token"); err != nil {
		t.Fatal("device issuance consumed workload token budget", err)
	}
	if _, err := rate.admitIP(t.Context(), facts, "introspect"); err != nil {
		t.Fatal("device issuance consumed introspection budget", err)
	}
}

func TestDeviceAuthorizationRateOutageAndCancellationFailClosed(t *testing.T) {
	h, _, _, backend := deviceAuthorizationFixture(t)
	backend.err = ratelimit.ErrUnavailable
	w := httptest.NewRecorder()
	h.ServeHTTP(w, deviceAuthorizationRequest("client_id=machine"))
	assertDeviceResponse(t, w, 503, map[string]any{"error": "temporarily_unavailable"})
	backend.err = nil
	r := deviceAuthorizationRequest("client_id=machine")
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r.WithContext(ctx))
	assertDeviceResponse(t, w, 503, map[string]any{"error": "temporarily_unavailable"})
}

func TestDeviceAuthorizationConstructionRejectsUnselectedOrInexactNativeOwners(t *testing.T) {
	c := consentConfig(t)
	network, _ := identityhttp.NewNetworkResolver(c.Network)
	decoder, _ := identityhttp.NewRequestDecoder(c.Network.Limits)
	rate, _ := rateFixture(t)
	disabled, err := device.NewService(nil, device.Config{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		service  *device.Service
		now      func() time.Time
		duration time.Duration
		issuer   string
		network  *identityhttp.NetworkResolver
		decoder  *identityhttp.RequestDecoder
		rate     *protocolRate
	}{
		{nil, c.Now, time.Second, string(c.Origin), network, decoder, rate},
		{disabled, c.Now, time.Second, string(c.Origin), network, decoder, rate},
		{c.Service, nil, time.Second, string(c.Origin), network, decoder, rate},
		{c.Service, c.Now, 0, string(c.Origin), network, decoder, rate},
		{c.Service, c.Now, time.Second, "https://other.example", network, decoder, rate},
		{c.Service, c.Now, time.Second, string(c.Origin), nil, decoder, rate},
		{c.Service, c.Now, time.Second, string(c.Origin), network, nil, rate},
		{c.Service, c.Now, time.Second, string(c.Origin), network, decoder, nil},
	} {
		if h, err := newDeviceAuthorizationHandler(tc.service, tc.now, tc.duration, tc.issuer, tc.network, tc.decoder, tc.rate); err == nil || h != nil {
			t.Fatal("incomplete or inexact optional protocol configuration constructed")
		}
	}
}
