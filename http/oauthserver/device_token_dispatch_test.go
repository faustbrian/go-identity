package oauthserverhttp

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-oauth-server/device"
)

func TestOptInDeviceFeaturesShareOneDocumentedTokenRoute(t *testing.T) {
	c, _, basic := featureFixture(t)
	c.Introspect, c.Revoke = false, false
	browser := consentConfig(t)
	features, err := NewFeaturesWithDevice(t.Context(), c, DeviceFeatureConfig{
		Service: browser.Service, SessionCookie: browser.SessionCookie,
	})
	if err != nil {
		t.Fatal("selected device and workload profiles", err)
	}
	operations, err := identityhttp.NewOperationDescriptors(identityhttp.FeatureServices{Features: features})
	if err != nil || len(operations) != 5 {
		t.Fatal("shared token route and four device routes were not selected once", err)
	}
	h, doc, err := identityhttp.NewRouter(identityhttp.TransportPolicy{
		Network: c.Network, HandlerTimeout: c.MaximumDuration, Document: identityhttp.DocumentConfig{Title: "Device OAuth", Version: "1"},
	}, operations, nil)
	if err != nil || !bytes.Contains(doc.JSON(), []byte(device.GrantType)) {
		t.Fatal("selected device grant is missing from shared route OpenAPI", err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wireRequest("token", "grant_type=client_credentials", basic))
	if w.Code != http.StatusOK {
		t.Fatal("composed workload issuance changed", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, deviceAuthorizationRequest("client_id=unknown"))
	assertDeviceResponse(t, w, http.StatusBadRequest, map[string]any{"error": "invalid_request"})
	w = httptest.NewRecorder()
	h.ServeHTTP(w, consentRequest("device-inspect", ""))
	if w.Code == http.StatusNotFound {
		t.Fatal("configured browser device consent route is absent")
	}
}

func TestSharedTokenRouteSelectsOnlyExactDeviceGrant(t *testing.T) {
	c, _, basic := featureFixture(t)
	_, service, rate, _ := deviceAuthorizationFixture(t)
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHandlerWithDevice(c, "token", "https://issuer.example", network, decoder, rate, service)
	if err != nil {
		t.Fatal(err)
	}
	validDevice := "grant_type=" + url.QueryEscape(device.GrantType) + "&device_code=" + strings.Repeat("A", 43)
	for _, tc := range []struct {
		name, form, auth, code string
		status                 int
	}{
		{"workload even when device is selected", "grant_type=client_credentials", basic, "", 200},
		{"native device admission does not become workload", validDevice + "&client_id=unknown", "", "invalid_request", 400},
		{"device poll cannot request new scope", validDevice + "&client_id=unknown&scope=identity%3Aread", "", "invalid_request", 400},
		{"mixed grant is not a fallback", validDevice + "&grant_type=client_credentials", basic, "invalid_request", 400},
		{"unsupported sibling remains unsupported", "grant_type=refresh_token&refresh_token=" + strings.Repeat("A", 43), basic, "unsupported_grant_type", 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			h.ServeHTTP(w, wireRequest("token", tc.form, tc.auth))
			if tc.code != "" {
				assertDeviceResponse(t, w, tc.status, map[string]any{"error": tc.code})
			} else if w.Code != tc.status || !strings.Contains(w.Body.String(), `"access_token":`) {
				t.Fatal("workload credentials stopped working when the device profile was selected")
			}
		})
	}
}

func TestDevicePollingCannotSpendTheWorkloadTokenIPBudget(t *testing.T) {
	c, _, basic := featureFixture(t)
	_, service, rate, _ := deviceAuthorizationFixture(t)
	network, err := identityhttp.NewNetworkResolver(c.Network)
	if err != nil {
		t.Fatal(err)
	}
	decoder, err := identityhttp.NewRequestDecoder(c.Network.Limits)
	if err != nil {
		t.Fatal(err)
	}
	h, err := newHandlerWithDevice(c, "token", "https://issuer.example", network, decoder, rate, service)
	if err != nil {
		t.Fatal(err)
	}
	poll := "grant_type=" + url.QueryEscape(device.GrantType) + "&device_code=" + strings.Repeat("A", 43) + "&client_id=unknown"
	for attempt := range 121 {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, wireRequest("token", poll, ""))
		expected := http.StatusBadRequest
		if attempt == 120 {
			expected = http.StatusTooManyRequests
		}
		if w.Code != expected {
			t.Fatal("device poll selected the wrong budget or native admission", w.Code)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, wireRequest("token", "grant_type=client_credentials", basic))
	if w.Code != http.StatusOK {
		t.Fatal("device polling consumed workload capacity", w.Code)
	}
}
