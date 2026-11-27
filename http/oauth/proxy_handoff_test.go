package oauthhttp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func TestProxyHandoffLocationRoundTripsBoundedCanonicalEnvelope(t *testing.T) {
	const destination = "https://preview.example/v1/oauth/proxy"
	const flow = identity.PreAuthTransactionID("AQEBAQEBAQEBAQEBAQEBAQ")
	for _, size := range []int{1, 2, 3, 8191, 8192} {
		envelope := bytes.Repeat([]byte{0xff}, size)
		location, err := proxyHandoffLocation(destination, flow, envelope)
		if err != nil {
			t.Fatal(err)
		}
		expected := destination + "#identity-proxy-v1." + string(flow) + "." + base64.RawURLEncoding.EncodeToString(envelope)
		if location != expected {
			t.Fatal("handoff did not preserve exact endpoint and fragment protocol")
		}
		parts := strings.Split(strings.TrimPrefix(location, destination+"#"), ".")
		actualFlow, actualEnvelope, err := parseProxyHandoff(parts[1], parts[2])
		if err != nil || actualFlow != flow || !bytes.Equal(actualEnvelope, envelope) {
			t.Fatal("canonical handoff did not round trip")
		}
	}
	for _, size := range []int{0, 8193} {
		if location, err := proxyHandoffLocation(destination, flow, make([]byte, size)); err == nil || location != "" {
			t.Fatal("out-of-bounds handoff returned a location")
		}
	}
	if location, err := proxyHandoffLocation(destination, "invalid", []byte{1}); err == nil || location != "" {
		t.Fatal("invalid flow returned a location")
	}
}

func TestParseProxyHandoffRejectsNoncanonicalAndOversizedInputs(t *testing.T) {
	const validFlow = "AQEBAQEBAQEBAQEBAQEBAQ"
	cases := []struct{ flow, envelope string }{
		{"", "AQ"}, {"AAAAAAAAAAAAAAAAAAAAAA", "AQ"}, {validFlow + "=", "AQ"},
		{validFlow[:21] + "R", "AQ"}, {validFlow, ""}, {validFlow, "AQ=="},
		{validFlow, "AR"}, {validFlow, "A\nQ"}, {validFlow, "+w"},
		{validFlow, "/w"}, {validFlow, "%41Q"}, {validFlow, "AQ."},
		{validFlow, base64.RawURLEncoding.EncodeToString(make([]byte, 8193))},
		{strings.Repeat("A", 1<<16), "AQ"}, {validFlow, strings.Repeat("A", 1<<16)},
	}
	for i, input := range cases {
		flow, envelope, err := parseProxyHandoff(input.flow, input.envelope)
		if err == nil || flow != "" || envelope != nil {
			t.Fatalf("case %d did not fail closed", i)
		}
		if strings.Contains(err.Error(), input.flow) && input.flow != "" {
			t.Fatalf("case %d disclosed flow", i)
		}
	}
}

func TestProxyHandoffRejectsEndpointsOutsideCanonicalRegisteredProfile(t *testing.T) {
	for _, endpoint := range []string{
		"", "/v1/oauth/proxy", "http://preview.example/v1/oauth/proxy", "HTTPS://preview.example/v1/oauth/proxy",
		"https://Preview.example/v1/oauth/proxy", "https://preview.example:443/v1/oauth/proxy",
		"https://preview.example:0444/v1/oauth/proxy", "https://preview.example:0/v1/oauth/proxy",
		"https://preview.example:65536/v1/oauth/proxy", "https://preview.example./v1/oauth/proxy",
		"https://user@preview.example/v1/oauth/proxy", "https://preview.example/v1/oauth/proxy?",
		"https://preview.example/v1/oauth/proxy?flow=secret", "https://preview.example/v1/oauth/proxy#",
		"https://preview.example/v1/oauth/proxy#secret", "https://preview.example", "https://preview.example/",
		"https://preview.example//proxy", "https://preview.example/a/../proxy", "https://preview.example/proxy/",
		"https://preview.example/%70roxy", "https://preview.example/proxy\\other", "https://*.example/proxy",
		"https://127.0.0.1/proxy", "https://[::1]/proxy", "https://localhost/proxy", "https://xn--bcher-kva.example/proxy",
		"https://prëview.example/proxy", "https://preview.example/proxy\n",
	} {
		if location, err := proxyHandoffLocation(endpoint, "AQEBAQEBAQEBAQEBAQEBAQ", []byte{1}); err == nil || location != "" {
			t.Fatalf("endpoint %q produced a handoff", endpoint)
		}
		if handler, err := NewProxyHandoffLanding(endpoint, "https://preview.example/signed-in"); err == nil || handler != nil {
			t.Fatalf("endpoint %q produced a landing", endpoint)
		}
	}
}

func TestProxyHandoffLandingRequiresDistinctSameOriginSuccess(t *testing.T) {
	const endpoint = "https://preview.example/v1/oauth/proxy"
	for _, success := range []string{
		"/signed-in", "https://other.example/signed-in", "https://preview.example:8443/signed-in",
		endpoint, "https://preview.example/signed-in?next=elsewhere", "https://preview.example/signed-in#fragment",
		"https://preview.example/a/../signed-in", "https://preview.example/%73igned-in",
	} {
		if handler, err := NewProxyHandoffLanding(endpoint, success); err == nil || handler != nil {
			t.Fatalf("success %q produced a landing", success)
		}
	}
	for _, success := range []string{"https://preview.example/signed-in", "https://preview.example/"} {
		if _, err := NewProxyHandoffLanding(endpoint, success); err != nil {
			t.Fatal("canonical same-origin success denied", err)
		}
	}
}

func TestProxyHandoffLandingServesOnlyExactBodylessHTTPSGet(t *testing.T) {
	const endpoint = "https://preview.example/v1/oauth/proxy"
	handler, err := NewProxyHandoffLanding(endpoint, "https://preview.example/signed-in")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct{ method, target, body string }{
		{http.MethodGet, endpoint, ""},
		{http.MethodHead, endpoint, ""}, {http.MethodPost, endpoint, ""},
		{http.MethodGet, endpoint + "?", ""}, {http.MethodGet, endpoint + "?flow=secret", ""},
		{http.MethodGet, endpoint + "/", ""}, {http.MethodGet, "https://preview.example/v1/oauth/%70roxy", ""},
		{http.MethodGet, "https://other.example/v1/oauth/proxy", ""},
		{http.MethodGet, "http://preview.example/v1/oauth/proxy", ""},
		{http.MethodGet, endpoint, "secret"},
	}
	for i, input := range cases {
		var body io.Reader
		if input.body != "" {
			body = strings.NewReader(input.body)
		}
		request := httptest.NewRequest(input.method, input.target, body)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if i == 0 {
			if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "text/html; charset=utf-8" {
				t.Fatal("exact HTTPS GET did not serve the landing")
			}
			continue
		}
		if response.Code == http.StatusOK || strings.Contains(response.Body.String(), "<script>") || response.Header().Get("Location") != "" {
			t.Fatalf("case %d accepted an alternate transport", i)
		}
	}
	for _, alter := range []func(*http.Request){
		func(r *http.Request) { r.ContentLength = 1 },
		func(r *http.Request) { r.ContentLength = -1 },
		func(r *http.Request) { r.TransferEncoding = []string{"chunked"} },
		func(r *http.Request) { r.Trailer = http.Header{"X-Extra": []string{"value"}} },
		func(r *http.Request) { r.Host = "other.example" },
		func(r *http.Request) { r.Header.Set("X-Forwarded-Host", "preview.example"); r.Host = "other.example" },
	} {
		request := httptest.NewRequest(http.MethodGet, endpoint, nil)
		alter(request)
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code == http.StatusOK {
			t.Fatal("alternate request envelope served the landing")
		}
	}
	request := httptest.NewRequest(http.MethodGet, endpoint, nil)
	request.URL.Scheme, request.URL.Host = "", ""
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatal("origin-form HTTPS request did not serve the exact landing")
	}
}

func TestProxyHandoffRetainsRegisteredNondefaultHTTPSPort(t *testing.T) {
	const endpoint = "https://preview.example:8443/v1/oauth/proxy"
	handler, err := NewProxyHandoffLanding(endpoint, "https://preview.example:8443/signed-in")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, endpoint, nil))
	if response.Code != http.StatusOK {
		t.Fatal("registered HTTPS port did not serve the landing")
	}
	location, err := proxyHandoffLocation(endpoint, "AQEBAQEBAQEBAQEBAQEBAQ", []byte{1})
	if err != nil || !strings.HasPrefix(location, endpoint+"#identity-proxy-v1.") {
		t.Fatal("registered port changed in the handoff location")
	}
}

func TestProxyHandoffLandingCSPAuthenticatesOnlyItsFixedScript(t *testing.T) {
	handler, err := NewProxyHandoffLanding("https://preview.example/v1/oauth/proxy", "https://preview.example/signed-in")
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://preview.example/v1/oauth/proxy", nil))
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" || response.Header().Get("X-Content-Type-Options") != "nosniff" || len(response.Result().Cookies()) != 0 {
		t.Fatal("landing omitted its confidentiality headers or set a cookie")
	}
	body := response.Body.String()
	_, afterStart, found := strings.Cut(body, "<script>")
	script, _, closed := strings.Cut(afterStart, "</script>")
	if !found || !closed || strings.Count(body, "<script>") != 1 {
		t.Fatal("landing did not carry one fixed inline script")
	}
	digest := sha256.Sum256([]byte(script))
	expectedCSP := "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(digest[:]) + "'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
	if response.Header().Get("Content-Security-Policy") != expectedCSP {
		t.Fatal("CSP does not authenticate the served script exactly")
	}
	if strings.Contains(body, "script src") || strings.Contains(body, "style=") || !strings.Contains(body, `data-success="/signed-in"`) {
		t.Fatal("landing contains an external asset or wrong success destination")
	}
	for _, required := range []string{
		`fetch(location.pathname, {`, `mode: "cors"`, `credentials: "same-origin"`,
		`referrerPolicy: "no-referrer"`, `redirect: "error"`, `cache: "no-store"`,
	} {
		if !strings.Contains(script, required) {
			t.Fatal("landing script omitted a required Fetch interoperability constraint")
		}
	}
}

func FuzzParseProxyHandoff(f *testing.F) {
	f.Add("AQEBAQEBAQEBAQEBAQEBAQ", "AQ")
	f.Add("AQEBAQEBAQEBAQEBAQEBAQ", "AR")
	f.Add("AAAAAAAAAAAAAAAAAAAAAA", "AQ")
	f.Fuzz(func(t *testing.T, rawFlow, encoded string) {
		flow, envelope, err := parseProxyHandoff(rawFlow, encoded)
		if err != nil {
			if flow != "" || envelope != nil {
				t.Fatal("rejected handoff retained output")
			}
			return
		}
		if _, err := identity.ParsePreAuthTransactionID(string(flow)); err != nil || len(envelope) < 1 || len(envelope) > 8192 || base64.RawURLEncoding.EncodeToString(envelope) != encoded {
			t.Fatal("accepted handoff was not bounded and canonical")
		}
	})
}
