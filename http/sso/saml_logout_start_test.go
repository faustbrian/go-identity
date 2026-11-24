package ssohttp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-sso/saml"
)

const (
	samlLogoutStartHTTPProvider = "Enterprise_SAML-01"
	samlLogoutStartHTTPPath     = "/saml2/" + samlLogoutStartHTTPProvider + "/logout"
	samlLogoutStartHTTPEndpoint = "https://provider.example/logout?binding=redirect&profile=selected"
	samlLogoutStartHTTPFinal    = "https://tenant.example/bye"
)

type samlLogoutStartHTTPProbe struct {
	t            testing.TB
	calls        int
	request      ProviderLogoutStartRequest
	result       SAMLLogoutStartResult
	err          error
	beforeReturn func(context.Context)
}

func (p *samlLogoutStartHTTPProbe) StartSSOSAMLLogout(ctx context.Context, request ProviderLogoutStartRequest) (SAMLLogoutStartResult, error) {
	deadline, ok := ctx.Deadline()
	if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > time.Second {
		p.t.Fatal("SAML logout start reached native authority without a live bounded context")
	}
	p.calls++
	p.request = request
	if p.beforeReturn != nil {
		p.beforeReturn(ctx)
	}
	return p.result, p.err
}

func samlLogoutStartHTTPFixture(t testing.TB) (SAMLLogoutStartConfig, *samlLogoutStartHTTPProbe) {
	t.Helper()
	base, _ := providerLogoutFixture(t)
	probe := &samlLogoutStartHTTPProbe{t: t, result: SAMLLogoutStartResult{
		LocalRevocation: saml.LocalRevocation{SessionID: "selected-local-session", Version: 7, Committed: true},
		LocalOnly:       true,
	}}
	return SAMLLogoutStartConfig{
		Network: base.Network, TenantID: base.TenantID, Origin: base.Origin,
		ProviderID: samlLogoutStartHTTPProvider, RedirectEndpoint: samlLogoutStartHTTPEndpoint,
		FinalRedirectAllowlist: []string{samlLogoutStartHTTPFinal}, Rate: base.Rate,
		MaximumDuration: time.Second, Cookie: base.Cookie, CSRFCookie: base.CSRFCookie, Owner: probe,
	}, probe
}

func samlLogoutStartHTTPRouter(t testing.TB, config SAMLLogoutStartConfig, selected bool) (http.Handler, identityhttp.OpenAPIDocument) {
	t.Helper()
	var operations []identityhttp.OperationDescriptor
	if selected {
		op, err := NewSAMLLogoutStartOperation(config)
		if err != nil {
			t.Fatal("select installed SAML logout start", err)
		}
		operations = append(operations, op)
	}
	router, document, err := identityhttp.NewRouter(identityhttp.TransportPolicy{
		Network: config.Network, HandlerTimeout: time.Second,
		Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"},
	}, operations, nil)
	if err != nil {
		t.Fatal("compose SAML logout start through the canonical router", err)
	}
	return router, document
}

func samlLogoutStartHTTPRequest() *http.Request {
	return providerLogoutRequest(http.MethodPost, samlLogoutStartHTTPPath, `{"finalRedirect":"https://tenant.example/bye"}`)
}

func requireSAMLLogoutStartHTTPProjection(t testing.TB, response *httptest.ResponseRecorder, outcome string, local saml.LocalRevocation) {
	t.Helper()
	var body map[string]json.RawMessage
	if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
		t.Fatal("selected SAML logout outcome must expose JSON", err)
	}
	if len(body) != 2 || string(body["outcome"]) != `"`+outcome+`"` {
		t.Fatal("selected SAML logout outcome exposed an open or missing wire disposition", response.Body.String())
	}
	var projection map[string]json.RawMessage
	if err := json.Unmarshal(body["localRevocation"], &projection); err != nil || len(projection) != 4 {
		t.Fatal("selected SAML logout must expose the complete local revocation projection")
	}
	want := map[string]any{"sessionId": local.SessionID, "version": local.Version, "committed": local.Committed, "reconciliationRequired": local.ReconciliationRequired}
	for field, value := range want {
		encoded, err := json.Marshal(value)
		if err != nil || string(projection[field]) != string(encoded) {
			t.Fatal("selected SAML logout changed authoritative local revocation", field)
		}
	}
	if !strings.HasPrefix(response.Header().Get("Content-Type"), "application/json") || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("selected SAML logout projection is not private JSON")
	}
}

func TestSAMLLogoutStartHTTPPreservesOriginalBrowserAuthorityAndLocalOnlyProjection(t *testing.T) {
	config, probe := samlLogoutStartHTTPFixture(t)
	config.RedirectEndpoint = ""
	router, _ := samlLogoutStartHTTPRouter(t, config, true)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, samlLogoutStartHTTPRequest())
	if w.Code != http.StatusOK || w.Header().Get("Location") != "" || probe.calls != 1 {
		t.Fatal("verified local-only SAML logout did not return its selected local result", w.Code)
	}
	request := probe.request
	csrf, err := request.CSRF.Reveal()
	if request.TenantID != testTenant || request.ProviderID != samlLogoutStartHTTPProvider || request.Origin != "https://tenant.example" || request.FinalRedirect != samlLogoutStartHTTPFinal || request.Session.Token() != logoutSessionWire || err != nil || csrf != strings.Repeat("A", 43) {
		t.Fatal("SAML logout start replaced the original tenant, provider or browser credentials")
	}
	key, err := identity.NewIdempotencyKey([]byte("original-logout-key"))
	if err != nil {
		t.Fatal(err)
	}
	want, err := key.Digest([32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	got, err := request.IdempotencyKey.Digest([32]byte{9})
	if err != nil || got != want {
		t.Fatal("SAML logout start replaced the original idempotency key")
	}
	requireSAMLLogoutStartHTTPProjection(t, w, "local-only", probe.result.LocalRevocation)
	requireLogoutCookieDeletion(t, w)
}

func samlLogoutStartHTTPSignedRedirect(endpoint string) string {
	separator := "?"
	if strings.Contains(endpoint, "?") {
		separator = "&"
	}
	return endpoint + separator + "SAMLRequest=YQ%3D%3D&SigAlg=" + url.QueryEscape(saml.SignatureAlgorithmRSAPSSSHA256) + "&Signature=Yg%3D%3D"
}

func TestSAMLLogoutStartHTTPKeepsLocalProjectionIndependentOfRemoteOutcome(t *testing.T) {
	committed := saml.LocalRevocation{SessionID: "selected-local-session", Version: 7, Committed: true}
	notCommitted := saml.LocalRevocation{SessionID: "selected-local-session", Version: 6}
	unknown := saml.LocalRevocation{SessionID: "selected-local-session", Version: 7, ReconciliationRequired: true}
	redirect := samlLogoutStartHTTPSignedRedirect(samlLogoutStartHTTPEndpoint)
	for _, tc := range []struct {
		name              string
		result            SAMLLogoutStartResult
		err               error
		status            int
		outcome, location string
		deleteCookies     bool
	}{
		{"signed redirect after commit", SAMLLogoutStartResult{LocalRevocation: committed, ProviderRedirect: redirect}, nil, http.StatusSeeOther, "redirect", redirect, true},
		{"local only after commit", SAMLLogoutStartResult{LocalRevocation: committed, LocalOnly: true}, nil, http.StatusOK, "local-only", "", true},
		{"provider unavailable after commit", SAMLLogoutStartResult{LocalRevocation: committed}, errors.New("remote unavailable"), http.StatusServiceUnavailable, "unavailable", "", true},
		{"local revocation refused", SAMLLogoutStartResult{LocalRevocation: notCommitted}, errors.New("local revocation refused"), http.StatusServiceUnavailable, "unavailable", "", false},
		{"local revocation unknown", SAMLLogoutStartResult{LocalRevocation: unknown}, errors.New("local outcome unknown"), http.StatusServiceUnavailable, "unknown-reconciliation", "", false},
		{"unknown cannot become local only", SAMLLogoutStartResult{LocalRevocation: unknown, LocalOnly: true}, nil, http.StatusServiceUnavailable, "unknown-reconciliation", "", false},
		{"unknown cannot offer provider redirect", SAMLLogoutStartResult{LocalRevocation: unknown, ProviderRedirect: redirect}, nil, http.StatusServiceUnavailable, "unknown-reconciliation", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, probe := samlLogoutStartHTTPFixture(t)
			probe.result, probe.err = tc.result, tc.err
			router, _ := samlLogoutStartHTTPRouter(t, config, true)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, samlLogoutStartHTTPRequest())
			if w.Code != tc.status || w.Header().Get("Location") != tc.location || probe.calls != 1 {
				t.Fatal("SAML logout start lost the local/remote disposition boundary", w.Code)
			}
			requireSAMLLogoutStartHTTPProjection(t, w, tc.outcome, tc.result.LocalRevocation)
			if tc.deleteCookies {
				requireLogoutCookieDeletion(t, w)
			} else if len(w.Header().Values("Set-Cookie")) != 0 {
				t.Fatal("uncommitted or unknown local revocation deleted browser custody")
			}
			if strings.Contains(w.Body.String(), "remote unavailable") || strings.Contains(w.Body.String(), logoutSessionWire) || strings.Contains(w.Body.String(), "original-logout-key") || strings.Contains(w.Body.String(), "SAMLRequest") {
				t.Fatal("SAML logout projection leaked credentials, provider wire or native error")
			}
		})
	}
}

func TestSAMLLogoutStartHTTPRejectsAlternateBrowserAuthorityBeforeNativeSelection(t *testing.T) {
	for name, mutate := range map[string]func(*http.Request){
		"foreign origin":  func(r *http.Request) { r.Header.Set("Origin", "https://foreign.example") },
		"missing origin":  func(r *http.Request) { r.Header.Del("Origin") },
		"HTTP origin":     func(r *http.Request) { r.Header.Set("Origin", "http://tenant.example") },
		"missing CSRF":    func(r *http.Request) { r.Header.Del("X-CSRF-Token") },
		"duplicate CSRF":  func(r *http.Request) { r.Header.Add("X-CSRF-Token", strings.Repeat("B", 43)) },
		"missing key":     func(r *http.Request) { r.Header.Del("Idempotency-Key") },
		"duplicate key":   func(r *http.Request) { r.Header.Add("Idempotency-Key", "second-key") },
		"missing session": func(r *http.Request) { r.Header.Del("Cookie") },
		"duplicate session": func(r *http.Request) {
			r.AddCookie(&http.Cookie{Name: "__Host-logout_session", Value: "second-session"})
		},
		"bearer alternative": func(r *http.Request) { r.Header.Set("Authorization", "Bearer another-session") },
		"wrong tenant":       func(r *http.Request) { r.Host = "other.example" },
		"HTTP transport":     func(r *http.Request) { r.TLS = nil; r.URL.Scheme = "http" },
		"query authority": func(r *http.Request) {
			r.URL.RawQuery = "finalRedirect=https%3A%2F%2Ftenant.example%2Fbye"
			r.RequestURI = r.URL.RequestURI()
		},
		"unselected provider": func(r *http.Request) { r.URL.Path = "/saml2/other/logout"; r.RequestURI = r.URL.RequestURI() },
	} {
		t.Run(name, func(t *testing.T) {
			config, probe := samlLogoutStartHTTPFixture(t)
			router, _ := samlLogoutStartHTTPRouter(t, config, true)
			r := samlLogoutStartHTTPRequest()
			mutate(r)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code < 400 || probe.calls != 0 || w.Header().Get("Location") != "" || len(w.Header().Values("Set-Cookie")) != 0 || strings.Contains(w.Body.String(), "localRevocation") {
				t.Fatal("unadmitted SAML logout selected native authority or invented local revocation", w.Code)
			}
		})
	}
	for _, body := range []string{
		`{}`, `null`, `[]`, `{"finalRedirect":""}`,
		`{"finalRedirect":"https://foreign.example/bye"}`,
		`{"finalRedirect":"http://tenant.example/bye"}`,
		`{"finalRedirect":"https://tenant.example/bye#fragment"}`,
		`{"finalRedirect":"https://tenant.example/bye","providerID":"other"}`,
		`{"finalRedirect":"https://tenant.example/bye","providerURL":"https://foreign.example/logout"}`,
		`{"finalRedirect":"https://tenant.example/bye","sessionID":"other"}`,
		`{"finalRedirect":"https://tenant.example/bye","finalRedirect":"https://tenant.example/bye"}`,
		`{"finalRedirect":"https://tenant.example/bye"} {}`,
	} {
		t.Run(body, func(t *testing.T) {
			config, probe := samlLogoutStartHTTPFixture(t)
			router, _ := samlLogoutStartHTTPRouter(t, config, true)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, providerLogoutRequest(http.MethodPost, samlLogoutStartHTTPPath, body))
			if w.Code < 400 || probe.calls != 0 || w.Header().Get("Location") != "" || len(w.Header().Values("Set-Cookie")) != 0 || strings.Contains(w.Body.String(), "localRevocation") {
				t.Fatal("invalid SAML logout JSON selected native authority or disclosed local revocation", w.Code)
			}
		})
	}
}

func TestSAMLLogoutStartHTTPWithholdsUnpinnedOrAmbiguousNativeRedirect(t *testing.T) {
	valid := samlLogoutStartHTTPSignedRedirect(samlLogoutStartHTTPEndpoint)
	for name, redirect := range map[string]string{
		"foreign host":           strings.Replace(valid, "provider.example", "foreign.example", 1),
		"different path":         strings.Replace(valid, "/logout?", "/other?", 1),
		"changed literal query":  strings.Replace(valid, "profile=selected", "profile=other", 1),
		"missing signature":      strings.Split(valid, "&Signature=")[0],
		"empty request":          strings.Replace(valid, "SAMLRequest=YQ%3D%3D", "SAMLRequest=", 1),
		"unsupported algorithm":  strings.Replace(valid, url.QueryEscape(saml.SignatureAlgorithmRSAPSSSHA256), "unsupported", 1),
		"duplicate signature":    valid + "&Signature=Yg%3D%3D",
		"unselected relay state": valid + "&RelayState=unselected",
		"wrong query order":      samlLogoutStartHTTPEndpoint + "&SigAlg=" + url.QueryEscape(saml.SignatureAlgorithmRSAPSSSHA256) + "&SAMLRequest=YQ%3D%3D&Signature=Yg%3D%3D",
		"fragment":               valid + "#fragment",
	} {
		t.Run(name, func(t *testing.T) {
			config, probe := samlLogoutStartHTTPFixture(t)
			probe.result.LocalOnly, probe.result.ProviderRedirect = false, redirect
			router, _ := samlLogoutStartHTTPRouter(t, config, true)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, samlLogoutStartHTTPRequest())
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("Location") != "" {
				t.Fatal("native output bypassed the exact configured SAML redirect profile", w.Code)
			}
			requireSAMLLogoutStartHTTPProjection(t, w, "unavailable", probe.result.LocalRevocation)
			requireLogoutCookieDeletion(t, w)
		})
	}
}

func TestSAMLLogoutStartHTTPCancellationRetainsSelectedLocalProjectionWithoutNavigation(t *testing.T) {
	config, probe := samlLogoutStartHTTPFixture(t)
	probe.result.LocalOnly = false
	probe.result.ProviderRedirect = samlLogoutStartHTTPSignedRedirect(config.RedirectEndpoint)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	probe.beforeReturn = func(context.Context) { cancel() }
	router, _ := samlLogoutStartHTTPRouter(t, config, true)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, samlLogoutStartHTTPRequest().WithContext(ctx))
	if w.Code != http.StatusServiceUnavailable || w.Header().Get("Location") != "" || probe.calls != 1 {
		t.Fatal("canceled SAML logout navigated remotely or lost its selected result", w.Code)
	}
	requireSAMLLogoutStartHTTPProjection(t, w, "unavailable", probe.result.LocalRevocation)
	if len(w.Header().Values("Set-Cookie")) != 0 {
		t.Fatal("canceled transport disclosed cookie changes")
	}
}

func FuzzSAMLLogoutStartProviderRedirect(f *testing.F) {
	const fixed = "https://idp.example/slo?tenant=managed"
	valid := samlLogoutStartHTTPSignedRedirect(fixed)
	validWithState := strings.Replace(valid, "&SigAlg=", "&RelayState="+strings.Repeat("A", 43)+"&SigAlg=", 1)
	for _, seed := range []string{valid, validWithState, strings.Replace(valid, "idp.example", "other.example", 1), valid + "&Signature=YQ%3D%3D", "", "https://idp.example/slo"} {
		f.Add(seed)
	}
	endpoint, err := url.Parse(fixed)
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		plain := samlLogoutStartProfile{endpoint: *endpoint}
		selected := samlLogoutStartProfile{endpoint: *endpoint, redirectProfile: samlLogoutRedirectWithRelayState}
		plainOK := plain.validRedirect(raw)
		stateOK := selected.validRedirect(raw)
		if plainOK && stateOK {
			t.Fatal("both profiles accepted the same signed Redirect")
		}
		if !plainOK && !stateOK {
			return
		}
		target, err := url.Parse(raw)
		if err != nil || target.Scheme != "https" || target.Host != "idp.example" || target.Path != "/slo" ||
			target.User != nil || target.Fragment != "" || len(raw) > 8192 {
			t.Fatal("accepted redirect escaped the configured destination")
		}
		values, err := url.ParseQuery(target.RawQuery)
		fieldCount := 4
		if stateOK {
			fieldCount++
			encoded := values.Get("RelayState")
			decoded, decodeErr := base64.RawURLEncoding.DecodeString(encoded)
			if len(values["RelayState"]) != 1 || decodeErr != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != encoded {
				t.Fatal("accepted a noncanonical opaque RelayState")
			}
		}
		if err != nil || len(values) != fieldCount || len(values["tenant"]) != 1 || values.Get("tenant") != "managed" ||
			len(values["SAMLRequest"]) != 1 || len(values["Signature"]) != 1 ||
			len(values["SigAlg"]) != 1 || values.Get("SigAlg") != saml.SignatureAlgorithmRSAPSSSHA256 {
			t.Fatal("accepted redirect escaped the selected binding")
		}
	})
}

func TestSAMLLogoutStartHTTPWithholdsMissingProjectionAndUnselectedNativeWire(t *testing.T) {
	t.Run("failure before authoritative session selection", func(t *testing.T) {
		config, probe := samlLogoutStartHTTPFixture(t)
		probe.result, probe.err = SAMLLogoutStartResult{}, errors.New("selection unavailable")
		router, _ := samlLogoutStartHTTPRouter(t, config, true)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, samlLogoutStartHTTPRequest())
		if w.Code != http.StatusServiceUnavailable || w.Header().Get("Location") != "" || len(w.Header().Values("Set-Cookie")) != 0 || strings.Contains(w.Body.String(), "localRevocation") {
			t.Fatal("unselected native failure invented local revocation or browser effects", w.Code)
		}
	})
	for _, tc := range []struct {
		name      string
		endpoint  string
		localOnly bool
	}{
		{"unselected provider redirect", "", false},
		{"mutually exclusive native outcomes", samlLogoutStartHTTPEndpoint, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config, probe := samlLogoutStartHTTPFixture(t)
			config.RedirectEndpoint = tc.endpoint
			probe.result.LocalOnly = tc.localOnly
			probe.result.ProviderRedirect = samlLogoutStartHTTPSignedRedirect(samlLogoutStartHTTPEndpoint)
			router, _ := samlLogoutStartHTTPRouter(t, config, true)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, samlLogoutStartHTTPRequest())
			if w.Code != http.StatusServiceUnavailable || w.Header().Get("Location") != "" {
				t.Fatal("unselected or contradictory native wire reached the browser", w.Code)
			}
			requireSAMLLogoutStartHTTPProjection(t, w, "unavailable", probe.result.LocalRevocation)
			requireLogoutCookieDeletion(t, w)
		})
	}
}

func TestSAMLLogoutStartHTTPRouteAndProjectionSchemaRequireExplicitSelection(t *testing.T) {
	config, probe := samlLogoutStartHTTPFixture(t)
	off, absent := samlLogoutStartHTTPRouter(t, config, false)
	r := samlLogoutStartHTTPRequest()
	r.Header.Del("Origin")
	w := httptest.NewRecorder()
	off.ServeHTTP(w, r)
	if w.Code != http.StatusNotFound || probe.calls != 0 || strings.Contains(string(absent.JSON()), `"/saml2/{provider_id}/logout"`) || strings.Contains(string(absent.JSON()), "localRevocation") {
		t.Fatal("unselected SAML logout start exposed its route, owner or wire schema")
	}
	on, selected := samlLogoutStartHTTPRouter(t, config, true)
	for _, required := range []string{`"/saml2/{provider_id}/logout"`, `"operationId":"identity.sso.saml-logout-start"`, `"finalRedirect"`, `"X-CSRF-Token"`, `"Idempotency-Key"`, `"localRevocation"`, `"sessionId"`, `"version"`, `"committed"`, `"reconciliationRequired"`, `"unknown-reconciliation"`} {
		if !strings.Contains(string(selected.JSON()), required) {
			t.Fatal("selected SAML logout start omitted its closed wire contract", required)
		}
	}
	for _, method := range []string{http.MethodGet, http.MethodPut} {
		w := httptest.NewRecorder()
		on.ServeHTTP(w, providerLogoutRequest(method, samlLogoutStartHTTPPath, ""))
		if w.Code < 400 || probe.calls != 0 || w.Header().Get("Location") != "" || len(w.Header().Values("Set-Cookie")) != 0 {
			t.Fatal("unsupported SAML logout start method reached native authority", w.Code)
		}
	}
}

func TestSAMLLogoutStartHTTPRejectsUnsafeConfiguration(t *testing.T) {
	for name, mutate := range map[string]func(*SAMLLogoutStartConfig){
		"missing tenant":          func(c *SAMLLogoutStartConfig) { c.TenantID = "" },
		"missing owner":           func(c *SAMLLogoutStartConfig) { c.Owner = nil },
		"typed nil owner":         func(c *SAMLLogoutStartConfig) { c.Owner = (*samlLogoutStartHTTPProbe)(nil) },
		"missing rate":            func(c *SAMLLogoutStartConfig) { c.Rate = nil },
		"invalid provider":        func(c *SAMLLogoutStartConfig) { c.ProviderID = "../other" },
		"unbounded duration":      func(c *SAMLLogoutStartConfig) { c.MaximumDuration = 0 },
		"HTTP origin":             func(c *SAMLLogoutStartConfig) { c.Origin = "http://tenant.example" },
		"origin path":             func(c *SAMLLogoutStartConfig) { c.Origin = "https://tenant.example/path" },
		"HTTP provider endpoint":  func(c *SAMLLogoutStartConfig) { c.RedirectEndpoint = "http://provider.example/logout" },
		"endpoint fragment":       func(c *SAMLLogoutStartConfig) { c.RedirectEndpoint += "#fragment" },
		"endpoint credentials":    func(c *SAMLLogoutStartConfig) { c.RedirectEndpoint = "https://user:pass@provider.example/logout" },
		"reserved endpoint query": func(c *SAMLLogoutStartConfig) { c.RedirectEndpoint += "&SAMLRequest=ambiguous" },
		"missing continuation":    func(c *SAMLLogoutStartConfig) { c.FinalRedirectAllowlist = nil },
		"HTTP continuation":       func(c *SAMLLogoutStartConfig) { c.FinalRedirectAllowlist = []string{"http://tenant.example/bye"} },
	} {
		t.Run(name, func(t *testing.T) {
			config, _ := samlLogoutStartHTTPFixture(t)
			mutate(&config)
			if _, err := NewSAMLLogoutStartOperation(config); err == nil {
				t.Fatal("unsafe SAML logout start configuration was accepted")
			}
		})
	}
}
