package oauthhttp_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
	oauthhttp "github.com/faustbrian/go-identity/http/oauth"
	"github.com/faustbrian/go-identity/i18n"
	"github.com/faustbrian/go-identity/oauth/providers"
)

func providerListLocalization(t testing.TB) *oauthhttp.ProviderListLocalizationConfig {
	t.Helper()
	config := &oauthhttp.ProviderListLocalizationConfig{DefaultLocale: "en"}
	for _, translation := range []struct {
		locale      string
		invalid     string
		denied      string
		rate        string
		unavailable string
	}{
		{"en", "Invalid request.", "Request denied.", "Too many requests.", "Temporarily unavailable."},
		{"fi", "Virheellinen pyyntö.", "Pyyntö evätty.", "Liian monta pyyntöä.", "Tilapäisesti poissa käytöstä."},
		{"sv", "Ogiltig begäran.", "Begäran nekad.", "För många förfrågningar.", "Tillfälligt otillgänglig."},
	} {
		catalog, err := i18n.NewCatalog(translation.locale, []i18n.Message{
			{ID: oauthhttp.ProviderListInvalidRequestMessage, Template: translation.invalid},
			{ID: oauthhttp.ProviderListDeniedMessage, Template: translation.denied},
			{ID: oauthhttp.ProviderListRateLimitedMessage, Template: translation.rate},
			{ID: oauthhttp.ProviderListUnavailableMessage, Template: translation.unavailable},
		})
		if err != nil {
			t.Fatal(err)
		}
		config.Catalogs = append(config.Catalogs, catalog)
	}
	return config
}

type providerListHTTPResponse struct {
	status int
	header http.Header
	body   string
}

func providerListTLS(t testing.TB, handler http.Handler) func(string, []string) providerListHTTPResponse {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client := server.Client()
	client.Timeout = 5 * time.Second
	return func(query string, languages []string) providerListHTTPResponse {
		t.Helper()
		request, err := http.NewRequest(http.MethodGet, server.URL+"/v1/oauth/provider-list?"+query, nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Host = "app.example"
		for _, language := range languages {
			request.Header.Add("Accept-Language", language)
		}
		request.Header.Set("Cookie", "locale=sv; session=private-session")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, err := io.ReadAll(io.LimitReader(response.Body, 32769))
		if err != nil {
			t.Fatal(err)
		}
		if response.Header.Get("Cache-Control") != "no-store" || response.Header.Get("X-Content-Type-Options") != "nosniff" || response.Header.Get("Set-Cookie") != "" || response.Header.Get("Content-Type") != "application/json" {
			t.Fatal("localization changed safe public response metadata")
		}
		return providerListHTTPResponse{response.StatusCode, response.Header, string(body)}
	}
}

func TestProviderListLocalizationTLSInvalidCursor(t *testing.T) {
	for _, tc := range []struct {
		name      string
		languages []string
		locale    string
		message   string
		enabled   bool
	}{
		{"finnish", []string{"fi-FI,sv;q=0.5"}, "fi", "Virheellinen pyyntö.", true},
		{"swedish", []string{"sv"}, "sv", "Ogiltig begäran.", true},
		{"default", nil, "en", "Invalid request.", true},
		{"unsupported", []string{"de"}, "en", "Invalid request.", true},
		{"malformed", []string{"fi;q=broken"}, "en", "Invalid request.", true},
		{"duplicate-fields", []string{"fi", "sv"}, "en", "Invalid request.", true},
		{"duplicate-ranges", []string{"fi,FI;q=0.5"}, "en", "Invalid request.", true},
		{"oversize", []string{strings.Repeat("x", 4097)}, "en", "Invalid request.", true},
		{"excluded", []string{"*;q=0"}, "", "", true},
		{"disabled", []string{"fi"}, "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newProviderListFixture(t)
			if tc.enabled {
				fixture.config.Localization = providerListLocalization(t)
			}
			handler, _ := providerListDocumented(t, fixture.config)
			if tc.enabled {
				fixture.config.Localization.Catalogs[0].Messages[0].Template = "changed after construction"
			}
			request := providerListTLS(t, handler)
			forged := base64.RawURLEncoding.EncodeToString(make([]byte, 37))
			response := request("limit=1&cursor="+forged, tc.languages)
			var body map[string]string
			if err := json.Unmarshal([]byte(response.body), &body); err != nil {
				t.Fatal(err)
			}
			if response.status != 400 || body["error"] != "invalid_request" || body["message"] != tc.message || response.header.Get("Content-Language") != tc.locale || response.header.Get("Retry-After") != "" {
				t.Fatalf("localized invalid cursor response = %d %v %v", response.status, body, response.header)
			}
			vary := ""
			if tc.enabled {
				vary = "Accept-Language"
			}
			if response.header.Get("Vary") != vary {
				t.Fatal("selected language negotiation is not explicit", response.header)
			}
			if tc.message == "" && response.body != "{\"error\":\"invalid_request\"}\n" {
				t.Fatal("machine-only response changed", response.body)
			}
			if strings.Contains(response.body, forged) || strings.Contains(response.body, "private") {
				t.Fatal("error exposed input or credentials")
			}
			if fixture.backend.debits != 1 {
				t.Fatal("locale negotiation changed native rate admission")
			}
		})
	}
}

func TestProviderListLocalizationTLSAdmissionAndSuccess(t *testing.T) {
	fixture := newProviderListFixture(t)
	fixture.config.Localization = providerListLocalization(t)
	handler, _ := providerListDocumented(t, fixture.config)
	request := providerListTLS(t, handler)
	for i := 0; i < 100; i++ {
		response := request("limit=1", []string{"fi"})
		if response.status != 200 || response.header.Get("Content-Language") != "" || strings.Contains(response.body, "message") {
			t.Fatal("success page was localized", response.status, response.body)
		}
	}
	limited := request("limit=1", []string{"sv"})
	if limited.status != 429 || limited.header.Get("Retry-After") != "1" || limited.header.Get("Content-Language") != "sv" || limited.body != "{\"error\":\"rate_limited\",\"message\":\"För många förfrågningar.\"}\n" {
		t.Fatal("localized rate response changed denial", limited)
	}
	fixture.backend.err = errors.New("private ambiguous admission diagnostic")
	unavailable := request("limit=1", []string{"fi"})
	if unavailable.status != 503 || unavailable.header.Get("Retry-After") != "" || unavailable.header.Get("Content-Language") != "fi" || unavailable.body != "{\"error\":\"unavailable\",\"message\":\"Tilapäisesti poissa käytöstä.\"}\n" {
		t.Fatal("localized unavailable response changed denial", unavailable)
	}
}

func TestProviderListLocalizationTLSFallbackAndEncoding(t *testing.T) {
	for _, tc := range []struct {
		name          string
		message       string
		expectMessage string
	}{
		{"json-context", `<public> & "quoted"`, `<public> & "quoted"`},
		{"serialized-bound", strings.Repeat("<", 8192), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := newProviderListFixture(t)
			fixture.config.Localization = providerListLocalization(t)
			// Swedish lacks this message; resolver must report the locale of
			// the actual default translation, not the requested Swedish locale.
			fixture.config.Localization.Catalogs[2].Messages = fixture.config.Localization.Catalogs[2].Messages[1:]
			fixture.config.Localization.Catalogs[0].Messages[0].Template = tc.message
			handler, _ := providerListDocumented(t, fixture.config)
			response := providerListTLS(t, handler)("limit=1&cursor=bad", []string{"sv"})
			var body map[string]string
			if err := json.Unmarshal([]byte(response.body), &body); err != nil {
				t.Fatal(err)
			}
			expectLocale := ""
			if tc.expectMessage != "" {
				expectLocale = "en"
			}
			if response.status != 400 || body["error"] != "invalid_request" || body["message"] != tc.expectMessage || response.header.Get("Content-Language") != expectLocale || len(response.body) > 32768 {
				t.Fatal("fallback or final-context encoding changed response", response.status, len(response.body), response.header)
			}
		})
	}
}

func TestProviderListLocalizationTLSDeniedAndUnselectedErrors(t *testing.T) {
	fixture := newProviderListFixture(t)
	fixture.config.Localization = providerListLocalization(t)
	fixture.config.Catalog = &providerListFailure{err: providers.ProviderListAuthorizationDeniedError{}}
	handler, _ := providerListDocumented(t, fixture.config)
	response := providerListTLS(t, handler)("limit=1", []string{"sv"})
	if response.status != 403 || response.header.Get("Content-Language") != "sv" || response.body != "{\"error\":\"denied\",\"message\":\"Begäran nekad.\"}\n" {
		t.Fatal("safe typed denial did not retain machine identity", response)
	}
	request := providerListRequest("limit=1")
	request.Method = http.MethodPost
	request.Header.Set("Accept-Language", "fi")
	unselected := serveProviderList(t, handler, request)
	if unselected.Code != 405 || unselected.Header().Get("Content-Language") != "" || unselected.Header().Get("Allow") != "GET" || unselected.Body.String() != "{\"error\":\"method_not_allowed\"}\n" {
		t.Fatal("localization changed unselected errors", unselected.Code, unselected.Body.String())
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	cancellation := serveProviderList(t, handler, providerListRequest("limit=1").WithContext(canceled))
	if cancellation.Code != 503 || cancellation.Header().Get("Content-Language") != "" || cancellation.Body.String() != "{\"error\":\"unavailable\"}\n" {
		t.Fatal("cancellation invented a rendered language", cancellation.Code, cancellation.Body.String())
	}
}

func TestProviderListLocalizationRequiresCompleteDefaultCatalog(t *testing.T) {
	for _, change := range []func(*oauthhttp.ProviderListLocalizationConfig){
		func(c *oauthhttp.ProviderListLocalizationConfig) { c.DefaultLocale = "EN" },
		func(c *oauthhttp.ProviderListLocalizationConfig) { c.DefaultLocale = "de" },
		func(c *oauthhttp.ProviderListLocalizationConfig) { c.Catalogs = nil },
		func(c *oauthhttp.ProviderListLocalizationConfig) { c.Catalogs[0].Messages = c.Catalogs[0].Messages[1:] },
	} {
		fixture := newProviderListFixture(t)
		fixture.config.Localization = providerListLocalization(t)
		change(fixture.config.Localization)
		if _, err := oauthhttp.NewProviderListHandler(fixture.config); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid localization admitted", err)
		}
	}
}

func TestProviderListLocalizationWireOnlyChangesSelectedDenials(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		fixture := newProviderListFixture(t)
		if enabled {
			fixture.config.Localization = providerListLocalization(t)
		}
		_, document := providerListDocumented(t, fixture.config)
		var wire struct {
			Paths map[string]map[string]struct {
				Parameters []struct{ Name string }
				Responses  map[string]struct {
					Content map[string]struct {
						Schema struct{ Properties map[string]json.RawMessage }
					}
					Headers map[string]json.RawMessage
				}
			}
		}
		if err := json.Unmarshal(document.JSON(), &wire); err != nil {
			t.Fatal(err)
		}
		operation := wire.Paths["/v1/oauth/provider-list"]["get"]
		foundLanguage := false
		for _, parameter := range operation.Parameters {
			foundLanguage = foundLanguage || parameter.Name == "Accept-Language"
		}
		if foundLanguage != enabled {
			t.Fatal("locale parameter disagrees with configured profile")
		}
		for status, response := range operation.Responses {
			selected := enabled && (status == "400" || status == "403" || status == "429" || status == "503")
			_, message := response.Content["application/json"].Schema.Properties["message"]
			_, language := response.Headers["Content-Language"]
			if message != selected || language != selected {
				t.Fatal("wire invented or omitted localized response", status, enabled)
			}
		}
		if operation.Responses["429"].Headers["Retry-After"] == nil {
			t.Fatal("localized schema lost native retry metadata")
		}
	}
}

func FuzzProviderListLocalizationLanguage(f *testing.F) {
	for _, language := range []string{"fi-FI,sv;q=0.5", "sv", "fi;q=invalid", "fi,FI;q=0.5", "*;q=0", strings.Repeat("x", 4097)} {
		f.Add(language, false)
	}
	f.Add("fi", true)
	f.Fuzz(func(t *testing.T, language string, duplicate bool) {
		fixture := newProviderListFixture(t)
		fixture.config.Localization = providerListLocalization(t)
		handler, err := oauthhttp.NewProviderListHandler(fixture.config)
		if err != nil {
			t.Fatal(err)
		}
		forged := base64.RawURLEncoding.EncodeToString(make([]byte, 37))
		request := providerListRequest("limit=1&cursor=" + forged)
		request.Header["Accept-Language"] = []string{language}
		if duplicate {
			request.Header.Add("Accept-Language", "sv")
		}
		response := serveProviderList(t, handler, request)
		var body map[string]string
		if err := json.Unmarshal(response.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		messages := map[string]string{"en": "Invalid request.", "fi": "Virheellinen pyyntö.", "sv": "Ogiltig begäran."}
		locale := response.Header().Get("Content-Language")
		if response.Code != 400 || body["error"] != "invalid_request" || response.Body.Len() > 32768 || body["message"] != messages[locale] || len(body) > 2 || locale != "" && messages[locale] == "" {
			t.Fatal("untrusted language changed bounded safe denial", response.Code, locale)
		}
		if locale == "" && len(body) != 1 {
			t.Fatal("machine-only fallback acquired extra fields")
		}
	})
}
