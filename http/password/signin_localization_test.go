package passwordhttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
	passwordhttp "github.com/faustbrian/go-identity/http/password"
	"github.com/faustbrian/go-identity/i18n"
	openapi "github.com/faustbrian/go-openapi/v2"
	"github.com/faustbrian/go-openapi/v2/parse"
	"github.com/faustbrian/go-openapi/v2/validate"
)

func signinLocalization(t *testing.T) passwordhttp.SigninLocalizationConfig {
	t.Helper()
	config := passwordhttp.SigninLocalizationConfig{DefaultLocale: "en"}
	for _, locale := range []string{"en", "fi"} {
		var messages []i18n.Message
		for _, code := range []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request", "rate_limited", "rate_limiter_unavailable", "denied", "unavailable", "conflict", "in_progress"} {
			messages = append(messages, i18n.Message{ID: i18n.MessageID("identity.password.signin." + code), Template: locale + ": " + code})
		}
		catalog, err := i18n.NewCatalog(locale, messages)
		if err != nil {
			t.Fatal(err)
		}
		config.Catalogs = append(config.Catalogs, catalog)
	}
	return config
}

func signinLocalizedDocument(t *testing.T, c passwordhttp.SigninConfig, localization *passwordhttp.SigninLocalizationConfig) (http.Handler, []byte) {
	t.Helper()
	var feature identityhttp.Feature
	var err error
	if localization == nil {
		feature, err = passwordhttp.NewSigninFeature(c)
	} else {
		feature, err = passwordhttp.NewSigninFeatureWithLocalization(c, *localization)
	}
	if err != nil {
		t.Fatal(err)
	}
	handler, document, err := identityhttp.NewDocumentedHandler(context.Background(), identityhttp.DocumentConfig{Title: "Signin", Version: "1"}, identityhttp.FeatureServices{Features: []identityhttp.Feature{feature}})
	if err != nil {
		t.Fatal(err)
	}
	return handler, document.JSON()
}

func TestSigninLocalizationNegotiatesOnlyExplicitBoundedHeader(t *testing.T) {
	for _, tc := range []struct {
		name      string
		languages []string
		locale    string
	}{
		{"finnish", []string{"fi-FI,en;q=0.5"}, "fi"},
		{"default-ignores-locale-cookie", nil, "en"},
		{"unsupported", []string{"de"}, "en"},
		{"malformed", []string{"fi;q=broken"}, "en"},
		{"duplicate-fields", []string{"fi", "en"}, "en"},
		{"duplicate-ranges", []string{"fi,FI;q=0.5"}, "en"},
		{"oversized", []string{strings.Repeat("x", 4097)}, "en"},
		{"excluded", []string{"*;q=0"}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, c, work, device := newSignin(t)
			localization := signinLocalization(t)
			handler, _ := signinLocalizedDocument(t, c, &localization)
			for i := range localization.Catalogs {
				for j := range localization.Catalogs[i].Messages {
					localization.Catalogs[i].Messages[j].Template = "changed after construction"
				}
			}
			r := signinRequest(f, device)
			r.AddCookie(&http.Cookie{Name: "locale", Value: "fi"})
			for _, language := range tc.languages {
				r.Header.Add("Accept-Language", language)
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			var body map[string]any
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
				t.Fatal(err)
			}
			message, hasMessage := body["message"]
			if w.Code != 403 || body["error"] != "denied" || body["signedIn"] != false || body["commitOutcome"] != "not_committed" || w.Header().Get("Content-Language") != tc.locale || !slices.Contains(w.Header().Values("Vary"), "Accept-Language") {
				t.Fatal("language preference changed native denial", w.Code, body, w.Header())
			}
			if tc.locale == "" && hasMessage || tc.locale != "" && message != tc.locale+": denied" {
				t.Fatal("wrong translated denial or machine-only fallback", body)
			}
			if w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || w.Header().Get("Retry-After") != "" || w.Header().Get("Cache-Control") != "no-store" || work.calls != 1 || work.reads != 1 || f.rate.calls != 2 || work.last.Password.Len() != 0 {
				t.Fatal("localization changed admission, secret cleanup or credential custody")
			}
		})
	}
}

func TestSigninLocalizationSupplementsOriginalOutcomeWithoutDiagnosticText(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		status int
		code   string
		retry  string
	}{
		{"denied", 403, "denied", ""},
		{"invalid-request", 400, "invalid_request", ""},
		{"rate-outage", 503, "rate_limiter_unavailable", ""},
		{"source-outage", 503, "unavailable", ""},
		{"native-error", 503, "unavailable", ""},
		{"conflict", 409, "conflict", ""},
		{"in-progress", 409, "in_progress", "2"},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			var original map[string]any
			for _, selected := range []bool{false, true} {
				f, c, work, device := newSignin(t)
				r := signinRequest(f, device)
				r.Header.Set("Accept-Language", "fi")
				switch scenario.name {
				case "invalid-request":
					r.URL.RawQuery = "unexpected=value"
				case "rate-outage":
					f.rate.fail = true
				case "source-outage":
					work.sourceErr = errors.New("private provider source diagnostic")
				case "native-error":
					work.err = errors.New("private account lookup diagnostic")
				case "conflict":
					work.result.Issuance.CommitOutcome = identity.CommitOutcomeConflict
				case "in-progress":
					work.result.Issuance.CommitOutcome = identity.CommitOutcomeInProgress
					work.result.Issuance.RetryAfter = 1500 * time.Millisecond
				}
				var localization *passwordhttp.SigninLocalizationConfig
				if selected {
					config := signinLocalization(t)
					localization = &config
				}
				handler, _ := signinLocalizedDocument(t, c, localization)
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				var body map[string]any
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
					t.Fatal(err)
				}
				if w.Code != scenario.status || body["error"] != scenario.code || w.Header().Get("Retry-After") != scenario.retry || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" || strings.Contains(w.Body.String(), "private") {
					t.Fatal("localized projection changed classification, retry or custody", selected, w.Code, body)
				}
				if selected {
					if body["message"] != "fi: "+scenario.code || w.Header().Get("Content-Language") != "fi" {
						t.Fatal("missing safe canonical translation", body, w.Header())
					}
					delete(body, "message")
					if !reflect.DeepEqual(original, body) {
						t.Fatal("localization changed original command metadata", original, body)
					}
				} else {
					if _, exists := body["message"]; exists || w.Header().Get("Content-Language") != "" {
						t.Fatal("unselected feature acquired localization")
					}
					original = body
				}
			}
		})
	}
}

func TestSigninLocalizationSuccessRetainsOriginalCredentialDelivery(t *testing.T) {
	f, c, work, device := newSignin(t)
	signinIssuance(t, f, c, work)
	localization := signinLocalization(t)
	handler, _ := signinLocalizedDocument(t, c, &localization)
	r := signinRequest(f, device)
	r.Header.Set("Accept-Language", "fi")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != 200 || body["signedIn"] != true || body["commitOutcome"] != "committed" || body["sessionID"] != work.result.SessionID || len(w.Header().Values("Set-Cookie")) != 1 || w.Header().Get("X-CSRF-Token") == "" || work.calls != 1 || work.last.Password.Len() != 0 {
		t.Fatal("localization changed fresh session delivery", w.Code)
	}
	if _, exists := body["message"]; exists || w.Header().Get("Content-Language") != "" || body["error"] != nil {
		t.Fatal("successful authentication acquired a localized error")
	}
}

func TestSigninLocalizationPreservesRealIdentifierRateDenial(t *testing.T) {
	f, c, work, device := newSignin(t)
	localization := signinLocalization(t)
	handler, _ := signinLocalizedDocument(t, c, &localization)
	for i := 0; i < 11; i++ {
		// This fixture checks admission order within each request.
		f.rate.calls = 0
		r := signinRequest(f, device)
		r.Header.Set("Accept-Language", "fi")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if i < 10 {
			if w.Code != 403 {
				t.Fatal("identifier budget rejected an admitted attempt", i, w.Code)
			}
			continue
		}
		var body map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		if w.Code != 429 || body["error"] != "rate_limited" || body["message"] != "fi: rate_limited" || w.Header().Get("Content-Language") != "fi" || w.Header().Get("Retry-After") != "60" || work.calls != 10 || w.Header().Get("Set-Cookie") != "" || w.Header().Get("X-CSRF-Token") != "" {
			t.Fatal("localization changed real identifier admission or retry", w.Code, body, w.Header())
		}
	}
}

func TestSigninLocalizationReportsFallbackLocaleAndEscapesJSON(t *testing.T) {
	f, c, _, device := newSignin(t)
	localization := signinLocalization(t)
	message := `<public> & "quoted"`
	for i := range localization.Catalogs[0].Messages {
		localization.Catalogs[0].Messages[i].Template = message
	}
	localization.Catalogs[1].Messages = localization.Catalogs[1].Messages[:1]
	handler, _ := signinLocalizedDocument(t, c, &localization)
	r := signinRequest(f, device)
	r.Header.Set("Accept-Language", "fi")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != 403 || body["error"] != "denied" || body["message"] != message || w.Header().Get("Content-Language") != "en" {
		t.Fatal("fallback mislabeled language or changed final JSON context", w.Code, body, w.Header())
	}
}

func TestSigninLocalizationPreservesErrorWhenEscapedMessageExceedsResponseBound(t *testing.T) {
	f, c, _, device := newSignin(t)
	localization := signinLocalization(t)
	for i := range localization.Catalogs[1].Messages {
		localization.Catalogs[1].Messages[i].Template = strings.Repeat("<", 8192)
	}
	handler, _ := signinLocalizedDocument(t, c, &localization)
	r := signinRequest(f, device)
	r.Header.Set("Accept-Language", "fi")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if w.Code != 403 || body["error"] != "denied" || body["commitOutcome"] != "not_committed" || body["message"] != nil || w.Header().Get("Content-Language") != "" {
		t.Fatal("oversized rendered response lost its original machine-only denial", w.Code, body, w.Header())
	}
}

func TestSigninLocalizationRequiresEveryParameterFreeDefaultMessage(t *testing.T) {
	_, c, _, _ := newSignin(t)
	baseline := signinLocalization(t)
	for _, message := range baseline.Catalogs[0].Messages {
		t.Run(string(message.ID), func(t *testing.T) {
			config := signinLocalization(t)
			var messages []i18n.Message
			for _, candidate := range config.Catalogs[0].Messages {
				if candidate.ID != message.ID {
					messages = append(messages, candidate)
				}
			}
			config.Catalogs[0].Messages = messages
			if _, err := passwordhttp.NewSigninFeatureWithLocalization(c, config); !errors.Is(err, identityhttp.ErrInvalidInput) {
				t.Fatal("missing required default translation accepted", err)
			}
		})
	}
	for _, mutate := range []func(*passwordhttp.SigninLocalizationConfig){
		func(c *passwordhttp.SigninLocalizationConfig) { c.DefaultLocale = "EN" },
		func(c *passwordhttp.SigninLocalizationConfig) { c.DefaultLocale = "de" },
		func(c *passwordhttp.SigninLocalizationConfig) { c.Catalogs = nil },
		func(c *passwordhttp.SigninLocalizationConfig) {
			for i := range c.Catalogs {
				c.Catalogs[i].Messages[0].Template = `{{value "detail" "plain-text"}}`
				c.Catalogs[i].Messages[0].Placeholders = []i18n.ParameterSpec{{Name: "detail", Kind: identity.AttributeString, Context: i18n.ParameterPlainText}}
			}
		},
	} {
		config := signinLocalization(t)
		mutate(&config)
		if _, err := passwordhttp.NewSigninFeatureWithLocalization(c, config); !errors.Is(err, identityhttp.ErrInvalidInput) {
			t.Fatal("invalid localization configuration accepted", err)
		}
	}
}

func TestSigninLocalizationWireMatchesSelectedErrorOnly(t *testing.T) {
	for _, selected := range []bool{false, true} {
		t.Run(strconv.FormatBool(selected), func(t *testing.T) {
			f, c, _, device := newSignin(t)
			var localization *passwordhttp.SigninLocalizationConfig
			if selected {
				config := signinLocalization(t)
				localization = &config
			}
			handler, document := signinLocalizedDocument(t, c, localization)
			r := signinRequest(f, device)
			r.Header.Set("Accept-Language", "fi")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			parsed, err := openapi.ParseJSON(context.Background(), bytes.NewReader(document), parse.DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			for _, status := range []string{"200", "403"} {
				node := parsed.Raw()
				for _, key := range []string{"paths", "/v1/password/signin", "post", "responses", status, "content", "application/json", "schema"} {
					var ok bool
					node, ok = node.Lookup(key)
					if !ok {
						t.Fatal("missing selected wire schema", key)
					}
				}
				body := w.Body.Bytes()
				if status == "200" {
					body = []byte(`{"signedIn":true,"commandID":"AQEBAQEBAQEBAQEBAQEBAQ","sessionID":"session-a","commitOutcome":"committed","recovery":{"commandID":"AQEBAQEBAQEBAQEBAQEBAQ","tenantID":"tenant-a","flowID":"AQEBAQEBAQEBAQEBAQEBAQ","actorID":"public-entry","actorKind":"service-account"},"message":"unexpected"}`)
				}
				var candidate map[string]any
				if err := json.Unmarshal(body, &candidate); err != nil {
					t.Fatal(err)
				}
				for _, withMessage := range []bool{false, true} {
					if withMessage {
						candidate["message"] = "public translation"
					} else {
						delete(candidate, "message")
					}
					encoded, err := json.Marshal(candidate)
					if err != nil {
						t.Fatal(err)
					}
					instance, err := parse.JSON(context.Background(), bytes.NewReader(encoded), parse.DefaultLimits())
					if err != nil {
						t.Fatal(err)
					}
					result, err := validate.SchemaInstance(context.Background(), parsed, node, instance, validate.InstanceOptions{Direction: validate.DirectionResponse})
					wantValid := !withMessage || selected && status == "403"
					if err != nil || result.Valid() != wantValid {
						t.Fatal("wire localization must be optional and restricted to selected errors", status, withMessage, err)
					}
				}
			}
			var wire struct {
				Paths map[string]map[string]struct {
					Parameters []struct{ Name string }
					Responses  map[string]struct{ Headers map[string]json.RawMessage }
				}
			}
			if err := json.Unmarshal(document, &wire); err != nil {
				t.Fatal(err)
			}
			operation := wire.Paths["/v1/password/signin"]["post"]
			foundLanguage := false
			for _, parameter := range operation.Parameters {
				foundLanguage = foundLanguage || parameter.Name == "Accept-Language"
			}
			if foundLanguage != selected || (operation.Responses["403"].Headers["Content-Language"] != nil) != selected || operation.Responses["200"].Headers["Content-Language"] != nil {
				t.Fatal("wire localization metadata disagrees with selected error response")
			}
		})
	}
}
