package ssohttp

import (
	"context"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	identityhttp "github.com/faustbrian/go-identity/http"
)

type samlLogoutRelayHTTPProbe struct {
	request func(context.Context, SAMLLogoutRequest, string) (SAMLLogoutRequestRelayResult, error)
	calls   int
}

func (p *samlLogoutRelayHTTPProbe) HandleSAMLLogoutRequestWithRelayState(ctx context.Context, request SAMLLogoutRequest, relayState string) (SAMLLogoutRequestRelayResult, error) {
	p.calls++
	return p.request(ctx, request, relayState)
}

func newSAMLLogoutRelayHTTPFixture(t *testing.T) (*samlLogoutHTTPFixture, *samlLogoutRelayHTTPProbe) {
	t.Helper()
	f := newSAMLLogoutHTTPFixture(t)
	owner := &samlLogoutRelayHTTPProbe{}
	owner.request = func(ctx context.Context, request SAMLLogoutRequest, relayState string) (SAMLLogoutRequestRelayResult, error) {
		deadline, ok := ctx.Deadline()
		if !ok || time.Until(deadline) <= 0 || time.Until(deadline) > f.config.MaximumDuration {
			t.Fatal("relay owner did not receive the bounded live request context")
		}
		if request.TenantID != testTenant || request.ProviderID != samlLogoutHTTPProvider || request.SAMLRequest != f.requestWire {
			t.Fatal("relay selection changed trusted scope or the original request wire")
		}
		return SAMLLogoutRequestRelayResult{
			SAMLLogoutRequestResult: SAMLLogoutRequestResult{Destination: samlLogoutHTTPEndpoint, SAMLResponse: f.signedResponse},
			RelayState:              relayState,
		}, nil
	}
	rebuildSAMLLogoutRelayHTTPFixture(t, f, owner)
	return f, owner
}

func rebuildSAMLLogoutRelayHTTPFixture(t *testing.T, f *samlLogoutHTTPFixture, owner SAMLLogoutRequestRelayOwner) {
	t.Helper()
	op, err := NewSAMLLogoutOperationWithRequestRelayState(f.config, owner)
	if err != nil {
		t.Fatal("select request RelayState transport", err)
	}
	f.router, f.document, err = identityhttp.NewRouter(identityhttp.TransportPolicy{
		Network: f.config.Network, HandlerTimeout: time.Second,
		CORS:     []identityhttp.CORSRoutePolicy{f.config.NavigationPolicy()},
		Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"},
	}, []identityhttp.OperationDescriptor{op}, nil)
	if err != nil {
		t.Fatal("compose request RelayState transport through the canonical router", err)
	}
}

func assertSAMLLogoutRelayHTTPForm(t *testing.T, f *samlLogoutHTTPFixture, w *httptest.ResponseRecorder, relayState string) {
	t.Helper()
	assertSAMLLogoutHTTPNoBrowserAuthority(t, w)
	if w.Code != http.StatusOK || w.Header().Get("Location") != "" ||
		w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" ||
		!strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") ||
		!strings.Contains(w.Header().Get("Content-Security-Policy"), "form-action "+samlLogoutHTTPIDP+";") {
		t.Fatal("relay response did not remain a private explicit IdP POST form", w.Code)
	}
	body := w.Body.String()
	attributes := func(tag string) map[string]string {
		out := make(map[string]string)
		for _, attribute := range regexp.MustCompile(`\s([a-z]+)="([^"]*)"`).FindAllStringSubmatch(tag, -1) {
			out[attribute[1]] = html.UnescapeString(attribute[2])
		}
		return out
	}
	forms := regexp.MustCompile(`<form\b[^>]*>`).FindAllString(body, -1)
	if len(forms) != 1 {
		t.Fatal("relay response did not contain exactly one form")
	}
	form := attributes(forms[0])
	if form["action"] != samlLogoutHTTPEndpoint || strings.ToLower(form["method"]) != "post" ||
		!strings.Contains(body, "&amp;profile=selected") || !strings.Contains(strings.ToLower(body), "<button") {
		t.Fatal("relay state changed the pinned IdP destination or explicit submission")
	}
	hidden := make(url.Values)
	for _, input := range regexp.MustCompile(`<input\b[^>]*>`).FindAllString(body, -1) {
		field := attributes(input)
		if field["type"] != "hidden" {
			t.Fatal("relay response exposed a non-hidden input")
		}
		hidden.Add(field["name"], field["value"])
	}
	wantFields := 1
	if relayState != "" {
		wantFields = 2
		if len(hidden["RelayState"]) != 1 || hidden.Get("RelayState") != relayState {
			t.Fatal("relay response did not echo the exact single opaque handle")
		}
	} else if _, present := hidden["RelayState"]; present {
		t.Fatal("absent relay state became a response field")
	}
	if len(hidden) != wantFields || len(hidden["SAMLResponse"]) != 1 || hidden.Get("SAMLResponse") != f.signedResponse {
		t.Fatal("relay response changed signed wire or added unselected fields")
	}
	for _, forbidden := range []string{"<script", "onload", "onsubmit", "http-equiv", "autofocus", "ambient-session-not-authority", strings.ToLower(f.requestWire)} {
		if strings.Contains(strings.ToLower(body), forbidden) {
			t.Fatal("relay response exposed request wire or automatic navigation", forbidden)
		}
	}
}

func TestSAMLLogoutRequestRelayHTTPPreservesOptionalExactHandle(t *testing.T) {
	for _, tc := range []struct {
		name, relayState string
	}{
		{"absent", ""},
		{"opaque handle", "Opaque_Handle-09"},
		{"80 byte boundary", strings.Repeat("A", 80)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			relayState := tc.relayState
			f, owner := newSAMLLogoutRelayHTTPFixture(t)
			original := owner.request
			owner.request = func(ctx context.Context, request SAMLLogoutRequest, got string) (SAMLLogoutRequestRelayResult, error) {
				if got != relayState {
					t.Fatal("native relay owner did not receive the exact optional handle")
				}
				return original(ctx, request, got)
			}
			form := url.Values{"SAMLRequest": {f.requestWire}}
			if relayState != "" {
				form.Set("RelayState", relayState)
			}
			r := f.formRequest(form.Encode())
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "ambient-session-not-authority"})
			assertSAMLLogoutRelayHTTPForm(t, f, f.serve(r), relayState)
			if owner.calls != 1 || f.requestCalls != 0 || f.responseCalls != 0 {
				t.Fatal("relay request dispatched to a legacy owner or more than once")
			}
		})
	}
}

func TestSAMLLogoutRequestRelayHTTPRejectsMalformedAndCrossedFormsBeforeOwner(t *testing.T) {
	for _, tc := range []struct {
		name  string
		field string
		relay []string
	}{
		{"empty handle", "SAMLRequest", []string{""}},
		{"duplicate handle", "SAMLRequest", []string{"same", "same"}},
		{"conflicting handles", "SAMLRequest", []string{"first", "second"}},
		{"over limit", "SAMLRequest", []string{strings.Repeat("a", 81)}},
		{"space", "SAMLRequest", []string{"not opaque"}},
		{"plus", "SAMLRequest", []string{"not+opaque"}},
		{"slash", "SAMLRequest", []string{"not/opaque"}},
		{"padding", "SAMLRequest", []string{"opaque="}},
		{"URL", "SAMLRequest", []string{"https://foreign.example/"}},
		{"NUL", "SAMLRequest", []string{"opaque\x00"}},
		{"non ASCII", "SAMLRequest", []string{"opáque"}},
		{"response with handle", "SAMLResponse", []string{"opaque"}},
		{"response with empty handle", "SAMLResponse", []string{""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, owner := newSAMLLogoutRelayHTTPFixture(t)
			wire := f.requestWire
			if tc.field == "SAMLResponse" {
				wire = f.responseWire
			}
			form := url.Values{tc.field: {wire}, "RelayState": tc.relay}
			assertSAMLLogoutHTTPDenied(t, f, f.serve(f.formRequest(form.Encode())), http.StatusBadRequest)
			if owner.calls != 0 || f.requestCalls != 0 || f.responseCalls != 0 {
				t.Fatal("malformed or response-crossed relay state reached native work")
			}
		})
	}
}

func TestSAMLLogoutRequestRelayHTTPStagesOwnerEchoAndEmptyReplay(t *testing.T) {
	for _, tc := range []struct {
		name, input, echo string
		noResponse        bool
	}{
		{"changed echo", "opaque", "changed", false},
		{"missing echo", "opaque", "", false},
		{"fabricated echo", "", "unexpected", false},
		{"echo without response", "opaque", "opaque", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f, owner := newSAMLLogoutRelayHTTPFixture(t)
			owner.request = func(context.Context, SAMLLogoutRequest, string) (SAMLLogoutRequestRelayResult, error) {
				response := SAMLLogoutRequestResult{Destination: samlLogoutHTTPEndpoint, SAMLResponse: f.signedResponse}
				if tc.noResponse {
					response = SAMLLogoutRequestResult{}
				}
				return SAMLLogoutRequestRelayResult{
					SAMLLogoutRequestResult: response,
					RelayState:              tc.echo,
				}, nil
			}
			form := url.Values{"SAMLRequest": {f.requestWire}}
			if tc.input != "" {
				form.Set("RelayState", tc.input)
			}
			w := f.serve(f.formRequest(form.Encode()))
			assertSAMLLogoutHTTPDenied(t, f, w, http.StatusServiceUnavailable)
			if owner.calls != 1 || strings.Contains(w.Body.String(), "RelayState") {
				t.Fatal("owner echo disagreement disclosed a partial response")
			}
		})
	}
	t.Run("empty settled replay", func(t *testing.T) {
		f, owner := newSAMLLogoutRelayHTTPFixture(t)
		owner.request = func(_ context.Context, _ SAMLLogoutRequest, relayState string) (SAMLLogoutRequestRelayResult, error) {
			if relayState != "opaque" {
				t.Fatal("empty replay did not receive the original handle")
			}
			return SAMLLogoutRequestRelayResult{}, nil
		}
		w := f.serve(f.formRequest(url.Values{"SAMLRequest": {f.requestWire}, "RelayState": {"opaque"}}.Encode()))
		assertSAMLLogoutHTTPDenied(t, f, w, http.StatusNoContent)
		if w.Body.Len() != 0 || owner.calls != 1 {
			t.Fatal("settled replay created new wire or echoed the handle")
		}
	})
}

func TestSAMLLogoutRequestRelayHTTPKeepsResponseAndLegacySelectionsSeparate(t *testing.T) {
	t.Run("optional legacy response owner", func(t *testing.T) {
		f, owner := newSAMLLogoutRelayHTTPFixture(t)
		w := f.serve(f.request("SAMLResponse"))
		assertSAMLLogoutHTTPNoBrowserAuthority(t, w)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != samlLogoutHTTPFinish ||
			owner.calls != 0 || f.requestCalls != 0 || f.responseCalls != 1 {
			t.Fatal("relay selection changed the separately selected response-settlement branch")
		}
	})
	t.Run("legacy constructor rejects relay", func(t *testing.T) {
		f := newSAMLLogoutHTTPFixture(t)
		w := f.serve(f.formRequest(url.Values{"SAMLRequest": {f.requestWire}, "RelayState": {"opaque"}}.Encode()))
		assertSAMLLogoutHTTPDenied(t, f, w, http.StatusBadRequest)
		if f.requestCalls != 0 || f.responseCalls != 0 {
			t.Fatal("new optional selection broadened the legacy closed form")
		}
	})
	t.Run("request-only relay selection", func(t *testing.T) {
		f, owner := newSAMLLogoutRelayHTTPFixture(t)
		f.config.Owner = nil
		if _, err := NewSAMLLogoutOperationWithRequestRelayState(f.config, owner); err == nil {
			t.Fatal("request-only relay selection accepted response continuations")
		}
		f.config.FinalRedirectAllowlist = nil
		rebuildSAMLLogoutRelayHTTPFixture(t, f, owner)
		doc := string(f.document.JSON())
		if !strings.Contains(doc, `"RelayState"`) || !strings.Contains(doc, `"maxLength":80`) ||
			strings.Contains(doc, `"SAMLResponse"`) || strings.Contains(doc, `"303"`) {
			t.Fatal("request-only OpenAPI does not describe just the selected RelayState and request branch")
		}
		assertSAMLLogoutHTTPDenied(t, f, f.serve(f.request("SAMLResponse")), http.StatusBadRequest)
		if owner.calls != 0 || f.requestCalls != 0 || f.responseCalls != 0 {
			t.Fatal("request-only relay selection reached response settlement")
		}
		w := f.serve(f.formRequest(url.Values{"SAMLRequest": {f.requestWire}, "RelayState": {"opaque"}}.Encode()))
		assertSAMLLogoutRelayHTTPForm(t, f, w, "opaque")
		if owner.calls != 1 || f.requestCalls != 0 || f.responseCalls != 0 {
			t.Fatal("request-only relay selection did not dispatch exclusively to its owner")
		}
	})
}

func TestSAMLLogoutRequestRelayHTTPRequiresUnambiguousOwnerSelection(t *testing.T) {
	f, owner := newSAMLLogoutRelayHTTPFixture(t)
	if _, err := NewSAMLLogoutOperationWithRequestRelayState(f.config, nil); err == nil {
		t.Fatal("request relay selection accepted no relay owner")
	}
	if _, err := NewSAMLLogoutOperationWithRequestRelayState(f.config, (*samlLogoutRelayHTTPProbe)(nil)); err == nil {
		t.Fatal("request relay selection accepted a typed-nil relay owner")
	}
	f.config.RequestOnlyOwner = f.owner
	if _, err := NewSAMLLogoutOperationWithRequestRelayState(f.config, owner); err == nil {
		t.Fatal("request relay selection accepted a competing RequestOnlyOwner")
	}
	f.config.Owner = nil
	f.config.FinalRedirectAllowlist = nil
	if _, err := NewSAMLLogoutOperationWithRequestRelayState(f.config, owner); err == nil {
		t.Fatal("request relay selection silently reused the legacy request-only owner")
	}
}

func FuzzSAMLLogoutRequestRelayState(f *testing.F) {
	for _, seed := range []string{"", "Opaque-IdP_9", strings.Repeat("a", 80), strings.Repeat("a", 81), "not opaque", "opaque\x00", "é"} {
		f.Add(seed)
	}
	grammar := regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
	f.Fuzz(func(t *testing.T, value string) {
		if validSAMLLogoutRelayState(value) != grammar.MatchString(value) {
			t.Fatal("RelayState validity did not match the selected opaque grammar")
		}
	})
}
