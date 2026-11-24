package ssohttp

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	identityhttp "github.com/faustbrian/go-identity/http"
)

type samlLogoutResponseRelayHTTPProbe struct {
	settle func(context.Context, SAMLLogoutResponseRequest, string) (SAMLLogoutResponseResult, error)
}

func (p *samlLogoutResponseRelayHTTPProbe) SettleSAMLLogoutResponseWithRelayState(ctx context.Context, request SAMLLogoutResponseRequest, relayState string) (SAMLLogoutResponseResult, error) {
	return p.settle(ctx, request, relayState)
}

func TestSAMLLogoutResponseRelayHTTPContract(t *testing.T) {
	// RawURL-base64 encodes a 32-byte zero handle as exactly 43 A characters.
	handle := strings.Repeat("A", 43)
	compose := func(t *testing.T, f *samlLogoutHTTPFixture, selected SAMLLogoutRelaySelection) {
		t.Helper()
		op, err := NewSAMLLogoutOperationWithRelayState(f.config, selected)
		if err != nil {
			t.Fatal("select response RelayState transport", err)
		}
		f.router, f.document, err = identityhttp.NewRouter(identityhttp.TransportPolicy{
			Network: f.config.Network, HandlerTimeout: time.Second,
			CORS:     []identityhttp.CORSRoutePolicy{f.config.NavigationPolicy()},
			Document: identityhttp.DocumentConfig{Title: "Identity", Version: "1"},
		}, []identityhttp.OperationDescriptor{op}, nil)
		if err != nil {
			t.Fatal("compose response RelayState through the canonical router", err)
		}
	}
	responseForm := func(f *samlLogoutHTTPFixture) url.Values {
		return url.Values{"SAMLResponse": {f.responseWire}, "RelayState": {handle}}
	}

	for _, tc := range []struct {
		name, relayState string
		result           SAMLLogoutResponseResult
		err              error
		status           int
	}{
		{"native continuation", handle, SAMLLogoutResponseResult{FinalRedirect: samlLogoutHTTPFinish}, nil, http.StatusSeeOther},
		{"URL alphabet handle", base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat("\xfb", 32))), SAMLLogoutResponseResult{FinalRedirect: samlLogoutHTTPFinish}, nil, http.StatusSeeOther},
		{"settled replay", handle, SAMLLogoutResponseResult{}, nil, http.StatusNoContent},
		{"native denial", handle, SAMLLogoutResponseResult{FinalRedirect: samlLogoutHTTPFinish}, identity.ForbiddenError{}, http.StatusForbidden},
		{"native failure", handle, SAMLLogoutResponseResult{FinalRedirect: samlLogoutHTTPFinish}, errors.New("native settlement unavailable"), http.StatusServiceUnavailable},
		{"foreign continuation", handle, SAMLLogoutResponseResult{FinalRedirect: "https://foreign.example/bye"}, nil, http.StatusServiceUnavailable},
		{"unselected local continuation", handle, SAMLLogoutResponseResult{FinalRedirect: samlLogoutHTTPOrigin + "/unselected"}, nil, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSAMLLogoutHTTPFixture(t)
			calls := 0
			owner := &samlLogoutResponseRelayHTTPProbe{settle: func(ctx context.Context, request SAMLLogoutResponseRequest, relayState string) (SAMLLogoutResponseResult, error) {
				calls++
				deadline, bounded := ctx.Deadline()
				if !bounded || time.Until(deadline) <= 0 || time.Until(deadline) > f.config.MaximumDuration {
					t.Fatal("response relay owner did not receive the bounded live context")
				}
				if request.TenantID != testTenant || request.ProviderID != samlLogoutHTTPProvider || request.SAMLResponse != f.responseWire || relayState != tc.relayState {
					t.Fatal("response relay owner lost trusted route scope, original wire or exact opaque handle")
				}
				return tc.result, tc.err
			}}
			compose(t, f, SAMLLogoutRelaySelection{Response: owner})
			form := responseForm(f)
			form.Set("RelayState", tc.relayState)
			r := f.formRequest(form.Encode())
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "ambient-session-not-authority"})
			w := f.serve(r)
			assertSAMLLogoutHTTPNoBrowserAuthority(t, w)
			if calls != 1 || f.requestCalls != 0 || f.responseCalls != 0 {
				t.Fatal("response relay form selected a legacy or request owner")
			}
			if tc.status == http.StatusSeeOther {
				if w.Code != tc.status || w.Header().Get("Location") != samlLogoutHTTPFinish {
					t.Fatal("response relay settlement lost the exact native allowlisted continuation", w.Code)
				}
			} else {
				assertSAMLLogoutHTTPDenied(t, f, w, tc.status)
			}
			if tc.status == http.StatusNoContent && w.Body.Len() != 0 {
				t.Fatal("settled response replay created another document")
			}
			for _, secret := range []string{tc.relayState, f.responseWire, f.signedResponse, "ambient-session-not-authority"} {
				if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Header().Get("Location"), secret) {
					t.Fatal("response settlement disclosed relay or message custody")
				}
			}
		})
	}

	for _, tc := range []struct {
		name   string
		mutate func(*samlLogoutHTTPFixture, url.Values, *http.Request)
		status int
	}{
		{"empty handle", func(_ *samlLogoutHTTPFixture, form url.Values, _ *http.Request) { form.Set("RelayState", "") }, 400},
		{"short handle", func(_ *samlLogoutHTTPFixture, form url.Values, _ *http.Request) { form.Set("RelayState", handle[:42]) }, 400},
		{"long handle", func(_ *samlLogoutHTTPFixture, form url.Values, _ *http.Request) { form.Set("RelayState", handle+"A") }, 400},
		{"padded handle", func(_ *samlLogoutHTTPFixture, form url.Values, _ *http.Request) { form.Set("RelayState", handle+"=") }, 400},
		{"noncanonical trailing bits", func(_ *samlLogoutHTTPFixture, form url.Values, _ *http.Request) {
			form.Set("RelayState", handle[:42]+"B")
		}, 400},
		{"non URL alphabet", func(_ *samlLogoutHTTPFixture, form url.Values, _ *http.Request) {
			form.Set("RelayState", "+"+handle[1:])
		}, 400},
		{"duplicate handle", func(_ *samlLogoutHTTPFixture, form url.Values, _ *http.Request) { form.Add("RelayState", handle) }, 400},
		{"duplicate response", func(f *samlLogoutHTTPFixture, form url.Values, _ *http.Request) {
			form.Add("SAMLResponse", f.responseWire)
		}, 400},
		{"crossed request", func(f *samlLogoutHTTPFixture, form url.Values, _ *http.Request) {
			form.Set("SAMLRequest", f.requestWire)
		}, 400},
		{"response selection cannot enable request relay", func(f *samlLogoutHTTPFixture, form url.Values, _ *http.Request) {
			form.Del("SAMLResponse")
			form.Set("SAMLRequest", f.requestWire)
		}, 400},
		{"caller continuation", func(_ *samlLogoutHTTPFixture, form url.Values, _ *http.Request) {
			form.Set("finalRedirect", samlLogoutHTTPFinish)
		}, 400},
		{"wrong response case", func(f *samlLogoutHTTPFixture, form url.Values, _ *http.Request) {
			form.Del("SAMLResponse")
			form.Set("samlresponse", f.responseWire)
		}, 400},
		{"foreign origin", func(_ *samlLogoutHTTPFixture, _ url.Values, r *http.Request) {
			r.Header.Set("Origin", "https://foreign.example")
		}, 403},
		{"SP origin", func(_ *samlLogoutHTTPFixture, _ url.Values, r *http.Request) {
			r.Header.Set("Origin", samlLogoutHTTPOrigin)
		}, 403},
		{"absent origin with cookie", func(_ *samlLogoutHTTPFixture, _ url.Values, r *http.Request) {
			r.Header.Del("Origin")
			r.AddCookie(&http.Cookie{Name: "__Host-identity_session", Value: "ambient-session-not-authority"})
		}, 403},
		{"duplicate origin", func(_ *samlLogoutHTTPFixture, _ url.Values, r *http.Request) {
			r.Header.Add("Origin", samlLogoutHTTPIDP)
		}, 400},
		{"query authority", func(_ *samlLogoutHTTPFixture, _ url.Values, r *http.Request) {
			r.URL.RawQuery = "RelayState=" + handle
			r.RequestURI = r.URL.RequestURI()
		}, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newSAMLLogoutHTTPFixture(t)
			calls := 0
			owner := &samlLogoutResponseRelayHTTPProbe{settle: func(context.Context, SAMLLogoutResponseRequest, string) (SAMLLogoutResponseResult, error) {
				calls++
				return SAMLLogoutResponseResult{FinalRedirect: samlLogoutHTTPFinish}, nil
			}}
			compose(t, f, SAMLLogoutRelaySelection{Response: owner})
			form := responseForm(f)
			r := f.formRequest("")
			tc.mutate(f, form, r)
			body := form.Encode()
			r.Body, r.ContentLength = io.NopCloser(strings.NewReader(body)), int64(len(body))
			w := f.serve(r)
			assertSAMLLogoutHTTPDenied(t, f, w, tc.status)
			if calls != 0 || f.requestCalls != 0 || f.responseCalls != 0 || strings.Contains(w.Body.String(), handle) {
				t.Fatal("invalid response relay form reached native work or disclosed its handle")
			}
		})
	}

	t.Run("absent handle retains historical no-state custody", func(t *testing.T) {
		f := newSAMLLogoutHTTPFixture(t)
		calls := 0
		owner := &samlLogoutResponseRelayHTTPProbe{settle: func(context.Context, SAMLLogoutResponseRequest, string) (SAMLLogoutResponseResult, error) {
			calls++
			return SAMLLogoutResponseResult{}, nil
		}}
		compose(t, f, SAMLLogoutRelaySelection{Response: owner})
		r := f.request("SAMLResponse")
		r.AddCookie(&http.Cookie{Name: "RelayState", Value: handle})
		w := f.serve(r)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != samlLogoutHTTPFinish || calls != 0 || f.responseCalls != 1 || f.requestCalls != 0 {
			t.Fatal("absent form state was inferred from cookies or bypassed historical no-state custody")
		}
		assertSAMLLogoutHTTPNoBrowserAuthority(t, w)
	})

	t.Run("unselected response state stays closed", func(t *testing.T) {
		for _, requestRelay := range []bool{false, true} {
			f := newSAMLLogoutHTTPFixture(t)
			var requestOwner *samlLogoutRelayHTTPProbe
			if requestRelay {
				f, requestOwner = newSAMLLogoutRelayHTTPFixture(t)
			}
			w := f.serve(f.formRequest(responseForm(f).Encode()))
			assertSAMLLogoutHTTPDenied(t, f, w, http.StatusBadRequest)
			if f.requestCalls != 0 || f.responseCalls != 0 || requestOwner != nil && requestOwner.calls != 0 {
				t.Fatal("legacy or request-only relay selection enabled response RelayState")
			}
		}
	})

	t.Run("request and response relay remain separately selected", func(t *testing.T) {
		f, requestOwner := newSAMLLogoutRelayHTTPFixture(t)
		calls := 0
		responseOwner := &samlLogoutResponseRelayHTTPProbe{settle: func(_ context.Context, request SAMLLogoutResponseRequest, relayState string) (SAMLLogoutResponseResult, error) {
			calls++
			if request.SAMLResponse != f.responseWire || relayState != handle {
				t.Fatal("combined selection changed the response wire or handle")
			}
			return SAMLLogoutResponseResult{FinalRedirect: samlLogoutHTTPFinish}, nil
		}}
		compose(t, f, SAMLLogoutRelaySelection{Request: requestOwner, Response: responseOwner})
		requestHandle := "separate-idp-request-handle"
		w := f.serve(f.formRequest(url.Values{"SAMLRequest": {f.requestWire}, "RelayState": {requestHandle}}.Encode()))
		assertSAMLLogoutRelayHTTPForm(t, f, w, requestHandle)
		w = f.serve(f.formRequest(responseForm(f).Encode()))
		assertSAMLLogoutHTTPNoBrowserAuthority(t, w)
		if w.Code != http.StatusSeeOther || w.Header().Get("Location") != samlLogoutHTTPFinish || calls != 1 || requestOwner.calls != 1 || f.requestCalls != 0 || f.responseCalls != 0 {
			t.Fatal("combined relay selection crossed request and response ownership")
		}
		for _, token := range []string{`"SAMLRequest"`, `"SAMLResponse"`, `"RelayState"`, `"oneOf"`, `"303"`} {
			if !strings.Contains(string(f.document.JSON()), token) {
				t.Fatal("combined OpenAPI omitted a selected branch", token)
			}
		}
	})
}
