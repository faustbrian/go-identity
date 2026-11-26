package onetap_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
)

const browserRetryFixture = "browser-start-retry-marker"

func browserStartSpec(t *testing.T, choice session.RememberChoice) onetap.BrowserStartRequestSpec {
	t.Helper()
	key, err := identity.NewIdempotencyKey([]byte(browserRetryFixture))
	if err != nil {
		t.Fatal(err)
	}
	prompt, err := onetap.NewOneTapPromptOptions(onetap.OneTapPromptConfig{Context: onetap.PromptSignIn, CancelOnTapOutside: true})
	if err != nil {
		t.Fatal(err)
	}
	options, err := onetap.NewBrowserStartOptions(prompt, onetap.OneTapButtonOptions{})
	if err != nil {
		t.Fatal(err)
	}
	remember, err := session.ResolveRememberPolicy(choice, session.LifetimeConfig{
		Default: session.BrowserSession, AbsoluteTTL: 48 * time.Hour, IdleTTL: 4 * time.Hour,
		RefreshAfter: 30 * time.Minute, FreshFor: 2 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	return onetap.BrowserStartRequestSpec{
		TenantID: "tenant-one", Origin: "https://login.example.test:8443",
		Network: "2001:db8::1", Device: "trusted-device-one", Key: key,
		Options: options, Remember: remember,
	}
}

func TestBrowserStartRequestPreservesOriginalOptionsRetryAndRemember(t *testing.T) {
	for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
		spec := browserStartSpec(t, choice)
		want := spec
		request, err := onetap.NewBrowserStartRequest(spec)
		if err != nil {
			t.Fatal(err)
		}
		spec.Origin, spec.Device, spec.Remember = "https://different.example.test", "different-device", session.RememberPolicy{}
		got, err := request.Bindings()
		if err != nil || got != want || got.Remember.Choice() != choice {
			t.Fatal("the original browser request or explicit lifetime policy was rewritten", err)
		}
		options, err := got.Options.Projection()
		if err != nil || options.Prompt == nil || options.Prompt.Context != onetap.PromptSignIn || !options.Prompt.CancelOnTapOutside {
			t.Fatal("the native owner did not receive the selected prompt", err)
		}
		options.Prompt.Context = onetap.PromptSignUp
		got, err = request.Bindings()
		if err != nil || got != want {
			t.Fatal("a detached projection changed the original retry intent", err)
		}
		for _, value := range []any{request, want} {
			formatted := fmt.Sprintf("%v %+v %#v %q", value, value, value, value)
			if strings.Contains(formatted, browserRetryFixture) || strings.Contains(formatted, want.Device) || strings.Contains(formatted, want.Origin) || strings.Contains(formatted, want.Network) {
				t.Fatal("implicit formatting disclosed original browser context")
			}
			if wire, err := json.Marshal(value); err == nil || len(wire) != 0 {
				t.Fatal("implicit serialization disclosed original browser context")
			}
		}
	}
}

func TestBrowserStartRequestRejectsUnusableAndAliasInputs(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*onetap.BrowserStartRequestSpec)
	}{
		{"missing tenant", func(c *onetap.BrowserStartRequestSpec) { c.TenantID = "" }},
		{"noncanonical origin", func(c *onetap.BrowserStartRequestSpec) { c.Origin = "https://Login.example.test" }},
		{"origin has path", func(c *onetap.BrowserStartRequestSpec) { c.Origin += "/callback" }},
		{"noncanonical IPv6", func(c *onetap.BrowserStartRequestSpec) { c.Network = "2001:0db8::1" }},
		{"mapped IPv4 alias", func(c *onetap.BrowserStartRequestSpec) { c.Network = "::ffff:192.0.2.10" }},
		{"zoned network", func(c *onetap.BrowserStartRequestSpec) { c.Network = "fe80::1%en0" }},
		{"unspecified network", func(c *onetap.BrowserStartRequestSpec) { c.Network = "0.0.0.0" }},
		{"multicast network", func(c *onetap.BrowserStartRequestSpec) { c.Network = "224.0.0.1" }},
		{"device too large", func(c *onetap.BrowserStartRequestSpec) { c.Device = strings.Repeat("a", 129) }},
		{"missing retry key", func(c *onetap.BrowserStartRequestSpec) { c.Key = identity.IdempotencyKey{} }},
		{"unresolved remember", func(c *onetap.BrowserStartRequestSpec) { c.Remember = session.RememberPolicy{} }},
		{"unselected experience", func(c *onetap.BrowserStartRequestSpec) { c.Options = onetap.BrowserStartOptions{} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := browserStartSpec(t, session.BrowserSession)
			tc.alter(&spec)
			request, err := onetap.NewBrowserStartRequest(spec)
			var classified *onetap.Error
			if !errors.As(err, &classified) || classified.Kind() != onetap.InvalidInput {
				t.Fatal("invalid request did not return a redacted input error", err)
			}
			if recovered, err := request.Bindings(); err == nil || recovered != (onetap.BrowserStartRequestSpec{}) {
				t.Fatal("a rejected request can reach native custody")
			}
		})
	}
}

func TestBrowserStartRequestRedactsWhenEmbeddedInDiagnosticState(t *testing.T) {
	spec := browserStartSpec(t, session.BrowserSession)
	request, err := onetap.NewBrowserStartRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	state := struct{ request onetap.BrowserStartRequest }{request: request}
	sliceState := struct{ requests []onetap.BrowserStartRequest }{requests: []onetap.BrowserStartRequest{request}}
	mapState := struct {
		requests map[string]onetap.BrowserStartRequest
	}{requests: map[string]onetap.BrowserStartRequest{"current": request}}
	for _, value := range []any{state, &state, sliceState, mapState} {
		formatted := fmt.Sprintf("%v %+v %#v %q", value, value, value, value)
		if strings.Contains(formatted, browserRetryFixture) || strings.Contains(formatted, spec.Device) || strings.Contains(formatted, spec.Origin) || strings.Contains(formatted, spec.Network) {
			t.Fatal("nested diagnostic formatting disclosed original browser context")
		}
	}
}
