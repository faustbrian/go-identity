package onetap_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
)

func browserRedirectStartSpec(t *testing.T, choice session.RememberChoice) onetap.BrowserStartRequestSpec {
	t.Helper()
	spec := browserStartSpec(t, choice)
	spec.Options = redirectStartOptions(t)
	return spec
}

func TestBrowserRedirectStartRequestRetainsExactOriginal(t *testing.T) {
	for _, choice := range []session.RememberChoice{session.BrowserSession, session.PersistentSession} {
		spec := browserRedirectStartSpec(t, choice)
		want := spec
		request, err := onetap.NewBrowserRedirectStartRequest(spec)
		if err != nil {
			t.Fatal(err)
		}
		spec.TenantID, spec.Origin, spec.Network, spec.Device = "changed-tenant", "https://changed.test", "192.0.2.1", "changed-device"
		spec.Key, spec.Options, spec.Remember = identity.IdempotencyKey{}, onetap.BrowserStartOptions{}, session.RememberPolicy{}
		got, err := request.Bindings()
		if err != nil || got != want || got.Remember.Choice() != choice {
			t.Fatal("redirect request changed the original inputs or resolved Remember policy", err)
		}
		projection, err := got.Options.Projection()
		if err != nil || projection.Experience != onetap.BrowserStartRedirectButton || projection.Prompt != nil || projection.Button == nil || projection.Button.UXMode != onetap.ButtonRedirect || projection.Button.Width != 400 {
			t.Fatal("redirect request lost the exact selected button", err)
		}
		projection.Button.Width, projection.Button.UXMode = 1, onetap.ButtonPopup
		got.Origin, got.Options, got.Remember = "https://changed.test", onetap.BrowserStartOptions{}, session.RememberPolicy{}
		again, err := request.Bindings()
		if err != nil || again != want {
			t.Fatal("detached bindings changed retained redirect intent", err)
		}
		_, err = onetap.NewBrowserStartRequest(want)
		assertBrowserOptionsInvalid(t, err)
	}
}

func TestBrowserRedirectStartRequestRejectsInvalidShapeAndCallbackChoices(t *testing.T) {
	for _, tc := range []struct {
		name  string
		alter func(*onetap.BrowserStartRequestSpec)
	}{
		{"missing tenant", func(s *onetap.BrowserStartRequestSpec) { s.TenantID = "" }},
		{"invalid tenant", func(s *onetap.BrowserStartRequestSpec) { s.TenantID = " tenant" }},
		{"origin alias", func(s *onetap.BrowserStartRequestSpec) { s.Origin = "https://Login.example.test" }},
		{"origin path", func(s *onetap.BrowserStartRequestSpec) { s.Origin += "/callback" }},
		{"HTTP origin", func(s *onetap.BrowserStartRequestSpec) { s.Origin = "http://login.example.test" }},
		{"missing IP", func(s *onetap.BrowserStartRequestSpec) { s.Network = "" }},
		{"IP bound", func(s *onetap.BrowserStartRequestSpec) { s.Network = strings.Repeat("1", 46) }},
		{"IPv6 alias", func(s *onetap.BrowserStartRequestSpec) { s.Network = "2001:0db8::1" }},
		{"mapped IPv4", func(s *onetap.BrowserStartRequestSpec) { s.Network = "::ffff:192.0.2.10" }},
		{"zoned IP", func(s *onetap.BrowserStartRequestSpec) { s.Network = "fe80::1%en0" }},
		{"unspecified IP", func(s *onetap.BrowserStartRequestSpec) { s.Network = "0.0.0.0" }},
		{"multicast IP", func(s *onetap.BrowserStartRequestSpec) { s.Network = "224.0.0.1" }},
		{"missing device", func(s *onetap.BrowserStartRequestSpec) { s.Device = "" }},
		{"device bound", func(s *onetap.BrowserStartRequestSpec) { s.Device = strings.Repeat("a", 129) }},
		{"device control", func(s *onetap.BrowserStartRequestSpec) { s.Device = "device\n" }},
		{"missing retry key", func(s *onetap.BrowserStartRequestSpec) { s.Key = identity.IdempotencyKey{} }},
		{"unresolved Remember", func(s *onetap.BrowserStartRequestSpec) { s.Remember = session.RememberPolicy{} }},
		{"missing options", func(s *onetap.BrowserStartRequestSpec) { s.Options = onetap.BrowserStartOptions{} }},
		{"prompt", func(s *onetap.BrowserStartRequestSpec) {
			s.Options = browserStartSpec(t, session.BrowserSession).Options
		}},
		{"popup", func(s *onetap.BrowserStartRequestSpec) {
			button, err := onetap.NewOneTapButtonOptions(onetap.OneTapButtonConfig{Type: onetap.ButtonIcon, Theme: onetap.ButtonOutline, Size: onetap.ButtonSmall})
			if err != nil {
				t.Fatal(err)
			}
			s.Options, err = onetap.NewBrowserStartOptions(onetap.OneTapPromptOptions{}, button)
			if err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := browserRedirectStartSpec(t, session.BrowserSession)
			tc.alter(&spec)
			request, err := onetap.NewBrowserRedirectStartRequest(spec)
			assertBrowserOptionsInvalid(t, err)
			got, err := request.Bindings()
			assertBrowserOptionsInvalid(t, err)
			if got != (onetap.BrowserStartRequestSpec{}) {
				t.Fatal("rejected redirect request returned usable original input")
			}
		})
	}
}

func TestBrowserRedirectStartRequestIsDistinctAndCannotBeWireConstructed(t *testing.T) {
	callbackType := reflect.TypeFor[onetap.BrowserStartRequest]()
	redirectType := reflect.TypeFor[onetap.BrowserRedirectStartRequest]()
	if redirectType.AssignableTo(callbackType) || callbackType.AssignableTo(redirectType) || redirectType.ConvertibleTo(callbackType) || callbackType.ConvertibleTo(redirectType) {
		t.Fatal("redirect and callback request types permit cross-mode assignment or conversion")
	}
	var request onetap.BrowserRedirectStartRequest
	for _, decode := range []bool{false, true} {
		if decode {
			if err := json.Unmarshal([]byte(`{"TenantID":"tenant-one","Options":{"experience":"redirect_button"},"request":{},"original":{}}`), &request); err != nil {
				t.Fatal(err)
			}
		}
		got, err := request.Bindings()
		assertBrowserOptionsInvalid(t, err)
		if got != (onetap.BrowserStartRequestSpec{}) {
			t.Fatal("zero or wire-forged redirect request returned original input")
		}
	}
}

func TestBrowserRedirectStartRequestDeniesSerializationAndRedactsNestedDiagnostics(t *testing.T) {
	spec := browserRedirectStartSpec(t, session.BrowserSession)
	request, err := onetap.NewBrowserRedirectStartRequest(spec)
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range []onetap.BrowserRedirectStartRequest{{}, request} {
		if wire, err := original.MarshalJSON(); err == nil || len(wire) != 0 {
			t.Fatal("redirect request allowed JSON export")
		}
		if wire, err := original.MarshalText(); err == nil || len(wire) != 0 {
			t.Fatal("redirect request allowed text export")
		}
		if wire, err := json.Marshal(original); err == nil || len(wire) != 0 {
			t.Fatal("redirect request allowed implicit JSON export")
		}
	}
	state := struct {
		request onetap.BrowserRedirectStartRequest
	}{request: request}
	sliceState := struct {
		requests []onetap.BrowserRedirectStartRequest
	}{requests: []onetap.BrowserRedirectStartRequest{request}}
	mapState := struct {
		requests map[string]onetap.BrowserRedirectStartRequest
	}{requests: map[string]onetap.BrowserRedirectStartRequest{"current": request}}
	for _, value := range []any{request, &request, state, &state, sliceState, mapState} {
		formatted := fmt.Sprintf("%v %+v %#v %q", value, value, value, value)
		for _, private := range []string{browserRetryFixture, string(spec.TenantID), spec.Origin, spec.Network, spec.Device} {
			if strings.Contains(formatted, private) {
				t.Fatal("redirect request diagnostic formatting disclosed original context")
			}
		}
	}
}
