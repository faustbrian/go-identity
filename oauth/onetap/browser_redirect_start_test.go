package onetap_test

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/faustbrian/go-identity/oauth/onetap"
	"github.com/faustbrian/go-identity/session"
)

func redirectStartOptions(t *testing.T) onetap.BrowserStartOptions {
	t.Helper()
	button, err := onetap.NewOneTapButtonOptions(onetap.OneTapButtonConfig{
		Type: onetap.ButtonStandard, Theme: onetap.ButtonOutline, Size: onetap.ButtonLarge, Width: 400,
	})
	if err != nil {
		t.Fatal(err)
	}
	options, err := onetap.NewBrowserRedirectStartOptions(button)
	if err != nil {
		t.Fatal(err)
	}
	return options
}

func TestBrowserRedirectStartOptionsAreExplicitAndDetached(t *testing.T) {
	options := redirectStartOptions(t)
	projection, err := options.Projection()
	if err != nil || projection.Experience != onetap.BrowserStartRedirectButton || projection.Prompt != nil || projection.Button == nil || projection.Button.UXMode != onetap.ButtonRedirect {
		t.Fatal("redirect button did not remain an exclusive selection", err)
	}
	wire, err := json.Marshal(projection)
	if err != nil || string(wire) != `{"experience":"redirect_button","button":{"ux_mode":"redirect","type":"standard","theme":"outline","size":"large","width":400}}` {
		t.Fatal("unexpected redirect option wire representation", err)
	}
	projection.Button.UXMode, projection.Button.Width = onetap.ButtonPopup, 1
	again, err := options.Projection()
	if err != nil || again.Button.UXMode != onetap.ButtonRedirect || again.Button.Width != 400 {
		t.Fatal("detached option mutation changed original redirect selection", err)
	}
	invalid, err := onetap.NewBrowserRedirectStartOptions(onetap.OneTapButtonOptions{})
	assertBrowserOptionsInvalid(t, err)
	_, err = invalid.Projection()
	assertBrowserOptionsInvalid(t, err)
}

func TestBrowserRedirectStartOptionsCannotEnterPopupStart(t *testing.T) {
	spec := browserStartSpec(t, session.BrowserSession)
	spec.Options = redirectStartOptions(t)
	request, err := onetap.NewBrowserStartRequest(spec)
	assertBrowserOptionsInvalid(t, err)
	_, err = request.Bindings()
	assertBrowserOptionsInvalid(t, err)
}

func TestBrowserRedirectStartDerivesOnlyOriginalGoogleProfile(t *testing.T) {
	f := newRedirectFixture(t)
	original := f.original
	options := redirectStartOptions(t)
	for range 2 {
		got, err := f.validator.BrowserRedirectStart(options, f.binding.Transaction)
		if err != nil {
			t.Fatal(err)
		}
		binding := original.Transaction.Binding
		if got.ClientID != original.Provider.ClientID || got.LoginURI != binding.Intent.CallbackURL || got.Nonce != base64.RawURLEncoding.EncodeToString(binding.Intent.Nonce[:]) || got.State != string(binding.ID) || got.AllowedParentOrigin != binding.Intent.Origin || !got.IssuedAt.Equal(binding.IssuedAt) || !got.ExpiresAt.Equal(binding.ExpiresAt) {
			t.Fatal("launch projection changed original client, endpoint, nonce, flow locator, origin or lifetime")
		}
		if got.Experience != onetap.BrowserStartRedirectButton || got.Button.UXMode != onetap.ButtonRedirect || got.Button.Width != 400 {
			t.Fatal("launch projection lost exact redirect button choice")
		}
		wire, err := json.Marshal(got)
		if err != nil || strings.Contains(string(wire), "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEB") || strings.Contains(string(wire), "cookie") || strings.Contains(string(wire), "csrf") || strings.Contains(string(wire), "remember") {
			t.Fatal("launch projection included private browser custody or lifetime policy", err)
		}
		got.Button.Width, got.Nonce, got.State = 1, "changed", "changed"
	}
	retained, err := f.binding.Transaction.ProviderBindings()
	if err != nil || retained != original {
		t.Fatal("non-authoritative launch projection mutated original transaction", err)
	}
}

func TestBrowserRedirectStartRejectsNonOriginalProfile(t *testing.T) {
	f := newRedirectFixture(t)
	options := redirectStartOptions(t)
	prompt, err := onetap.NewOneTapPromptOptions(onetap.OneTapPromptConfig{Context: onetap.PromptSignIn})
	if err != nil {
		t.Fatal(err)
	}
	promptOptions, err := onetap.NewBrowserStartOptions(prompt, onetap.OneTapButtonOptions{})
	if err != nil {
		t.Fatal(err)
	}
	button, err := onetap.NewOneTapButtonOptions(onetap.OneTapButtonConfig{Type: onetap.ButtonIcon, Theme: onetap.ButtonOutline, Size: onetap.ButtonSmall})
	if err != nil {
		t.Fatal(err)
	}
	popupOptions, err := onetap.NewBrowserStartOptions(onetap.OneTapPromptOptions{}, button)
	if err != nil {
		t.Fatal(err)
	}
	for _, wrong := range []onetap.BrowserStartOptions{{}, promptOptions, popupOptions} {
		got, err := f.validator.BrowserRedirectStart(wrong, f.binding.Transaction)
		assertBrowserOptionsInvalid(t, err)
		if !reflect.DeepEqual(got, onetap.BrowserRedirectStartProjection{}) {
			t.Fatal("rejected selection exposed a launch projection")
		}
	}
	for _, tc := range []struct {
		name   string
		change func(*session.ProviderPreAuthTransactionSpec)
	}{
		{"callback", func(s *session.ProviderPreAuthTransactionSpec) {
			s.Provider.Mode = session.PreAuthProviderCallback
			s.Transaction.Binding.Intent.CallbackURL = ""
		}},
		{"provider", func(s *session.ProviderPreAuthTransactionSpec) { s.Provider.ProviderID = "another-google-profile" }},
		{"provider version", func(s *session.ProviderPreAuthTransactionSpec) { s.Provider.ProviderVersion++ }},
		{"client", func(s *session.ProviderPreAuthTransactionSpec) { s.Provider.ClientID = "another-client" }},
		{"endpoint", func(s *session.ProviderPreAuthTransactionSpec) {
			s.Transaction.Binding.Intent.CallbackURL = "https://app.test/other"
		}},
		{"origin", func(s *session.ProviderPreAuthTransactionSpec) {
			s.Transaction.Binding.Intent.Origin = "https://other.test"
			s.Transaction.Binding.Intent.CallbackURL = "https://other.test/callback"
		}},
		{"tenant", func(s *session.ProviderPreAuthTransactionSpec) {
			s.Transaction.Binding.Intent.TenantID = "other-tenant"
		}},
		{"policy", func(s *session.ProviderPreAuthTransactionSpec) {
			s.Transaction.Binding.Intent.PolicyID = "other-policy"
		}},
		{"policy version", func(s *session.ProviderPreAuthTransactionSpec) { s.Transaction.Binding.Intent.PolicyVersion++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := f.original
			tc.change(&spec)
			binding := providerBinding(t, spec)
			got, err := f.validator.BrowserRedirectStart(options, binding.Transaction)
			assertBrowserOptionsInvalid(t, err)
			if !reflect.DeepEqual(got, onetap.BrowserRedirectStartProjection{}) {
				t.Fatal("rejected original exposed a launch projection")
			}
		})
	}
	legacy, err := session.NewPreAuthTransaction(f.original.Transaction)
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range []session.PreAuthTransaction{{}, legacy} {
		_, err := f.validator.BrowserRedirectStart(options, original)
		assertBrowserOptionsInvalid(t, err)
	}
	callbackValidator, err := onetap.NewProviderBoundValidator(f.config)
	if err != nil {
		t.Fatal(err)
	}
	for _, validator := range []*onetap.ProviderBoundValidator{nil, {}, callbackValidator} {
		_, err := validator.BrowserRedirectStart(options, f.binding.Transaction)
		assertBrowserOptionsInvalid(t, err)
	}
}
