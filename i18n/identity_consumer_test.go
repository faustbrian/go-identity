package i18n_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"testing"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/i18n"
)

// This adapter belongs to the consuming application's user-validation operation,
// not to the identity kernel. Only this known typed/field pair is registered;
// arbitrary diagnostics and caller-controlled field labels are never forwarded.
type userValidationFailure struct{ cause identity.InvalidInputError }

func (userValidationFailure) Error() string   { return "example: invalid user" }
func (e userValidationFailure) Unwrap() error { return e.cause }
func (userValidationFailure) ErrorIdentity() i18n.ErrorIdentity {
	return "example.user.invalid"
}
func (userValidationFailure) SafeParameters() []i18n.SafeParameter {
	return []i18n.SafeParameter{{
		Name: "field", Context: i18n.ParameterHTML,
		Value: identity.AttributeScalar{Kind: identity.AttributeString, String: "<user ID>"},
	}}
}

func adaptUserValidation(err error) error {
	if invalid, ok := err.(identity.InvalidInputError); ok && invalid.Field == "user_id" {
		return userValidationFailure{cause: invalid}
	}
	return err
}

func userValidationResolver() (*i18n.DefaultResolver, error) {
	registry := i18n.NewErrorRegistry()
	schema := []i18n.ParameterSpec{{Name: "field", Kind: identity.AttributeString, Context: i18n.ParameterHTML}}
	if err := registry.Register("example.user.invalid", "user.invalid", i18n.ParameterSchema{Parameters: schema}); err != nil {
		return nil, err
	}
	catalogs, err := i18n.NewCatalogStore([]i18n.Catalog{
		{Locale: "en", Version: 1, Messages: []i18n.Message{{ID: "user.invalid", Template: `Invalid {{value "field" "html"}}`, Placeholders: schema}}},
		{Locale: "fi", Version: 1, Messages: []i18n.Message{{ID: "user.invalid", Template: `Virheellinen {{value "field" "html"}}`, Placeholders: schema}}},
	})
	if err != nil {
		return nil, err
	}
	return i18n.NewConfiguredResolver(i18n.ResolverConfig{Registry: registry, Catalogs: catalogs, Fallbacks: []i18n.Locale{"en", "fi"}})
}

func ExampleDefaultResolver_Resolve_identityValidation() {
	resolver, err := userValidationResolver()
	if err != nil {
		panic(err)
	}
	// A real public identity operation produces the original typed failure.
	original := (identity.User{TenantID: "tenant", Status: identity.StatusActive, Version: 1}).Validate("tenant")
	localized, err := resolver.Resolve(context.Background(), i18n.ResolveInput{
		Explicit: "fi-FI", Session: "en", Cookie: "en", AcceptLanguage: "en", Default: "en",
		Error: fmt.Errorf("validate user: %w", adaptUserValidation(original)),
	})
	if err != nil {
		panic(err)
	}
	var invalid identity.InvalidInputError
	fmt.Println(localized.Code, localized.MessageID, localized.Locale)
	fmt.Println(errors.Is(localized, original), errors.As(localized, &invalid), invalid.Field)
	fmt.Println(localized.Parameters[0].Value.String)
	// The final HTML owner escapes once; neither registry nor catalog pre-escapes.
	page := template.Must(template.New("error").Parse(`<p>{{.Message}}</p>`))
	var output bytes.Buffer
	if err := page.Execute(&output, localized); err != nil {
		panic(err)
	}
	fmt.Println(output.String())
	// Output:
	// example.user.invalid user.invalid fi
	// true true user_id
	// <user ID>
	// <p>Virheellinen &lt;user ID&gt;</p>
}

func TestPublicIdentityConsumerLocaleSourcesAndErrorSemantics(t *testing.T) {
	resolver, err := userValidationResolver()
	if err != nil {
		t.Fatal(err)
	}
	original := (identity.User{TenantID: "tenant", Status: identity.StatusActive, Version: 1}).Validate("tenant")
	if original == nil {
		t.Fatal("public identity validation accepted a missing user ID")
	}
	wrapped := fmt.Errorf("validate user: %w", adaptUserValidation(original))
	for _, tc := range []struct {
		name, explicit, session, cookie, header, locale string
	}{
		{"explicit region", "fi-FI", "en", "en", "en", "fi"},
		{"stored preference", "", "fi", "en", "en", "fi"},
		{"trusted cookie", "", "", "fi", "en", "fi"},
		{"weighted header", "", "", "", "en;q=0.2,fi;q=0.8", "fi"},
		{"configured fallback", "", "", "", "", "en"},
		{"unsupported preference", "de", "fi", "en", "en", "fi"},
		{"higher source overrides header exclusion", "fi", "", "", "fi;q=0,en", "fi"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := resolver.Resolve(context.Background(), i18n.ResolveInput{Explicit: tc.explicit, Session: tc.session, Cookie: tc.cookie, AcceptLanguage: tc.header, Default: "en", Error: wrapped})
			want := "Invalid <user ID>"
			if tc.locale == "fi" {
				want = "Virheellinen <user ID>"
			}
			var invalid identity.InvalidInputError
			if err != nil || result.Locale != tc.locale || result.Message != want || result.Code != "example.user.invalid" || result.MessageID != "user.invalid" || result.Cause != wrapped || !errors.Is(result, original) || !errors.As(result, &invalid) || invalid.Field != "user_id" {
				t.Fatal("public consumer lost selected locale, machine/message identity or original typed failure")
			}
			if len(result.Parameters) != 1 || result.Parameters[0].Value.Kind != identity.AttributeString || result.Parameters[0].Value.String != "<user ID>" || result.Parameters[0].Context != i18n.ParameterHTML {
				t.Fatal("public consumer lost the exact unescaped safe typed parameter")
			}
		})
	}
	for _, input := range []i18n.ResolveInput{
		{Explicit: "fi", Cookie: "en_US", Default: "en", Error: wrapped},
		{Explicit: "fi", AcceptLanguage: "en;q=2", Default: "en", Error: wrapped},
		{AcceptLanguage: "*;q=0", Default: "en", Error: wrapped},
		{Default: "de", Error: wrapped},
		{Default: "en", Error: errors.New("identity: invalid input")},
		{Default: "en", Error: original},
	} {
		result, err := resolver.Resolve(context.Background(), input)
		if err == nil || !errors.Is(err, input.Error) || result.Cause != nil || result.Message != "" || result.Parameters != nil {
			t.Fatal("invalid source or unregistered error produced a partial translation or lost its original cause")
		}
	}
	// The adapter does not turn arbitrary typed field values into public data.
	other := identity.InvalidInputError{Field: "not-a-registered-field"}
	if adaptUserValidation(other) != other {
		t.Fatal("consumer adapter accepted an unregistered field")
	}
}
