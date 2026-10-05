package i18n

import (
	"context"
	"errors"
	"fmt"
	identity "github.com/faustbrian/go-identity"
	"strings"
	"sync"
	"testing"
)

func resolverFixture(t *testing.T) (*DefaultResolver, *ErrorRegistry, *CatalogStore, error) {
	t.Helper()
	registry := NewErrorRegistry()
	if err := registry.Register("identity.test.denied", "denied", ParameterSchema{}); err != nil {
		t.Fatal(err)
	}
	catalogs, err := NewCatalogStore([]Catalog{
		{Locale: "en", Version: 1, Messages: []Message{{ID: "denied", Template: "Denied"}}},
		{Locale: "fi", Version: 1, Messages: []Message{{ID: "denied", Template: "Estetty"}}},
		{Locale: "sv", Version: 1, Messages: []Message{{ID: "denied", Template: "Nekad"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs})
	if err != nil {
		t.Fatal(err)
	}
	return resolver, registry, catalogs, &registryError{identity: "identity.test.denied"}
}

func TestResolverPrecedenceAndOriginalError(t *testing.T) {
	resolver, registry, _, original := resolverFixture(t)
	for _, tc := range []struct{ explicit, session, cookie, header, want string }{
		{"fi", "sv", "en", "en", "fi"}, {"", "sv", "fi", "en", "sv"},
		{"", "", "fi", "sv", "fi"}, {"", "", "", "sv;q=0.5,fi;q=1", "fi"},
		{"", "", "", "", "en"}, {"de", "fi", "sv", "en", "fi"},
		{"fi-FI", "sv", "en", "en;q=0,fi;q=0", "fi"},
	} {
		wrapped := registryWrap{original}
		result, err := resolver.Resolve(context.Background(), ResolveInput{Explicit: tc.explicit, Session: tc.session, Cookie: tc.cookie, AcceptLanguage: tc.header, Default: "en", Error: wrapped})
		var typed *registryError
		if err != nil || result.Locale != tc.want || result.Code != "identity.test.denied" || result.MessageID != "denied" || !errors.Is(result, original) || !errors.As(result, &typed) {
			t.Fatalf("selection/identity lost for explicit=%q session=%q cookie=%q header=%q: locale=%s err=%v", tc.explicit, tc.session, tc.cookie, tc.header, result.Locale, err)
		}
	}
	if err := registry.Register("late", "denied", ParameterSchema{}); err == nil {
		t.Fatal("resolver did not seal registry")
	}
}

func TestResolverFailuresPreserveOriginalWithoutDiagnostics(t *testing.T) {
	resolver, _, _, original := resolverFixture(t)
	for _, input := range []ResolveInput{
		{Default: "en", Error: errors.New("identity.test.denied")},
		{Default: "en", Error: &registryError{identity: "unknown"}},
		{Default: "en", Error: original, Explicit: "bad_"},
		{Default: "en", Error: original, Session: strings.Repeat("x", 65)},
		{Default: "en", Error: original, AcceptLanguage: strings.Repeat("x", 4097)},
		{Default: "en", Error: original, AcceptLanguage: "*;q=0"},
		{Default: "xx", Error: original},
	} {
		result, err := resolver.Resolve(context.Background(), input)
		if err == nil || !errors.Is(err, input.Error) || result.Cause != nil || result.Message != "" {
			t.Fatal("failure lost original or returned partial rendering")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := resolver.Resolve(ctx, ResolveInput{Default: "en", Error: original})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, original) {
		t.Fatal("cancellation or original lost")
	}
}

func TestResolverAdmissionAndPublication(t *testing.T) {
	registry := NewErrorRegistry()
	if err := registry.Register("id", "missing", ParameterSchema{}); err != nil {
		t.Fatal(err)
	}
	catalogs, err := NewCatalogStore([]Catalog{{Locale: "en", Version: 1, Messages: []Message{{ID: "present", Template: "Present"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if resolver, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs}); err == nil || resolver != nil {
		t.Fatal("absent registered message admitted")
	}
	if err := registry.Register("still.open", "present", ParameterSchema{}); err != nil {
		t.Fatal("failed constructor sealed registry")
	}
	resolver, _, catalogs, original := resolverFixture(t)
	if err := catalogs.Replace(1, []Catalog{{Locale: "en", Version: 2, Messages: []Message{{ID: "other", Template: "Other"}}}}); err == nil {
		t.Fatal("catalog removed admitted message")
	}
	result, err := resolver.Resolve(context.Background(), ResolveInput{Default: "en", Error: original})
	if err != nil || result.Message != "Denied" {
		t.Fatal("rejected publication changed snapshot")
	}
}

type resolverMatcher func(MatchInput) (Locale, error)

func (f resolverMatcher) Match(input MatchInput) (Locale, error) { return f(input) }

func TestResolverCustomMatcherAndConcurrentSnapshots(t *testing.T) {
	resolver, registry, catalogs, original := resolverFixture(t)
	custom, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs, Matcher: resolverMatcher(func(input MatchInput) (Locale, error) { input.Supported[0] = "changed"; return "fi", nil })})
	if err != nil {
		t.Fatal(err)
	}
	if result, err := custom.Resolve(context.Background(), ResolveInput{Default: "en", Error: original}); err != nil || result.Locale != "fi" {
		t.Fatal("custom matcher failed")
	}
	bad, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs, Matcher: resolverMatcher(func(MatchInput) (Locale, error) { return "unknown", nil })})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Resolve(context.Background(), ResolveInput{Default: "en", Error: original}); err == nil || !errors.Is(err, original) {
		t.Fatal("custom arbitrary catalog key admitted")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 64 {
				result, err := resolver.Resolve(context.Background(), ResolveInput{Explicit: "fi", Default: "en", Error: original})
				if err != nil || result.Locale != "fi" || result.Message != "Estetty" && result.Message != "Uusi" {
					t.Error("mixed snapshot", err)
				}
			}
		}()
	}
	if err := catalogs.Replace(1, []Catalog{{Locale: "en", Version: 2, Messages: []Message{{ID: "denied", Template: "New"}}}, {Locale: "fi", Version: 2, Messages: []Message{{ID: "denied", Template: "Uusi"}}}}); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestResolverSchemaAdmissionAndTypedParts(t *testing.T) {
	registry := NewErrorRegistry()
	spec := ParameterSpec{Name: "text", Kind: identity.AttributeString, Context: ParameterHTML}
	if err := registry.Register("typed", "message", ParameterSchema{Parameters: []ParameterSpec{spec}}); err != nil {
		t.Fatal(err)
	}
	catalogs, err := NewCatalogStore([]Catalog{{Locale: "en", Version: 1, Messages: []Message{{ID: "message", Template: `{{value "text" "plain-text"}}`, Placeholders: []ParameterSpec{{Name: "text", Kind: identity.AttributeString, Context: ParameterPlainText}}}}}})
	if err != nil {
		t.Fatal(err)
	}
	if resolver, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs}); err == nil || resolver != nil {
		t.Fatal("wrong catalog context admitted")
	}
	if err := registry.Register("other", "message", ParameterSchema{Parameters: []ParameterSpec{spec}}); err != nil {
		t.Fatal("failed admission sealed registry")
	}
	correct := []Catalog{{Locale: "en", Version: 2, Messages: []Message{{ID: "message", Template: `Value: {{value "text" "html"}}`, Placeholders: []ParameterSpec{spec}}}}}
	if err := catalogs.Replace(1, correct); err != nil {
		t.Fatal(err)
	}
	resolver, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs})
	if err != nil {
		t.Fatal(err)
	}
	original := &registryError{identity: "typed", params: []SafeParameter{{Name: "text", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: "<private&>"}, Context: ParameterHTML}}}
	result, err := resolver.Resolve(context.Background(), ResolveInput{Default: "en", Error: original})
	if err != nil || result.Message != "Value: <private&>" || len(result.Parts) != 2 || result.Parts[1].Parameter.Context != ParameterHTML || result.CatalogVersion != 2 {
		t.Fatal("typed rendering lost", err)
	}
	if strings.Contains(fmt.Sprintf("%v %#v", result, result), "private") || strings.Contains(result.Error(), "private") {
		t.Fatal("diagnostic rendering exposed parameters")
	}
	result.Parameters[0].Value.String = "changed"
	result.Parts[1].Parameter.Value.String = "changed"
	if original.params[0].Value.String != "<private&>" {
		t.Fatal("result aliased error parameters")
	}
	correct[0].Version = 3
	correct[0].Messages[0].Placeholders[0].Context = ParameterPlainText
	correct[0].Messages[0].Template = `{{value "text" "plain-text"}}`
	if err := catalogs.Replace(2, correct); err == nil {
		t.Fatal("admitted schema changed after sealing")
	}
}

func TestResolverOneSnapshotAndBoundedCallbacks(t *testing.T) {
	_, registry, catalogs, original := resolverFixture(t)
	matcher := resolverMatcher(func(input MatchInput) (Locale, error) {
		if err := catalogs.Replace(1, []Catalog{{Locale: "en", Version: 2, Messages: []Message{{ID: "denied", Template: "Successor"}}}}); err != nil {
			t.Fatal(err)
		}
		return "fi", nil
	})
	resolver, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs, Matcher: matcher})
	if err != nil {
		t.Fatal(err)
	}
	result, err := resolver.Resolve(context.Background(), ResolveInput{Default: "en", Error: original})
	if err != nil || result.Locale != "fi" || result.Message != "Estetty" || result.CatalogVersion != 1 {
		t.Fatal("negotiation/render used different snapshots", err)
	}
	for _, matcher := range []Matcher{
		resolverMatcher(func(MatchInput) (Locale, error) { panic("private diagnostic") }),
		resolverMatcher(func(MatchInput) (Locale, error) { return "", errors.New("private diagnostic") }),
	} {
		resolver, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs, Matcher: matcher})
		if err != nil {
			t.Fatal(err)
		}
		_, err = resolver.Resolve(context.Background(), ResolveInput{Default: "en", Error: original})
		if err == nil || !errors.Is(err, original) || strings.Contains(err.Error(), "private") {
			t.Fatal("callback failure not redacted/preserved")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	resolver, err = NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs, Matcher: resolverMatcher(func(MatchInput) (Locale, error) { cancel(); return "en", nil })})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resolver.Resolve(ctx, ResolveInput{Default: "en", Error: original}); !errors.Is(err, context.Canceled) || !errors.Is(err, original) {
		t.Fatal("callback cancellation lost")
	}
}

func TestResolverAliasAndRegistryLifetime(t *testing.T) {
	_, registry, catalogs, original := resolverFixture(t)
	aliases := []LocaleAlias{{Alias: "de", Locale: "fi"}}
	resolver, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs, Aliases: aliases})
	if err != nil {
		t.Fatal(err)
	}
	aliases[0].Locale = "sv"
	// Caller registry reassignment cannot replace an admitted shared lifetime.
	*registry = *NewErrorRegistry()
	result, err := resolver.Resolve(context.Background(), ResolveInput{Explicit: "de", Default: "en", Error: original})
	if err != nil || result.Locale != "fi" {
		t.Fatal("constructor retained caller-owned configuration", err)
	}
	if err := catalogs.Replace(1, []Catalog{{Locale: "en", Version: 2, Messages: []Message{{ID: "denied", Template: "Denied"}}}}); err == nil {
		t.Fatal("alias target removed")
	}
}

func TestResolverConfiguredAliasesPrecedeCanonicalizationForEverySource(t *testing.T) {
	registry := NewErrorRegistry()
	if err := registry.Register("id", "message", ParameterSchema{}); err != nil {
		t.Fatal(err)
	}
	catalogs, err := NewCatalogStore([]Catalog{
		{Locale: "en", Version: 1, Messages: []Message{{ID: "message", Template: "English"}}},
		{Locale: "he", Version: 1, Messages: []Message{{ID: "message", Template: "Base"}}},
		{Locale: "he-IL", Version: 1, Messages: []Message{{ID: "message", Template: "Configured"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs, Aliases: []LocaleAlias{{Alias: "custom", Locale: "he-IL"}, {Alias: "iw", Locale: "he-IL"}}})
	if err != nil {
		t.Fatal(err)
	}
	original := &registryError{identity: "id"}
	for _, input := range []ResolveInput{
		{Explicit: "iw", Default: "en", Error: original},
		{Session: "iw", Default: "en", Error: original},
		{Cookie: "iw", Default: "en", Error: original},
		{AcceptLanguage: "iw", Default: "en", Error: original},
		{Explicit: "custom", Default: "en", Error: original},
		{Session: "custom", Default: "en", Error: original},
		{Cookie: "custom", Default: "en", Error: original},
		{AcceptLanguage: "custom", Default: "en", Error: original},
	} {
		result, err := resolver.Resolve(context.Background(), input)
		if err != nil || result.Locale != "he-IL" || result.Message != "Configured" {
			t.Errorf("configured alias lost: locale=%q err=%v", result.Locale, err)
		}
	}
}

func FuzzResolverInput(f *testing.F) {
	f.Add("fi", "sv", "en", "fi;q=1,en;q=0.5", "en")
	f.Add("", "", "", "*;q=0", "en")
	f.Fuzz(func(t *testing.T, explicit, session, cookie, header, fallback string) {
		resolver, _, _, original := resolverFixture(t)
		result, err := resolver.Resolve(context.Background(), ResolveInput{Explicit: explicit, Session: session, Cookie: cookie, AcceptLanguage: header, Default: fallback, Error: original})
		if err != nil {
			if result.Cause != nil || !errors.Is(err, original) {
				t.Fatal("failure lost original or exposed partial result")
			}
			return
		}
		if !errors.Is(result, original) || result.Code != "identity.test.denied" || result.MessageID != "denied" || result.CatalogVersion != 1 || result.Locale != "en" && result.Locale != "fi" && result.Locale != "sv" {
			t.Fatal("identity/snapshot changed")
		}
	})
}

func TestResolverDerivesParentsFromCanonicalIdentity(t *testing.T) {
	registry := NewErrorRegistry()
	if err := registry.Register("id", "message", ParameterSchema{}); err != nil {
		t.Fatal(err)
	}
	catalogs, err := NewCatalogStore([]Catalog{
		{Locale: "en", Version: 1, Messages: []Message{{ID: "message", Template: "English"}}},
		{Locale: "no", Version: 1, Messages: []Message{{ID: "message", Template: "Norwegian"}}},
		{Locale: "fi", Version: 1, Messages: []Message{{ID: "message", Template: "Finnish"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	resolver, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: catalogs, Aliases: []LocaleAlias{{Alias: "en", Locale: "fi"}}})
	if err != nil {
		t.Fatal(err)
	}
	original := &registryError{identity: "id"}
	for _, tag := range []string{"no-bok", "en-US"} {
		for _, input := range []ResolveInput{
			{Explicit: tag, Default: "en", Error: original}, {Session: tag, Default: "en", Error: original},
			{Cookie: tag, Default: "en", Error: original}, {AcceptLanguage: tag, Default: "en", Error: original},
		} {
			result, err := resolver.Resolve(context.Background(), input)
			if err != nil || result.Locale != "en" {
				t.Errorf("canonical identity %q selected %q; err=%v", tag, result.Locale, err)
			}
		}
	}
}
