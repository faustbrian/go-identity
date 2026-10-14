package i18n

import (
	"context"
	"errors"
	"math"
	"strings"
	"sync"
	"testing"

	identity "github.com/faustbrian/go-identity"
)

func catalogFixture(version uint64) []Catalog {
	schema := []ParameterSpec{{Name: "count", Kind: identity.AttributeInt64, Context: ParameterPlainText}}
	return []Catalog{{Locale: "en", Version: version, Messages: []Message{{ID: "attempts", Template: `{{value "count" "plain-text"}} {{plural "count" "=0" "none" "one" "attempt" "other" "attempts"}}`, Placeholders: schema}}}, {Locale: "fi", Version: version, Messages: []Message{{ID: "attempts", Template: `{{value "count" "plain-text"}} {{plural "count" "one" "yritys" "other" "yritystä"}}`, Placeholders: schema}}}}
}

func countParameter(count int64) []Parameter {
	return []Parameter{{Name: "count", Value: identity.AttributeScalar{Kind: identity.AttributeInt64, Int64: count}, Context: ParameterPlainText}}
}

func TestCatalogPluralFullWidthIntegers(t *testing.T) {
	// Russian CLDR cardinal rules distinguish suffix 1 (except 11), 2..4
	// (except 12..14), and the remaining integer suffixes. English one is
	// exactly 1, not any larger number ending in 1.
	schema := []ParameterSpec{{Name: "count", Kind: identity.AttributeInt64, Context: ParameterPlainText}}
	template := `{{plural "count" "one" "one" "few" "few" "many" "many" "other" "other"}}`
	store, err := NewCatalogStore([]Catalog{
		{Locale: "ru", Version: 1, Messages: []Message{{ID: "count", Template: template, Placeholders: schema}}},
		{Locale: "en", Version: 1, Messages: []Message{{ID: "count", Template: template, Placeholders: schema}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		locale Locale
		number int64
		want   string
	}{
		{"ru", 1000001, "one"}, {"ru", 1000002, "few"}, {"ru", 1000011, "many"},
		{"ru", -1000001, "one"}, {"ru", -1000002, "few"},
		{"ru", 9223372036854775801, "one"}, {"ru", 9223372036854775802, "few"},
		{"ru", math.MaxInt64, "many"}, {"ru", math.MinInt64, "many"},
		{"en", 1, "one"}, {"en", -1, "one"}, {"en", 10000001, "other"},
		{"en", math.MinInt64, "other"},
	} {
		result, err := store.Render(context.Background(), tc.locale, "count", countParameter(tc.number))
		if err != nil || result.Message != tc.want {
			t.Errorf("locale %s count %d: got %q, want %q; error %v", tc.locale, tc.number, result.Message, tc.want, err)
		}
	}
}

func TestCatalogRendersPluralAndPreservesTypedContext(t *testing.T) {
	input := catalogFixture(1)
	store, err := NewCatalogStore(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0].Messages[0].Template = "mutated"
	input[0].Messages[0].Placeholders[0].Name = "changed"
	for _, tc := range []struct {
		locale Locale
		count  int64
		want   string
	}{{"en", 0, "0 none"}, {"en", 1, "1 attempt"}, {"en", 2, "2 attempts"}, {"fi", 1, "1 yritys"}, {"fi", 2, "2 yritystä"}, {"en", math.MinInt64, "-9223372036854775808 attempts"}} {
		result, err := store.Render(context.Background(), tc.locale, "attempts", countParameter(tc.count))
		if err != nil || result.Message != tc.want || result.Version != 1 || len(result.Parameters) != 1 || result.Parameters[0].Value.Int64 != tc.count {
			t.Fatal("render changed semantics", result.Message, err)
		}
	}
}

func TestCatalogRejectsInvalidTemplatesAndTranslationMismatch(t *testing.T) {
	for _, source := range []string{`{{value "missing" "plain-text"}}`, `{{value "count" "html"}}`, `{{.count}}`, `{{printf "%s" "x"}}`, `{{if true}}x{{end}}`, `{{define "other"}}x{{end}}`, `{{value "count" "plain-text" | value "count"}}`, `{{plural "count" "one" "singular"}}`, `{{plural "count" "other" "a" "other" "b"}}`, `{{plural "count" "bogus" "a" "other" "b"}}`, `{{value "count" "plain-text"}`, strings.Repeat("x", 8193)} {
		c := catalogFixture(1)
		c[0].Messages[0].Template = source
		if store, err := NewCatalogStore(c); err == nil || store != nil {
			t.Fatal("invalid catalog admitted")
		}
	}
	for _, kind := range []string{"duplicate-message", "duplicate-locale", "schema", "version", "unused"} {
		c := catalogFixture(1)
		switch kind {
		case "duplicate-message":
			c[0].Messages = append(c[0].Messages, c[0].Messages[0])
		case "duplicate-locale":
			c = append(c, c[0])
		case "schema":
			c[1].Messages[0].Placeholders[0].Context = ParameterHTML
		case "version":
			c[1].Version = 2
		case "unused":
			c[0].Messages[0].Template = "literal"
		}
		if _, err := NewCatalogStore(c); err == nil {
			t.Fatal("conflicting catalog admitted", kind)
		}
	}
}

func TestCatalogSelectionLimitsAndMissingParameters(t *testing.T) {
	c := []Catalog{{Locale: "en", Version: 1, Messages: []Message{{ID: "mode", Template: `{{select "mode" "fast" "Fast" "other" "Standard"}}: {{value "text" "html"}}`, Placeholders: []ParameterSpec{{Name: "mode", Kind: identity.AttributeString, Context: ParameterPlainText}, {Name: "text", Kind: identity.AttributeString, Context: ParameterHTML}}}}}}
	s, err := NewCatalogStore(c)
	if err != nil {
		t.Fatal(err)
	}
	params := []Parameter{{Name: "mode", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: "fast"}, Context: ParameterPlainText}, {Name: "text", Value: identity.AttributeScalar{Kind: identity.AttributeString, String: "<unescaped&>"}, Context: ParameterHTML}}
	got, err := s.Render(context.Background(), "en", "mode", params)
	if err != nil || got.Message != "Fast: <unescaped&>" || len(got.Parts) != 3 || got.Parts[2].Parameter == nil || got.Parts[2].Parameter.Context != ParameterHTML {
		t.Fatal("typed context lost or prematurely escaped", err)
	}
	params[0].Value.String = "other choice"
	if got, err := s.Render(context.Background(), "en", "mode", params); err != nil || got.Message != "Standard: <unescaped&>" {
		t.Fatal("select fallback lost", err)
	}
	if got, err := s.Render(context.Background(), "en", "mode", nil); err == nil || got.Message != "" {
		t.Fatal("partial rendering returned")
	}
	if _, err := s.Render(context.Background(), "en", "absent", params); err == nil {
		t.Fatal("absent message admitted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Render(ctx, "en", "mode", params); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation lost", err)
	}
	c[0].Messages[0].Template = strings.Repeat(`{{value "text" "html"}}`, 3) + `{{select "mode" "other" "literal"}}`
	s, err = NewCatalogStore(c)
	if err != nil {
		t.Fatal(err)
	}
	params[1].Value.String = strings.Repeat("a", 4096)
	if got, err := s.Render(context.Background(), "en", "mode", params); err == nil || got.Message != "" || got.Parts != nil {
		t.Fatal("output bound bypassed")
	}
}

func TestCatalogAtomicReplacementAndConcurrentReads(t *testing.T) {
	s, err := NewCatalogStore(catalogFixture(1))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(2, catalogFixture(3)); err == nil {
		t.Fatal("stale publication accepted")
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 64 {
				v, err := s.Render(context.Background(), "en", "attempts", countParameter(1))
				if err != nil || v.Message != "1 attempt" || v.Version != 1 && v.Version != 2 {
					t.Error("partial snapshot observed", err)
				}
			}
		}()
	}
	if err := s.Replace(1, catalogFixture(2)); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if err := s.Replace(2, catalogFixture(2)); err == nil {
		t.Fatal("non-increasing version accepted")
	}
	locales, version := s.Locales()
	locales[0] = "changed"
	if again, _ := s.Locales(); again[0] != "en" || version != 2 {
		t.Fatal("locale result aliases catalog")
	}
}

func TestCatalogRejectsRootTemplateRedefinition(t *testing.T) {
	c := catalogFixture(1)
	c[0].Messages[0].Template = `{{define "message"}}{{value "count" "plain-text"}}{{end}}`
	if store, err := NewCatalogStore(c); err == nil || store != nil {
		t.Fatal("root definition bypassed restricted action grammar")
	}
}

func TestCatalogBoundsAndDefensiveCopies(t *testing.T) {
	for _, catalogs := range [][]Catalog{nil, make([]Catalog, 257), {{Locale: "EN", Version: 1, Messages: []Message{{ID: "literal", Template: "text"}}}}, {{Locale: "en", Version: 1, Messages: make([]Message, 10001)}}} {
		if store, err := NewCatalogStore(catalogs); err == nil || store != nil {
			t.Fatal("catalog bounds bypassed")
		}
	}
	c := catalogFixture(1)
	c[0].Messages[0].Template = strings.Repeat(`{{value "count" "plain-text"}}`, 257)
	if _, err := NewCatalogStore(c); err == nil {
		t.Fatal("template part bound bypassed")
	}
	s, err := NewCatalogStore(catalogFixture(1))
	if err != nil {
		t.Fatal(err)
	}
	params := countParameter(1)
	result, err := s.Render(context.Background(), "en", "attempts", params)
	if err != nil {
		t.Fatal(err)
	}
	result.Parameters[0].Value.Int64 = 20
	result.Parts[0].Parameter.Value.Int64 = 30
	if params[0].Value.Int64 != 1 {
		t.Fatal("render output aliases caller parameters")
	}
	if again, err := s.Render(context.Background(), "en", "attempts", params); err != nil || again.Message != "1 attempt" {
		t.Fatal("output mutated catalog")
	}
	for _, params := range [][]Parameter{make([]Parameter, 33), {{Name: strings.Repeat("a", 129), Value: identity.AttributeScalar{Kind: identity.AttributeInt64}, Context: ParameterPlainText}}} {
		if got, err := s.Render(context.Background(), "en", "attempts", params); err == nil || got.Parts != nil {
			t.Fatal("unsafe lookup parameters accepted")
		}
	}
	if _, err := s.Render(context.Background(), Locale(strings.Repeat("e", 65)), "attempts", countParameter(1)); err == nil {
		t.Fatal("oversized locale admitted")
	}
	if _, err := s.Render(context.Background(), "en", MessageID(strings.Repeat("m", 129)), countParameter(1)); err == nil {
		t.Fatal("oversized message admitted")
	}
}

func FuzzCatalogTemplate(f *testing.F) {
	for _, seed := range []string{`{{value "count" "plain-text"}}`, `{{plural "count" "one" "one" "other" "many"}}`, `{{define "message"}}{{value "count" "plain-text"}}{{end}}`, `{{.count}}`, "{"} {
		f.Add(seed, int64(1))
	}
	f.Fuzz(func(t *testing.T, source string, count int64) {
		c := catalogFixture(1)
		c[0].Messages[0].Template = source
		s, err := NewCatalogStore(c)
		if err != nil {
			if s != nil {
				t.Fatal("partial catalog escaped")
			}
			return
		}
		got, err := s.Render(context.Background(), "en", "attempts", countParameter(count))
		if err != nil {
			if got.Message != "" || got.Parts != nil {
				t.Fatal("partial rendering escaped")
			}
			return
		}
		if len(got.Message) == 0 || len(got.Message) > 8192 || got.Version != 1 || len(got.Parameters) != 1 || got.Parameters[0].Value.Int64 != count {
			t.Fatal("bound or typed value lost")
		}
	})
}
