package i18n

import (
	"errors"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestLocaleMatching(t *testing.T) {
	for _, tc := range []struct {
		requested []string
		want      Locale
	}{
		{nil, "en"},
		{[]string{"fi-FI"}, "fi"},
		{[]string{"fr", "fi"}, "fi"},
		{[]string{"fi;q=0.2", "en;q=0.9"}, "en"},
		{[]string{"fi;q=0.900", "en;q=0.9"}, "fi"},
		{[]string{"en;q=0", "*"}, "fi"},
		{[]string{"*;q=0", "fi;q=1"}, "fi"},
		{[]string{"fi-Latn-FI-x-private"}, "fi"},
		{[]string{"FIN"}, "fi"},
		{[]string{"*", "fi"}, "fi"},
		{[]string{"*;q=1", "fi;q=0.8"}, "fi"},
	} {
		input := MatchInput{Requested: tc.requested, Supported: []Locale{"en", "fi"}, Default: "en"}
		before := append([]string(nil), tc.requested...)
		got, err := (DefaultMatcher{}).Match(input)
		if err != nil || got != tc.want || !reflect.DeepEqual(before, tc.requested) {
			t.Fatal("matching or input conservation", tc.requested, got, err)
		}
	}
	if got, err := (DefaultMatcher{}).Match(MatchInput{Requested: []string{"iw"}, Supported: []Locale{"he", "en"}, Default: "en"}); err != nil || got != "he" {
		t.Fatal("upstream alias not canonicalized", got, err)
	}
}

func TestMatcherConcurrentImmutableReads(t *testing.T) {
	input := MatchInput{Requested: []string{"fi-FI"}, Supported: []Locale{"en", "fi"}, Default: "en"}
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			for range 32 {
				if got, err := (DefaultMatcher{}).Match(input); err != nil || got != "fi" {
					t.Error("shared immutable input changed", got, err)
				}
			}
		}()
	}
	group.Wait()
}

func FuzzAcceptLanguage(f *testing.F) {
	for _, seed := range []string{"", "en", "fi-FI;q=0.9,en;q=0.5", "*;q=0", "de-DE-x-goethe", "en,,fi", "en;q=NaN", "fi\r\n"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		values, err := ParseAcceptLanguage(raw)
		if err != nil {
			if values != nil {
				t.Fatal("partial parse escaped")
			}
			return
		}
		if len(raw) > 4096 || len(values) > 32 {
			t.Fatal("input bound bypassed")
		}
		for _, value := range values {
			if len(value) > 64 {
				t.Fatal("range bound bypassed")
			}
		}
		got, err := (DefaultMatcher{}).Match(MatchInput{Requested: values, Supported: []Locale{"en", "fi", "de"}, Default: "en"})
		if err != nil && got != "" {
			t.Fatal("partial match escaped")
		}
		if err == nil && got != "en" && got != "fi" && got != "de" {
			t.Fatal("attacker catalog key escaped")
		}
	})
}

func TestLocaleMatchingRejectsMalformedOrUnboundedInput(t *testing.T) {
	for _, raw := range []string{"fi;q=.5", "fi;q=1.001", "fi;q=0.0001", "fi;q=-1", "fi;q=NaN", "fi;q=1;q=0", "fi;foo=1", "fi_*", "fi--FI", "fi\r\nX: bad", strings.Repeat("a", 65)} {
		if got, err := (DefaultMatcher{}).Match(MatchInput{Requested: []string{raw}, Supported: []Locale{"en", "fi"}, Default: "en"}); err == nil || got != "" || strings.Contains(err.Error(), raw) {
			t.Fatal("unsafe negotiation admitted", got, err)
		}
	}
	for _, input := range []MatchInput{
		{}, {Supported: []Locale{"en", "en"}, Default: "en"},
		{Supported: []Locale{"EN"}, Default: "EN"},
		{Supported: []Locale{"en"}, Default: "fi"},
		{Supported: make([]Locale, 257), Default: "en"},
		{Requested: make([]string, 33), Supported: []Locale{"en"}, Default: "en"},
		{Supported: []Locale{"en", "fi"}, Default: "en", Aliases: []LocaleAlias{{Alias: "en", Locale: "fi"}, {Alias: "fi", Locale: "en"}}},
	} {
		if got, err := (DefaultMatcher{}).Match(input); err == nil || got != "" {
			t.Fatal("invalid configuration admitted")
		}
	}
	_, err := (DefaultMatcher{}).Match(MatchInput{Requested: []string{"*;q=0"}, Supported: []Locale{"en", "fi"}, Default: "en"})
	var rejected NoAcceptableLocaleError
	if !errors.As(err, &rejected) {
		t.Fatal("all excluded locales returned a match", err)
	}
}

func TestLocaleAliasesAndHeader(t *testing.T) {
	input := MatchInput{Requested: []string{"custom"}, Supported: []Locale{"en", "fi"}, Default: "en", Aliases: []LocaleAlias{{Alias: "custom", Locale: "fi"}}}
	if got, err := (DefaultMatcher{}).Match(input); err != nil || got != "fi" {
		t.Fatal(got, err)
	}
	ranges, err := ParseAcceptLanguage(" fi-FI ; q=0.8, en ;q=0.2 ")
	if err != nil || !reflect.DeepEqual(ranges, []string{"fi-FI;q=0.8", "en;q=0.2"}) {
		t.Fatal(ranges, err)
	}
	for _, raw := range []string{strings.Repeat("x", 4097), strings.Repeat("en,", 32) + "fi", "en;q=NaN"} {
		if values, err := ParseAcceptLanguage(raw); err == nil || values != nil {
			t.Fatal("malformed header admitted")
		}
	}
}

func TestAcceptLanguageIgnoresBoundedEmptyListElements(t *testing.T) {
	// RFC 9110 section 5.6.1.2 requires recipient tolerance of reasonable
	// empty elements, including those created by merged header field values.
	for _, raw := range []string{"en,,fi", ", en, ,fi,"} {
		got, err := ParseAcceptLanguage(raw)
		if err != nil || !reflect.DeepEqual(got, []string{"en", "fi"}) {
			t.Fatal("valid merged list rejected", got, err)
		}
	}
	if got, err := ParseAcceptLanguage(", ,"); err != nil || got != nil {
		t.Fatal("empty list manufactured preference", got, err)
	}
}

func TestCanonicalLocaleRejectsDuplicateAndMisorderedSubtags(t *testing.T) {
	for _, raw := range []string{"sl-rozaj-rozaj", "en-a-foo-a-bar", "en-Latn-Cyrl", "en-US-GB", "en-a", "en-x", "en-1901-US"} {
		if got, err := CanonicalLocale(raw); err == nil || got != "" {
			t.Fatalf("invalid structural tag admitted: %q %q %v", raw, got, err)
		}
		if got, err := (DefaultMatcher{}).Match(MatchInput{Supported: []Locale{Locale(raw)}, Default: Locale(raw)}); err == nil || got != "" {
			t.Fatal("invalid configured locale admitted", got, err)
		}
	}
	for _, raw := range []string{"en-a-foo-x-a-foo", "en-x-foo-foo", "x-private-private", "de-1901", "zh-cmn-Hans-CN", "i-klingon"} {
		if got, err := CanonicalLocale(raw); err != nil || got == "" {
			t.Fatalf("valid structural tag rejected: %q %v", raw, err)
		}
	}
}
