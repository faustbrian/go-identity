// Package i18n provides transport-neutral bounded identity localization.
// Locale matching does not authenticate preferences, persist personal data,
// translate diagnostics, or change machine error identity.
package i18n

import (
	"fmt"
	"slices"
	"strings"

	"golang.org/x/text/language"
)

// Locale is a canonical BCP 47 tag of at most 64 ASCII bytes. Zero is invalid.
// CanonicalLocale validates values; a cast alone does not establish validity.
type Locale string

// InvalidLocaleError is a redacted malformed/bounded-input classification.
type InvalidLocaleError struct{}

func (InvalidLocaleError) Error() string { return "identity.i18n: invalid locale input" }

// NoAcceptableLocaleError means every configured locale was explicitly excluded.
// A transport may separately choose an HTTP negotiation failure policy; this
// matcher never silently resurrects an excluded locale.
type NoAcceptableLocaleError struct{}

func (NoAcceptableLocaleError) Error() string { return "identity.i18n: no acceptable locale" }

// CanonicalLocale parses a bounded strict tag using pinned upstream language
// data. It rejects underscores, whitespace, controls and wildcards, preserves
// canonical case and applies registered aliases. It never returns raw parser
// diagnostics. Unsupported tags cannot become accepted stored preferences merely
// because they parse: persistence must also select a configured supported value.
func CanonicalLocale(raw string) (Locale, error) {
	if !basicRange(raw) || !structuralTag(raw) {
		return "", InvalidLocaleError{}
	}
	tag, err := language.Parse(raw)
	if err != nil {
		return "", InvalidLocaleError{}
	}
	canonical := tag.String()
	if len(canonical) > 64 {
		return "", InvalidLocaleError{}
	}
	return Locale(canonical), nil
}

// structuralTag checks RFC 5646 ordering and uniqueness before the upstream
// parser can silently repair invalid tags. Registry validity stays upstream.
func structuralTag(raw string) bool {
	parts := strings.Split(strings.ToLower(raw), "-")
	// RFC 5646 section 2.1's fixed grandfathered list is not generated from
	// mutable registry data; its exceptional grammar must precede normal parsing.
	switch strings.ToLower(raw) {
	case "en-gb-oed", "i-ami", "i-bnn", "i-default", "i-enochian", "i-hak", "i-klingon", "i-lux", "i-mingo", "i-navajo", "i-pwn", "i-tao", "i-tay", "i-tsu", "sgn-be-fr", "sgn-be-nl", "sgn-ch-de", "art-lojban", "cel-gaulish", "no-bok", "no-nyn", "zh-guoyu", "zh-hakka", "zh-min", "zh-min-nan", "zh-xiang":
		return true
	}
	if parts[0] == "x" {
		return len(parts) > 1
	}
	if len(parts[0]) < 2 || len(parts[0]) > 8 {
		return false
	}
	alpha := func(s string) bool {
		for i := range len(s) {
			if s[i] < 'a' || s[i] > 'z' {
				return false
			}
		}
		return true
	}
	digits := func(s string) bool {
		for i := range len(s) {
			if s[i] < '0' || s[i] > '9' {
				return false
			}
		}
		return true
	}
	i := 1
	if len(parts[0]) <= 3 {
		for count := 0; i < len(parts) && count < 3 && len(parts[i]) == 3 && alpha(parts[i]); count++ {
			i++
		}
	}
	if i < len(parts) && len(parts[i]) == 4 && alpha(parts[i]) {
		i++
	}
	if i < len(parts) && (len(parts[i]) == 2 && alpha(parts[i]) || len(parts[i]) == 3 && digits(parts[i])) {
		i++
	}
	variants := make(map[string]bool)
	for i < len(parts) && (len(parts[i]) >= 5 || len(parts[i]) == 4 && parts[i][0] >= '0' && parts[i][0] <= '9') {
		if variants[parts[i]] {
			return false
		}
		variants[parts[i]] = true
		i++
	}
	singletons := make(map[string]bool)
	for i < len(parts) && len(parts[i]) == 1 && parts[i] != "x" {
		if singletons[parts[i]] {
			return false
		}
		singletons[parts[i]] = true
		i++
		start := i
		for i < len(parts) && len(parts[i]) >= 2 {
			i++
		}
		if start == i {
			return false
		}
	}
	if i < len(parts) && parts[i] == "x" {
		return i+1 < len(parts)
	}
	return i == len(parts)
}

// LocaleAlias is an exact configured alias to a supported canonical locale.
// Alias keys are lowercase basic ranges, sorted bytewise, unique and acyclic.
// This explicit composition policy is distinct from upstream registered aliases.
type LocaleAlias struct {
	Alias  string
	Locale Locale
}

// MatchInput owns one immutable bounded selection: at most 32 requested basic
// ranges (each at most 64 bytes including optional HTTP q weight), 1..256 unique
// canonical supported locales, up to 256 sorted aliases, and a supported default.
// Requested order breaks equal-weight ties; Supported order breaks wildcard and
// excluded-default fallback ties. Do not mutate inputs concurrently with Match.
type MatchInput struct {
	Requested []string
	Supported []Locale
	Aliases   []LocaleAlias
	Default   Locale
}

// Format prevents preference/header inputs entering diagnostics.
func (MatchInput) Format(s fmt.State, _ rune) { _, _ = s.Write([]byte("i18n.MatchInput(redacted)")) }

// Matcher is the transport-neutral language negotiation boundary.
type Matcher interface {
	Match(MatchInput) (Locale, error)
}

// DefaultMatcher is stateless; zero is usable and concurrent calls are safe.
// Matching uses exact canonical tags with RFC 4647 progressive lookup, not
// demographic inference, approximate language similarity or remote catalogs.
type DefaultMatcher struct{}

var _ Matcher = DefaultMatcher{}

type weightedRange struct {
	tag     string
	quality uint16
}

// Match validates all inputs before selection. Positive weights are stable
// priority-ordered. Zero weights exclude basic-prefix matches; a more specific
// positive range overrides a broader exclusion. Duplicate canonical request
// ranges are rejected rather than guessing conflicting weight precedence.
// Wildcards defer to concrete ranges before the eligible default and Supported
// order fallback. Unsupported
// requests fall back without ever creating attacker-selected catalog keys.
// Regional/private/extension suffixes are progressively removed, including a
// trailing singleton together with its last subtag. All failures return zero.
func (DefaultMatcher) Match(input MatchInput) (Locale, error) {
	invalid := InvalidLocaleError{}
	if len(input.Requested) > 32 || len(input.Supported) == 0 || len(input.Supported) > 256 || len(input.Aliases) > 256 {
		return "", invalid
	}
	supported := make(map[string]Locale, len(input.Supported))
	for _, locale := range input.Supported {
		canonical, err := CanonicalLocale(string(locale))
		key := strings.ToLower(string(locale))
		if err != nil || canonical != locale || supported[key] != "" {
			return "", invalid
		}
		supported[key] = locale
	}
	if supported[strings.ToLower(string(input.Default))] != input.Default || input.Default == "" {
		return "", invalid
	}
	aliases := make(map[string]string, len(input.Aliases))
	for index, alias := range input.Aliases {
		if !basicRange(alias.Alias) || alias.Alias == "*" || strings.ToLower(alias.Alias) != alias.Alias || index > 0 && input.Aliases[index-1].Alias >= alias.Alias || supported[strings.ToLower(string(alias.Locale))] != alias.Locale || alias.Locale == "" {
			return "", invalid
		}
		aliases[alias.Alias] = strings.ToLower(string(alias.Locale))
	}
	for key := range aliases {
		seen := make(map[string]bool, len(aliases))
		for key != "" {
			if seen[key] {
				return "", invalid
			}
			seen[key] = true
			key = aliases[key]
		}
	}
	ranges := make([]weightedRange, 0, len(input.Requested))
	seen := make(map[string]bool, len(input.Requested))
	for _, requested := range input.Requested {
		r, err := parseRange(requested)
		if err != nil {
			return "", err
		}
		key := strings.ToLower(r.tag)
		if target := aliases[key]; target != "" {
			for target != "" {
				key = target
				target = aliases[key]
			}
		} else if canonical, err := CanonicalLocale(r.tag); err == nil {
			key = strings.ToLower(string(canonical))
		}
		if seen[key] {
			return "", invalid
		}
		seen[key] = true
		r.tag = key
		ranges = append(ranges, r)
	}
	slices.SortStableFunc(ranges, func(a, b weightedRange) int { return int(b.quality) - int(a.quality) })
	eligible := func(locale Locale) bool {
		key := strings.ToLower(string(locale))
		best, allowed := -1, true
		for _, r := range ranges {
			if r.tag == "*" || key == r.tag || strings.HasPrefix(key, r.tag+"-") {
				specificity := len(r.tag)
				if r.tag == "*" {
					specificity = 0
				}
				if specificity > best {
					best, allowed = specificity, r.quality != 0
				}
			}
		}
		return allowed
	}
	fallback := func() (Locale, error) {
		if eligible(input.Default) {
			return input.Default, nil
		}
		for _, locale := range input.Supported {
			if eligible(locale) {
				return locale, nil
			}
		}
		return "", NoAcceptableLocaleError{}
	}
	for _, r := range ranges {
		if r.quality == 0 {
			continue
		}
		if r.tag == "*" {
			continue
		}
		for tag := r.tag; tag != ""; tag = truncateRange(tag) {
			if locale := supported[tag]; locale != "" && eligible(locale) {
				return locale, nil
			}
		}
	}
	return fallback()
}

func truncateRange(tag string) string {
	last := strings.LastIndexByte(tag, '-')
	if last < 0 {
		return ""
	}
	tag = tag[:last]
	previous := strings.LastIndexByte(tag, '-')
	if len(tag)-previous-1 == 1 {
		if previous < 0 {
			return ""
		}
		tag = tag[:previous]
	}
	return tag
}

func basicRange(raw string) bool {
	if len(raw) == 0 || len(raw) > 64 {
		return false
	}
	if raw == "*" {
		return true
	}
	length, first := 0, true
	for i := range len(raw) {
		c := raw[i]
		if c == '-' {
			if length == 0 || length > 8 {
				return false
			}
			length, first = 0, false
			continue
		}
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || !first && c >= '0' && c <= '9') {
			return false
		}
		length++
	}
	return length > 0 && length <= 8
}

func parseRange(raw string) (weightedRange, error) {
	invalid := InvalidLocaleError{}
	if len(raw) > 64 {
		return weightedRange{}, invalid
	}
	tag, parameter, weighted := strings.Cut(raw, ";")
	tag = strings.Trim(tag, " \t")
	if !basicRange(tag) {
		return weightedRange{}, invalid
	}
	r := weightedRange{tag: tag, quality: 1000}
	if !weighted {
		return r, nil
	}
	name, value, ok := strings.Cut(strings.Trim(parameter, " \t"), "=")
	if !ok || !strings.EqualFold(name, "q") {
		return weightedRange{}, invalid
	}
	value = strings.Trim(value, " \t")
	if len(value) == 0 || len(value) > 5 || value[0] != '0' && value[0] != '1' {
		return weightedRange{}, invalid
	}
	if len(value) == 1 {
		r.quality = uint16(value[0]-'0') * 1000
		return r, nil
	}
	if value[1] != '.' {
		return weightedRange{}, invalid
	}
	quality, multiplier := uint16(value[0]-'0')*1000, uint16(100)
	for i := 2; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' || value[0] == '1' && value[i] != '0' {
			return weightedRange{}, invalid
		}
		quality += uint16(value[i]-'0') * multiplier
		multiplier /= 10
	}
	r.quality = quality
	return r, nil
}

// ParseAcceptLanguage validates up to 4096 bytes and 32 HTTP basic ranges,
// preserving order and weights while stripping permitted SP/HTAB separators.
// Empty input/elements omit the preference, with at most 31 commas tolerated.
// Malformed weights, controls and extended wildcard ranges are rejected.
// Returned strings are caller-owned;
// the function performs no header access, persistence or selection.
func ParseAcceptLanguage(raw string) ([]string, error) {
	if len(raw) > 4096 || strings.Count(raw, ",") >= 32 {
		return nil, InvalidLocaleError{}
	}
	if strings.Trim(raw, " \t") == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	var result []string
	for _, part := range parts {
		if strings.Trim(part, " \t") == "" {
			continue
		}
		r, err := parseRange(strings.Trim(part, " \t"))
		if err != nil {
			return nil, err
		}
		_, parameter, weighted := strings.Cut(part, ";")
		if weighted {
			_, value, _ := strings.Cut(strings.Trim(parameter, " \t"), "=")
			result = append(result, r.tag+";q="+strings.Trim(value, " \t"))
		} else {
			result = append(result, r.tag)
		}
	}
	return result, nil
}
