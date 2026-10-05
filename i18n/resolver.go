package i18n

import (
	"context"
	"fmt"
	"slices"
	"strings"
)

// ResolveInput contains bounded caller-owned locale sources and the original
// typed error. Session is authenticated stored preference, Cookie is already
// integrity-checked by its transport owner; the resolver does not authenticate
// either. Default must be a canonical available translation for this message.
// Preference strings are at most 64 bytes; AcceptLanguage at most 4096 bytes.
type ResolveInput struct {
	Explicit       string
	Session        string
	Cookie         string
	AcceptLanguage string
	Default        string
	Error          error
}

func (ResolveInput) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("i18n.ResolveInput(redacted)"))
}

// LocalizedError retains the original causal chain and stable machine/message
// identities. Message is an unescaped public preview; Parts preserve the typed
// value boundaries for final transport escaping. Collections are caller-owned.
// Error/Format are diagnostic-safe and do not expose preview or parameter data.
// Do not mutate a result while consumers use it concurrently.
type LocalizedError struct {
	Cause          error
	Code           string
	MessageID      MessageID
	Parameters     []Parameter
	Locale         string
	Message        string
	Parts          []RenderPart
	CatalogVersion uint64
}

func (LocalizedError) Error() string   { return "identity.i18n: localized error" }
func (e LocalizedError) Unwrap() error { return e.Cause }
func (LocalizedError) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("i18n.LocalizedError(redacted)"))
}

// ResolutionError preserves both the original error and a typed failure reason.
// Error never calls either cause's Error method. No partial localized result is
// returned on failure; errors.Is/As can still inspect the original cause.
type ResolutionError struct {
	Cause  error
	Reason error
}

func (ResolutionError) Error() string     { return "identity.i18n: resolution failed" }
func (e ResolutionError) Unwrap() []error { return []error{e.Reason, e.Cause} }
func (ResolutionError) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("i18n.ResolutionError(redacted)"))
}

// UnknownErrorIdentityError means no registered typed owner with exact safe
// parameters was available. Error-string classification is never attempted.
type UnknownErrorIdentityError struct{}

func (UnknownErrorIdentityError) Error() string { return "identity.i18n: unknown typed error" }

// MatcherFailureError classifies a matcher panic, invalid result or callback
// error without exposing untrusted callback diagnostics. Cancellation/deadline
// errors are propagated separately after the bounded callback returns.
type MatcherFailureError struct{}

func (MatcherFailureError) Error() string { return "identity.i18n: matcher failure" }

// Resolver translates typed errors without changing their machine semantics.
type Resolver interface {
	Resolve(context.Context, ResolveInput) (LocalizedError, error)
}

// ResolverConfig binds an owning registry and catalog store. Matcher defaults
// to DefaultMatcher. Custom callbacks must be bounded, concurrent-safe and must
// not retain or mutate inputs after returning; no goroutine is used to hide an
// unbounded callback. Aliases follow MatchInput's sorted bounded declaration.
type ResolverConfig struct {
	Registry *ErrorRegistry
	Catalogs *CatalogStore
	Matcher  Matcher
	Aliases  []LocaleAlias
}

// DefaultResolver owns immutable composition; registry construction is sealed
// on successful admission. Concurrent Resolve calls and catalog updates are
// safe. Zero/nil is invalid. It owns no persistence, IO or goroutines.
type DefaultResolver struct {
	registry *ErrorRegistry
	catalogs *CatalogStore
	matcher  Matcher
	aliases  []LocaleAlias
}

var _ Resolver = (*DefaultResolver)(nil)

// NewConfiguredResolver validates all registered schemas against present translations,
// requiring at least one translation per registered message, then atomically
// installs publication constraints and seals the registry. Failure does not
// seal an unsealed registry or change store constraints. Subsequent Replace
// cannot remove every admitted translation, change its schema, or remove an
// alias target. Missing translations in other locales are permitted.
func NewConfiguredResolver(config ResolverConfig) (*DefaultResolver, error) {
	if config.Registry == nil || config.Registry.state == nil || config.Catalogs == nil || len(config.Aliases) > 256 {
		return nil, RegistryConflictError{}
	}
	store, state := config.Catalogs, config.Registry.state
	// Lock order is store publication then registry construction; callbacks are
	// never invoked under either lock. Register/Seal never take the store lock.
	store.publishMu.Lock()
	defer store.publishMu.Unlock()
	state.mu.Lock()
	defer state.mu.Unlock()
	snapshot := store.snapshot.Load()
	if snapshot == nil {
		return nil, CatalogConflictError{}
	}
	aliases := slices.Clone(config.Aliases)
	if _, err := (DefaultMatcher{}).Match(MatchInput{Supported: snapshot.locales, Default: snapshot.locales[0], Aliases: aliases}); err != nil {
		return nil, err
	}
	admitted := make(map[MessageID][]ParameterSpec, len(store.admitted)+len(state.entries))
	for id, schema := range store.admitted {
		admitted[id] = schema
	}
	for _, entry := range state.entries {
		schema := orderedSchema(entry.schema)
		if previous, exists := admitted[entry.message]; exists && !slices.Equal(previous, schema) {
			return nil, RegistryConflictError{}
		}
		admitted[entry.message] = schema
	}
	required := make(map[Locale]bool, len(store.requiredLocales)+len(aliases))
	for locale := range store.requiredLocales {
		required[locale] = true
	}
	for _, alias := range aliases {
		required[alias.Locale] = true
	}
	if !validAdmission(snapshot, admitted, required) {
		return nil, CatalogConflictError{}
	}
	matcher := config.Matcher
	if matcher == nil {
		matcher = DefaultMatcher{}
	}
	store.admitted, store.requiredLocales = admitted, required
	state.sealed = true
	return &DefaultResolver{registry: &ErrorRegistry{state: state}, catalogs: store, matcher: matcher, aliases: aliases}, nil
}

func orderedSchema(schema []ParameterSpec) []ParameterSpec {
	ordered := slices.Clone(schema)
	slices.SortFunc(ordered, func(a, b ParameterSpec) int { return strings.Compare(a.Name, b.Name) })
	return ordered
}

func validAdmission(snapshot *catalogSnapshot, admitted map[MessageID][]ParameterSpec, required map[Locale]bool) bool {
	for locale := range required {
		if snapshot.messages[locale] == nil {
			return false
		}
	}
	found := make(map[MessageID]bool, len(admitted))
	for _, messages := range snapshot.messages {
		for id, message := range messages {
			if schema, exists := admitted[id]; exists {
				if !slices.Equal(schema, orderedSchema(message.schema)) {
					return false
				}
				found[id] = true
			}
		}
	}
	return len(found) == len(admitted)
}

// Resolve validates all source syntax/bounds, captures one snapshot, then
// chooses explicit > stored > trusted cookie > header > configured default.
// Unsupported preferences fall through; region lookup and aliases are allowed.
// Header exclusions cannot override a higher-priority supported preference.
// A message's available translations form its supported set. Custom matchers
// receive copied inputs; a preference call includes progressive positive parents
// and *;q=0 to suppress fallback, and
// NoAcceptableLocaleError means try the next source. All other callback errors,
// panics or unavailable results fail closed without exposing their diagnostics.
func (r *DefaultResolver) Resolve(ctx context.Context, input ResolveInput) (LocalizedError, error) {
	fail := func(reason error) (LocalizedError, error) {
		return LocalizedError{}, ResolutionError{Cause: input.Error, Reason: reason}
	}
	if ctx == nil || r == nil || r.registry == nil || r.catalogs == nil || input.Error == nil {
		return fail(RegistryConflictError{})
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	preferences := make([]string, 0, 3)
	for _, raw := range []string{input.Explicit, input.Session, input.Cookie} {
		if raw == "" {
			continue
		}
		// Configured exact aliases precede upstream canonical aliases, as
		// they do in DefaultMatcher. Keep the validated raw tag for lookup.
		aliased := false
		if basicRange(raw) && raw != "*" {
			for _, alias := range r.aliases {
				if alias.Alias == strings.ToLower(raw) {
					aliased = true
					break
				}
			}
		}
		if !aliased {
			if _, err := CanonicalLocale(raw); err != nil {
				return fail(err)
			}
		}
		preferences = append(preferences, raw)
	}
	fallback, err := CanonicalLocale(input.Default)
	if err != nil || string(fallback) != input.Default {
		return fail(InvalidLocaleError{})
	}
	header, err := ParseAcceptLanguage(input.AcceptLanguage)
	if err != nil {
		return fail(err)
	}
	// Validate header semantics even when a preference wins, without allowing
	// a lower source's valid exclusions to change that preference's selection.
	snapshot := r.catalogs.snapshot.Load()
	if snapshot == nil {
		return fail(CatalogConflictError{})
	}
	if _, err := (DefaultMatcher{}).Match(MatchInput{Requested: header, Supported: snapshot.locales, Default: fallback, Aliases: r.aliases}); err != nil {
		if _, none := err.(NoAcceptableLocaleError); !none {
			return fail(err)
		}
	}
	code, id, safe, ok := r.registry.resolveRegistered(input.Error)
	if !ok {
		return fail(UnknownErrorIdentityError{})
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	supported := make([]Locale, 0, len(snapshot.locales))
	for _, locale := range snapshot.locales {
		if _, exists := snapshot.messages[locale][id]; exists {
			supported = append(supported, locale)
		}
	}
	if _, exists := snapshot.messages[fallback][id]; !exists {
		return fail(MissingMessageError{})
	}
	match := func(requested []string) (Locale, error) {
		// Requests are fully alias-resolved before progressive lookup. Do not
		// reapply an exact alias to a parent generated by that lookup.
		return boundedMatch(ctx, r.matcher, MatchInput{Requested: requested, Supported: supported, Default: fallback})
	}
	var selected Locale
	for _, preference := range preferences {
		selected, err = match(preferenceRequests(preference, r.aliases))
		if err == nil {
			break
		}
		if _, none := err.(NoAcceptableLocaleError); !none {
			return fail(err)
		}
	}
	if selected == "" {
		normalized := make([]string, len(header))
		for i, request := range header {
			tag, weight, weighted := strings.Cut(request, ";")
			normalized[i] = canonicalRequestTag(tag, r.aliases)
			if weighted {
				normalized[i] += ";" + weight
			}
		}
		selected, err = match(normalized)
		if err != nil {
			return fail(err)
		}
	}
	parameters := make([]Parameter, len(safe))
	for i, value := range safe {
		parameters[i] = Parameter(value)
	}
	rendered, err := renderSnapshot(ctx, snapshot, selected, id, parameters)
	if err != nil {
		return fail(err)
	}
	return LocalizedError{Cause: input.Error, Code: string(code), MessageID: id, Parameters: rendered.Parameters, Locale: string(selected), Message: rendered.Message, Parts: rendered.Parts, CatalogVersion: rendered.Version}, nil
}

// Explicitly allow canonical progressive parents alongside the no-fallback
// wildcard. Grandfathered tags must canonicalize as a whole before truncation:
// no-bok becomes nb, not a region whose parent is no.
func preferenceRequests(preference string, aliases []LocaleAlias) []string {
	var requested []string
	for tag := canonicalRequestTag(preference, aliases); tag != ""; tag = truncateRange(tag) {
		requested = append(requested, tag)
	}
	return append(requested, "*;q=0")
}

// Matcher's configured exact alias precedence applies to the original full
// range, not to synthetic parents. Header ranges may be structurally valid
// but absent from upstream registered tags; keep those bounded ranges intact.
func canonicalRequestTag(raw string, aliases []LocaleAlias) string {
	key := strings.ToLower(raw)
	for depth := 0; depth < len(aliases); depth++ {
		found := false
		for _, alias := range aliases {
			if alias.Alias == key {
				key, found = strings.ToLower(string(alias.Locale)), true
				break
			}
		}
		if !found {
			break
		}
	}
	if canonical, err := CanonicalLocale(key); err == nil {
		key = strings.ToLower(string(canonical))
	}
	return key
}

func boundedMatch(ctx context.Context, matcher Matcher, input MatchInput) (locale Locale, err error) {
	defer func() {
		if recover() != nil {
			locale, err = "", MatcherFailureError{}
		}
	}()
	if err := ctx.Err(); err != nil {
		return "", err
	}
	supported := slices.Clone(input.Supported)
	input.Supported = slices.Clone(input.Supported)
	input.Requested = slices.Clone(input.Requested)
	input.Aliases = slices.Clone(input.Aliases)
	locale, err = matcher.Match(input)
	if canceled := ctx.Err(); canceled != nil {
		return "", canceled
	}
	if err != nil {
		if _, none := err.(NoAcceptableLocaleError); none {
			return "", err
		}
		return "", MatcherFailureError{}
	}
	if !slices.Contains(supported, locale) {
		return "", MatcherFailureError{}
	}
	return locale, nil
}
