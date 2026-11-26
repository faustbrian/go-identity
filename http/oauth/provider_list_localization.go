package oauthhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/i18n"
)

// Provider-list message IDs belong to this transport's safe public denial
// projection. Catalogs must declare all four without interpolation parameters.
const (
	ProviderListInvalidRequestMessage i18n.MessageID = "identity.oauth.provider-list.invalid_request"
	ProviderListDeniedMessage         i18n.MessageID = "identity.oauth.provider-list.denied"
	ProviderListRateLimitedMessage    i18n.MessageID = "identity.oauth.provider-list.rate_limited"
	ProviderListUnavailableMessage    i18n.MessageID = "identity.oauth.provider-list.unavailable"
)

// ProviderListLocalizationConfig opts into localized invalid_request, denied,
// rate_limited and unavailable responses only. Catalogs are copied at handler
// construction; every message requires a parameter-free DefaultLocale
// translation. Other locales may omit messages and use that fallback. Templates
// are trusted public text, never diagnostics. Only bounded Accept-Language and
// DefaultLocale participate; cookies and sessions are never locale authority.
type ProviderListLocalizationConfig struct {
	Catalogs      []i18n.Catalog
	DefaultLocale string
}

// Format redacts caller-owned catalog contents.
func (ProviderListLocalizationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauthhttp.ProviderListLocalizationConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime catalog export.
func (ProviderListLocalizationConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText refuses implicit runtime catalog export.
func (ProviderListLocalizationConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

type providerListLocalization struct {
	resolver      *i18n.DefaultResolver
	defaultLocale string
}

func newProviderListLocalization(config *ProviderListLocalizationConfig) (*providerListLocalization, error) {
	if config == nil {
		return nil, nil
	}
	locale, err := i18n.CanonicalLocale(config.DefaultLocale)
	if err != nil || string(locale) != config.DefaultLocale {
		return nil, identityhttp.ErrInvalidInput
	}
	registry := i18n.NewErrorRegistry()
	for _, code := range []string{"invalid_request", "denied", "rate_limited", "unavailable"} {
		failure := providerListRejection{code: code}
		if err := registry.Register(failure.ErrorIdentity(), i18n.MessageID(failure.ErrorIdentity()), i18n.ParameterSchema{}); err != nil {
			return nil, identityhttp.ErrInvalidInput
		}
	}
	catalogs, err := i18n.NewCatalogStore(config.Catalogs)
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	resolver, err := i18n.NewConfiguredResolver(i18n.ResolverConfig{Registry: registry, Catalogs: catalogs, Fallbacks: []i18n.Locale{locale}})
	if err != nil {
		return nil, identityhttp.ErrInvalidInput
	}
	return &providerListLocalization{resolver: resolver, defaultLocale: string(locale)}, nil
}

func (e providerListRejection) ErrorIdentity() i18n.ErrorIdentity {
	return i18n.ErrorIdentity("identity.oauth.provider-list." + e.code)
}

func (providerListRejection) SafeParameters() []i18n.SafeParameter { return nil }

func providerListLocalizedStatus(status int) bool {
	return status == 400 || status == 403 || status == 429 || status == 503
}

// response retains the legacy envelope on every translation failure. Only the
// typed public projection is passed to i18n; raw causes never become parameters.
func (l *providerListLocalization) response(r *http.Request, failure providerListRejection) (body []byte, locale string) {
	out := struct {
		Error   string `json:"error"`
		Message string `json:"message,omitempty"`
	}{Error: failure.code}
	if l != nil && providerListLocalizedStatus(failure.status) && r != nil {
		language := ""
		if values := r.Header.Values("Accept-Language"); len(values) == 1 && len(values[0]) <= 4096 {
			language = values[0]
		}
		input := i18n.ResolveInput{Error: failure, Default: l.defaultLocale, AcceptLanguage: language}
		localized, err := l.resolver.Resolve(r.Context(), input)
		var malformed i18n.InvalidLocaleError
		if errors.As(err, &malformed) {
			// A malformed/ambiguous public preference cannot become locale
			// authority. Reuse the same resolver with only the configured default.
			input.AcceptLanguage = ""
			localized, err = l.resolver.Resolve(r.Context(), input)
		}
		if err == nil {
			out.Message, locale = localized.Message, localized.Locale
		}
	}
	body, _ = json.Marshal(out)
	// JSON escaping may expand an admitted 8192-byte catalog beyond this
	// operation's existing serialized-response bound; never publish a partial
	// translation or language metadata for the machine-only fallback.
	if len(body)+1 > maximumProviderListResponse {
		out.Message, locale = "", ""
		body, _ = json.Marshal(out)
	}
	return append(body, '\n'), locale
}
