package passwordhttp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	identityhttp "github.com/faustbrian/go-identity/http"
	"github.com/faustbrian/go-identity/i18n"
)

// SigninLocalizationConfig selects localized public email password-signin
// errors. The catalog owner supplies parameter-free text for all existing
// error codes under identity.password.signin.<code> in DefaultLocale. Other
// locales may omit a message and fall back. Only a bounded Accept-Language
// header participates; no cookie or unauthenticated account selects a locale.
type SigninLocalizationConfig struct {
	Catalogs      []i18n.Catalog
	DefaultLocale string
}

// Format prevents logging caller-owned catalogs.
func (SigninLocalizationConfig) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("passwordhttp.SigninLocalizationConfig(redacted)"))
}

// MarshalJSON refuses implicit runtime catalog export.
func (SigninLocalizationConfig) MarshalJSON() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

// MarshalText refuses implicit runtime catalog export.
func (SigninLocalizationConfig) MarshalText() ([]byte, error) {
	return nil, identityhttp.ErrInvalidInput
}

const (
	signinMaximumResponseBytes = 16384
	signinMaximumLanguageBytes = 4096
)

var signinPublicErrorCodes = []string{"invalid_request", "origin_denied", "https_required", "not_found", "method_not_allowed", "misdirected_request",
	"rate_limited", "rate_limiter_unavailable", "denied", "unavailable", "conflict", "in_progress"}

// signinPublicError carries only the final public classification. Internal
// errors, request identifiers and native denial details never enter i18n.
type signinPublicError string

func (e signinPublicError) Error() string { return string(e) }

func (e signinPublicError) ErrorIdentity() i18n.ErrorIdentity {
	return i18n.ErrorIdentity("identity.password.signin." + string(e))
}

func (signinPublicError) SafeParameters() []i18n.SafeParameter { return nil }

type signinLocalization struct {
	resolver      *i18n.DefaultResolver
	defaultLocale string
}

func newSigninLocalization(config SigninLocalizationConfig) (*signinLocalization, error) {
	locale, err := i18n.CanonicalLocale(config.DefaultLocale)
	if err != nil || string(locale) != config.DefaultLocale {
		return nil, identityhttp.ErrInvalidInput
	}
	registry := i18n.NewErrorRegistry()
	for _, code := range signinPublicErrorCodes {
		id := signinPublicError(code).ErrorIdentity()
		if err := registry.Register(id, i18n.MessageID(id), i18n.ParameterSchema{}); err != nil {
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
	return &signinLocalization{resolver: resolver, defaultLocale: string(locale)}, nil
}

func (l *signinLocalization) writeError(w http.ResponseWriter, r *http.Request, status int, out *SigninResponse) {
	if l == nil || r == nil || out.Error == "" {
		writeSigninResponse(w, status, out)
		return
	}
	w.Header().Add("Vary", "Accept-Language")
	input := i18n.ResolveInput{Error: signinPublicError(out.Error), Default: l.defaultLocale}
	if values := r.Header.Values("Accept-Language"); len(values) == 1 && len(values[0]) <= signinMaximumLanguageBytes {
		input.AcceptLanguage = values[0]
	}
	localized, err := l.resolver.Resolve(r.Context(), input)
	var invalidLocale i18n.InvalidLocaleError
	if errors.As(err, &invalidLocale) {
		input.AcceptLanguage = ""
		localized, err = l.resolver.Resolve(r.Context(), input)
	}
	if err != nil || localized.Message == "" {
		writeSigninResponse(w, status, out)
		return
	}
	data, err := json.Marshal(struct {
		SigninResponse
		Message string `json:"message"`
	}{SigninResponse: *out, Message: localized.Message})
	if err != nil || len(data)+1 > signinMaximumResponseBytes {
		writeSigninResponse(w, status, out)
		return
	}
	w.Header().Set("Content-Language", localized.Locale)
	w.WriteHeader(status)
	_, _ = w.Write(append(data, '\n'))
}
