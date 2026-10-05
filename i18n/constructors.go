package i18n

import (
	"context"
	"slices"
	"time"
)

// NewCatalog validates a canonicalized locale and freezes copies of messages
// and placeholder declarations in a version-1 construction value. Version 1 is
// the explicit initial catalog profile; publication successors advance Version.
// The returned value remains caller-owned; concurrent mutation during calls is
// forbidden. It has the same template/schema/resource limits as NewCatalogStore.
func NewCatalog(locale string, messages []Message) (Catalog, error) {
	canonical, err := CanonicalLocale(locale)
	if err != nil {
		return Catalog{}, err
	}
	if len(messages) == 0 || len(messages) > 10000 {
		return Catalog{}, CatalogConflictError{}
	}
	catalog := Catalog{Locale: string(canonical), Version: 1, Messages: messages}
	// Bound templates and schemas before copying caller-controlled collections.
	if _, err := compileCatalogs([]Catalog{catalog}); err != nil {
		return Catalog{}, err
	}
	catalog.Messages = slices.Clone(messages)
	for i := range catalog.Messages {
		catalog.Messages[i].Placeholders = slices.Clone(catalog.Messages[i].Placeholders)
	}
	return catalog, nil
}

// I18nResolveRequest carries exactly the typed direct localization input; no
// error text is used to identify the original cause.
type I18nResolveRequest struct{ Input ResolveInput }

// I18nResolveResult owns the localized projection; no partial result on failure.
type I18nResolveResult struct{ Localized LocalizedError }

// LocalizationService exposes the typed transport-neutral localization operation.
type LocalizationService interface {
	I18nResolve(context.Context, I18nResolveRequest) (I18nResolveResult, error)
}

// I18nResolve delegates the real resolver operation without persistence or
// transport escaping. It preserves the classified error and original chain.
func (r *DefaultResolver) I18nResolve(ctx context.Context, request I18nResolveRequest) (I18nResolveResult, error) {
	localized, err := r.Resolve(ctx, request.Input)
	if err != nil {
		return I18nResolveResult{}, err
	}
	return I18nResolveResult{Localized: localized}, nil
}

// PreferenceResolver is the canonical composition's resolver and validated
// preference-store facade. Its methods are low-level authorized-scope inputs,
// not public unauthenticated handlers. Durable authority remains store-owned.
type PreferenceResolver interface {
	Resolver
	PreferenceStore
	LocalizationService
}

type preferenceResolver struct {
	*DefaultResolver
	*PreferencePolicy
}

var _ PreferenceResolver = (*preferenceResolver)(nil)

// NewResolver is the specified catalog/fallback/registry/preference composition.
// It validates 1..16 unique canonical supported fallback tags and all schema
// admission before sealing. Each registered message requires a configured
// fallback translation. Default inputs must be in that chain; if its message is
// absent, the first available configured fallback is used. Header exclusions
// remain effective. Preferences use an immutable accepted-locale policy and a
// documented five-second callback timeout, never implicit fallback persistence.
// The returned value also implements PreferenceResolver for explicit Get/Set;
// session/HTTP owners retrieve authenticated preferences and pass Session input.
// Construction owns no IO or lifecycle acknowledgement; nil stores fail.
func NewResolver(catalogs []Catalog, fallbacks []string, registry *ErrorRegistry, preferences PreferenceStore) (Resolver, error) {
	if nilPreferenceStore(preferences) || len(fallbacks) == 0 || len(fallbacks) > 16 {
		return nil, PreferenceInputError{}
	}
	chain := make([]Locale, len(fallbacks))
	for i, raw := range fallbacks {
		locale, err := CanonicalLocale(raw)
		if err != nil || string(locale) != raw {
			return nil, InvalidLocaleError{}
		}
		chain[i] = locale
	}
	store, err := NewCatalogStore(catalogs)
	if err != nil {
		return nil, err
	}
	supported, _ := store.Locales()
	policy, err := NewPreferencePolicy(PreferencePolicyConfig{Store: preferences, Supported: supported, Timeout: 5 * time.Second})
	if err != nil {
		return nil, err
	}
	core, err := NewConfiguredResolver(ResolverConfig{Registry: registry, Catalogs: store, Fallbacks: chain})
	if err != nil {
		return nil, err
	}
	return &preferenceResolver{DefaultResolver: core, PreferencePolicy: policy}, nil
}
