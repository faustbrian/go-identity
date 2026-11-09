package oauth

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strings"
	"time"

	auth "github.com/faustbrian/go-authentication/v2"
	"github.com/faustbrian/go-authorization/v3"
	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/session"
)

// ProviderID selects one configured provider without aliases or inferred hosts.
type ProviderID string

// ValidatedCallbackURL preserves one exact allowlisted HTTPS application URL.
// It is redirect configuration, never state, browser or identity authority.
// Zero is invalid; copies are immutable and URL returns an independent value.
type ValidatedCallbackURL struct{ raw string }

// NewValidatedCallbackURL validates the complete allowlist and exact raw match.
// It never normalizes, resolves relative URLs, follows redirects or trusts an
// inbound Host. Query strings are allowed; userinfo, fragments and wildcards
// are forbidden. At most64 URLs, each at most8192 bytes, are examined before use.
func NewValidatedCallbackURL(raw string, allowlist []string) (ValidatedCallbackURL, error) {
	if len(allowlist) == 0 || len(allowlist) > 64 || !applicationCallbackURL(raw) {
		return ValidatedCallbackURL{}, failure(InvalidInput, nil)
	}
	matched := false
	for index, allowed := range allowlist {
		if !applicationCallbackURL(allowed) {
			return ValidatedCallbackURL{}, failure(InvalidInput, nil)
		}
		for _, prior := range allowlist[:index] {
			if prior == allowed {
				return ValidatedCallbackURL{}, failure(InvalidInput, nil)
			}
		}
		matched = matched || raw == allowed
	}
	if !matched {
		return ValidatedCallbackURL{}, failure(InvalidInput, nil)
	}
	return ValidatedCallbackURL{strings.Clone(raw)}, nil
}

func applicationCallbackURL(raw string) bool {
	if !visible(raw, 1, 8192) || strings.ContainsAny(raw, "\\#*") {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.Fragment == "" && u.String() == raw
}

// URL returns an owned projection, or an empty URL for invalid zero values.
func (u ValidatedCallbackURL) URL() url.URL {
	value, err := url.Parse(u.raw)
	if err != nil {
		return url.URL{}
	}
	return *value
}

// ScopeSet retains exact requested scope order and explicit empty selection.
// Zero means omitted/invalid, not the provider's default. Returned values never
// alias the input. Constructed values support concurrent immutable reads.
type ScopeSet struct{ values []string }

// NewScopeSet accepts 0..64 distinct RFC6749 scope tokens, each1..128 bytes.
// It makes no grant, consent or provider-support decision. A selected service
// must compare this exact selection to its current provider and policy profile.
func NewScopeSet(values []string) (ScopeSet, error) {
	if len(values) > 64 {
		return ScopeSet{}, failure(InvalidInput, nil)
	}
	for index, value := range values {
		if !visible(value, 1, 128) || strings.ContainsAny(value, " \"\\") || slices.Contains(values[:index], value) {
			return ScopeSet{}, failure(InvalidInput, nil)
		}
	}
	copy := make([]string, len(values))
	for index, value := range values {
		copy[index] = strings.Clone(value)
	}
	return ScopeSet{copy}, nil
}

// Valid distinguishes an explicit empty selection from a zero value.
func (s ScopeSet) Valid() bool { return s.values != nil }

// Values returns a fresh copy, nonnil for explicit empty and nil for zero.
func (s ScopeSet) Values() []string { return slices.Clone(s.values) }

// LinkStartRequest binds original explicit-self intent and borrowed browser
// credentials. Caller, TenantID, Origin and Network come from trusted transport
// composition, not authentication authority. The native owner authenticates the
// session, freshness, CSRF, current policy and every authority again in Work.
// SignupDisabled is required by the initial explicit-link-only profile. A URL
// validated against another allowlist still needs the service's own exact check.
type LinkStartRequest struct {
	TenantID                identity.TenantID
	Provider                ProviderID
	Callback, ErrorCallback ValidatedCallbackURL
	Scopes                  ScopeSet
	SignupDisabled          bool
	IdempotencyKey          identity.IdempotencyKey
	Session                 auth.BearerCredential
	CSRFToken               session.CSRFToken
	Caller                  authorization.DecisionContext
	Origin, Network         string
}

// Validate checks original bounded shape only; it grants no possession,
// freshness, authorization, allowance, state issuance or durable outcome.
func (r LinkStartRequest) Validate() error {
	if !identifier(string(r.Provider)) || r.Callback.raw == "" || r.ErrorCallback.raw == "" || !r.Scopes.Valid() || !r.SignupDisabled || r.IdempotencyKey == (identity.IdempotencyKey{}) || r.CSRFToken == (session.CSRFToken{}) {
		return failure(InvalidInput, nil)
	}
	return validateLinkCaller(r.TenantID, r.Session, r.Caller, r.Origin, r.Network, "identity.account.link-start")
}

func validateLinkCaller(tenant identity.TenantID, bearer auth.BearerCredential, c authorization.DecisionContext, originText, network string, operation authorization.Action) error {
	if err := validateLinkBrowser(tenant, bearer, originText, network); err != nil {
		return err
	}
	if c.Validate() != nil || c.Request.Tenant != authorization.TenantID(tenant) || c.Request.Subject.Kind != authorization.SubjectUser || c.Request.Action != operation || c.Request.Resource.Type != "identity.user" || string(c.Request.Resource.ID) != string(c.Request.Subject.ID) {
		return failure(InvalidInput, nil)
	}
	return nil
}

func validateLinkBrowser(tenant identity.TenantID, bearer auth.BearerCredential, originText, network string) error {
	_, tenantErr := identity.ParseIdentifierID(string(tenant))
	_, tokenErr := session.ParseToken(bearer.Token())
	ip, ipErr := netip.ParseAddr(network)
	if tenantErr != nil || tokenErr != nil || !httpsURL(originText) || len(network) > 45 || ipErr != nil || ip.Zone() != "" || ip.String() != network || ip.IsUnspecified() || ip.IsMulticast() {
		return failure(InvalidInput, nil)
	}
	origin, err := url.Parse(originText)
	if err != nil || origin.Path != "" {
		return failure(InvalidInput, nil)
	}
	return nil
}

// LinkStartResult carries one durably issued RP transaction, not an account
// link or session. RedirectURI deliberately transfers original state/nonce to
// the browser and must never be logged. Expiry is the original UTC deadline.
type LinkStartResult struct {
	RedirectURI   url.URL
	TransactionID string
	ExpiresAt     time.Time
}

// LinkStarter supplies native-backed explicit account-link initiation.
// Calls are bounded/cancellation-aware. Keyed retries preserve original intent;
// no application-written stores, handlers or secret-generation callbacks belong
// behind this contract in supported composition.
type LinkStarter interface {
	LinkStart(context.Context, LinkStartRequest) (LinkStartResult, error)
}

func (ValidatedCallbackURL) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.ValidatedCallbackURL(redacted)"))
}
func (ValidatedCallbackURL) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }
func (ValidatedCallbackURL) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
func (ScopeSet) Format(s fmt.State, _ rune)               { _, _ = s.Write([]byte("oauth.ScopeSet(redacted)")) }
func (ScopeSet) MarshalJSON() ([]byte, error)             { return nil, failure(InvalidInput, nil) }
func (ScopeSet) MarshalText() ([]byte, error)             { return nil, failure(InvalidInput, nil) }
func (LinkStartRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.LinkStartRequest(redacted)"))
}
func (LinkStartRequest) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }
func (LinkStartRequest) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
func (LinkStartResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.LinkStartResult(redacted)"))
}
func (LinkStartResult) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }
func (LinkStartResult) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }
