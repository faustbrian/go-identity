package oauth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// SharedOAuth2UserInfoProvider is the nonce-free OAuth2 client for a shared,
// issuer-bound callback and a configured authenticated identity resource. It
// does not implement the distinct-redirect social Provider contract. The
// caller owns native transaction reservation, encrypted PKCE/token storage,
// authorization and sessions. Close after admitted calls finish.
type SharedOAuth2UserInfoProvider struct{ provider *OAuth2UserInfoProvider }

// NewSharedOAuth2UserInfoProvider snapshots one strict same-origin HTTPS
// token/identity profile, its client secret and up to 128 exact selected
// top-level claim names. No I/O occurs. Claim names are case-sensitive with
// no nesting or normalization; duplicates and credential names are rejected.
// Empty selection retains only the subject. Use OAuth2StringSubject or
// OAuth2PositiveIntegerSubject explicitly. There are no vendor exceptions.
func NewSharedOAuth2UserInfoProvider(c OAuth2UserInfoConfig, claimNames []string) (*SharedOAuth2UserInfoProvider, error) {
	if len(claimNames) > 128 {
		return nil, failure(InvalidInput, nil)
	}
	seen := make(map[string]bool, len(claimNames))
	for _, name := range claimNames {
		if !oauth2UserInfoClaimName(name) || seen[name] {
			return nil, failure(InvalidInput, nil)
		}
		seen[name] = true
	}
	provider, err := newOAuth2UserInfoProvider(c, "", queryCallbackSharedOAuth2)
	if err != nil {
		return nil, err
	}
	provider.claimNames = slices.Clone(claimNames)
	return &SharedOAuth2UserInfoProvider{provider: provider}, nil
}

func sharedOAuth2UserInfoProfileValid(facts OAuth2UserInfoProfile) bool {
	p, d := facts.Profile, facts.Details
	return oauth2QueryProfileValid(p) && sameOAuth2Origin(p.Issuer, d.UserInfoEndpoint) &&
		len(d.SubjectClaim) <= 64 && oauth2UserInfoClaimName(d.SubjectClaim) &&
		(d.SubjectEncoding == OAuth2StringSubject || d.SubjectEncoding == OAuth2PositiveIntegerSubject) &&
		d.ProofLifetime >= time.Second && d.ProofLifetime <= 20*time.Second
}

// Profile returns detached base facts for ParseSharedOAuth2QueryCallback.
// Native composition must separately bind the configured identity resource,
// claim selection, credential generation and original transaction.
func (p *SharedOAuth2UserInfoProvider) Profile() ProviderProfile {
	if p == nil {
		return ProviderProfile{}
	}
	return p.provider.Profile()
}

// Authorization builds the fixed code/query/S256 redirect without I/O. State
// and challenge come from the original native transaction; nonce is rejected.
func (p *SharedOAuth2UserInfoProvider) Authorization(ctx context.Context, a AuthorizationParameters) (AuthorizationRequest, error) {
	if p == nil {
		return AuthorizationRequest{}, failure(InvalidInput, ctx)
	}
	return p.provider.Authorization(ctx, a)
}

// Exchange validates successful shared-redirect custody for the exact profile,
// state and S256 challenge before one token request and one authenticated
// identity request. The caller must first reserve the original transaction and
// supply its retained authorization parameters and decrypted verifier. Denied
// callbacks use native denial processing and never reach the provider here.
// No code retry, token retention or authentication timestamp is introduced.
// Destroy caller-owned inputs and result tokens after use, including denial.
func (p *SharedOAuth2UserInfoProvider) Exchange(ctx context.Context, callback QueryCallback, verifier PKCEVerifier, original AuthorizationParameters) (ExchangeResult, error) {
	if ctx == nil || p == nil || p.provider == nil {
		return ExchangeResult{}, failure(InvalidInput, ctx)
	}
	if ctx.Err() != nil {
		return ExchangeResult{}, failure(Unavailable, ctx)
	}
	profile := p.provider.profile.Profile
	if !callback.success || callback.protocol != queryCallbackSharedOAuth2 || callback.receivedRedirect != profile.RedirectURI || !reflect.DeepEqual(callback.profile, profile) {
		return ExchangeResult{}, failure(InvalidInput, ctx)
	}
	if original.Nonce != "" || !canonical32(original.State) || !canonical32(original.PKCEChallenge) || verifier.Challenge() != original.PKCEChallenge {
		return ExchangeResult{}, failure(InvalidInput, ctx)
	}
	matched := false
	err := callback.input.Use(ctx, func(_ context.Context, _, state []byte) error {
		matched = subtle.ConstantTimeCompare(state, []byte(original.State)) == 1
		return nil
	})
	if ctx.Err() != nil {
		return ExchangeResult{}, failure(Unavailable, ctx)
	}
	if err != nil || !matched {
		return ExchangeResult{}, failure(InvalidInput, ctx)
	}
	return p.provider.Exchange(ctx, callback.input, verifier, "")
}

// Close destroys the provider-owned secret copy and idle transport connections.
func (p *SharedOAuth2UserInfoProvider) Close() {
	if p != nil {
		p.provider.Close()
	}
}

// Format protects configuration and credential material from diagnostics.
func (SharedOAuth2UserInfoProvider) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.SharedOAuth2UserInfoProvider(redacted)"))
}

// MarshalJSON refuses implicit provider serialization.
func (SharedOAuth2UserInfoProvider) MarshalJSON() ([]byte, error) {
	return nil, failure(InvalidInput, nil)
}

// MarshalText refuses implicit provider serialization.
func (SharedOAuth2UserInfoProvider) MarshalText() ([]byte, error) {
	return nil, failure(InvalidInput, nil)
}

// OAuth2ClaimKind describes a selected observation from the authenticated
// identity endpoint. It does not describe authority to alter a local field.
type OAuth2ClaimKind string

const (
	// OAuth2ClaimAbsent means the selected name was not in the response.
	OAuth2ClaimAbsent OAuth2ClaimKind = "absent"
	// OAuth2ClaimNull means the selected name had an explicit null value.
	OAuth2ClaimNull OAuth2ClaimKind = "null"
	// OAuth2ClaimString includes the valid empty string.
	OAuth2ClaimString OAuth2ClaimKind = "string"
	// OAuth2ClaimBool includes the valid false value.
	OAuth2ClaimBool OAuth2ClaimKind = "bool"
)

// ObservedOAuth2Claim is detached, immutable response evidence. The zero
// value is invalid, not selected absence. SSO owns authority and mapping.
type ObservedOAuth2Claim struct {
	name string
	kind OAuth2ClaimKind
	text string
	flag bool
}

// Name returns the exact selected name, or empty for a zero value.
func (c ObservedOAuth2Claim) Name() string { return c.name }

// Kind returns the selected presence/value kind, or empty for a zero value.
func (c ObservedOAuth2Claim) Kind() OAuth2ClaimKind { return c.kind }

// StringValue returns an exact string, including empty, only for string kind.
func (c ObservedOAuth2Claim) StringValue() (string, bool) { return c.text, c.kind == OAuth2ClaimString }

// BoolValue returns an exact boolean, including false, only for boolean kind.
func (c ObservedOAuth2Claim) BoolValue() (bool, bool) { return c.flag, c.kind == OAuth2ClaimBool }

// Format redacts all selected identity values from diagnostics.
func (ObservedOAuth2Claim) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.ObservedOAuth2Claim(redacted)"))
}

// MarshalJSON refuses implicit identity evidence serialization.
func (ObservedOAuth2Claim) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses implicit identity evidence serialization.
func (ObservedOAuth2Claim) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

type oauth2ClaimProjection struct{ claims []ObservedOAuth2Claim }

// ObservedOAuth2Claims returns detached selected OAuth2 identity-resource
// observations in configuration order. Absence and null remain distinct.
// Unselected responses and OIDC results return nil. This does not confer field
// ownership, provider authentication age, or organization/session authority.
func (r ExchangeResult) ObservedOAuth2Claims() []ObservedOAuth2Claim {
	if r.Identity.oauth2Claims == nil {
		return nil
	}
	return slices.Clone(r.Identity.oauth2Claims.claims)
}

func oauth2UserInfoClaimName(name string) bool {
	if !oidcProjectionName(name) {
		return false
	}
	switch strings.ToLower(name) {
	case "access_token", "refresh_token", "id_token", "client_secret", "client_assertion", "code", "code_verifier", "state", "nonce", "authorization", "password", "token":
		return false
	}
	return true
}

// The existing bounded JSON reader has already rejected duplicate names,
// malformed strings and excessive members/depth. Project only exact selected
// values; unsupported kinds deny the whole result before token handoff.
func projectOAuth2UserInfoClaims(fields map[string]any, names []string) (*oauth2ClaimProjection, bool) {
	projection := &oauth2ClaimProjection{claims: make([]ObservedOAuth2Claim, len(names))}
	for i, name := range names {
		claim := ObservedOAuth2Claim{name: name, kind: OAuth2ClaimAbsent}
		if value, present := fields[name]; present {
			switch v := value.(type) {
			case nil:
				claim.kind = OAuth2ClaimNull
			case bool:
				claim.kind, claim.flag = OAuth2ClaimBool, v
			case string:
				if len(v) > 4096 || !utf8.ValidString(v) {
					return nil, false
				}
				claim.kind, claim.text = OAuth2ClaimString, v
			default:
				return nil, false
			}
		}
		projection.claims[i] = claim
	}
	return projection, true
}
