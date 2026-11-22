package oauth

import (
	"slices"
	"time"
)

// OAuth2TokenPolicy selects a closed token/resource protocol, not a general
// endpoint allowlist. The zero value preserves the original strict same-origin,
// space-scoped, positive-expiry OAuth2 UserInfo contract.
type OAuth2TokenPolicy string

// OAuth2GitHubOAuthAppPolicy selects ordinary GitHub OAuth-app responses: the
// fixed api.github.com user resource, comma-separated granted scopes, and an
// honestly absent access-token expiry when expires_in is not returned. It does
// not select refresh, email-based linking or a provider authentication age.
const OAuth2GitHubOAuthAppPolicy OAuth2TokenPolicy = "github-oauth-app-v1"

// OAuth2TokenPolicyFacts is an optional immutable provider capability. Native
// owners must authenticate this selection together with the full UserInfo and
// base profile before releasing state/code custody. Absence means strict zero.
type OAuth2TokenPolicyFacts interface{ OAuth2TokenPolicy() OAuth2TokenPolicy }

// ProviderOAuth2TokenPolicy snapshots the optional closed protocol selection.
// It grants no provider authority and does not validate a provider's other facts.
func ProviderOAuth2TokenPolicy(p Provider) OAuth2TokenPolicy {
	if facts, ok := p.(OAuth2TokenPolicyFacts); ok {
		return facts.OAuth2TokenPolicy()
	}
	return ""
}

// ValidateForTokenPolicy checks the complete selected startup profile. The
// original Validate method remains strict and does not infer vendor exceptions.
func (p OAuth2UserInfoProfile) ValidateForTokenPolicy(policy OAuth2TokenPolicy) error {
	if policy == "" {
		return p.Validate()
	}
	b, d := p.Profile, p.Details
	if policy != OAuth2GitHubOAuthAppPolicy || !oauth2QueryProfileValid(b) || b.ID != "github" || b.Issuer != "https://github.com" || b.AuthorizationEndpoint != "https://github.com/login/oauth/authorize" || b.TokenEndpoint != "https://github.com/login/oauth/access_token" || d.UserInfoEndpoint != "https://api.github.com/user" || d.SubjectClaim != "id" || d.SubjectEncoding != OAuth2PositiveIntegerSubject || d.ProofLifetime < time.Second || d.ProofLifetime > 20*time.Second || len(b.Scopes) != 2 || !slices.Contains(b.Scopes, "read:user") || !slices.Contains(b.Scopes, "user:email") {
		return failure(InvalidInput, nil)
	}
	return nil
}
