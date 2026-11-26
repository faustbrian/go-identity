package oauth

import (
	"context"
	"fmt"
	"strings"
)

// GoogleHostedDomain is an immutable exact-domain restriction from trusted
// startup configuration, not an observed claim or organization authority.
// Construct it with NewGoogleHostedDomain and bind it to the original initiating
// configuration; never choose it from callback data. Zero is invalid.
type GoogleHostedDomain struct{ domain string }

// NewGoogleHostedDomain selects one already-canonical lowercase ASCII domain:
// at least two LDH labels, 1..63 bytes each, at most 253 bytes total, with an
// ASCII letter in the final label. No trimming, case folding, root-dot removal,
// wildcard/suffix matching, DNS lookup or Unicode/IDNA conversion occurs. An
// ASCII A-label is accepted as supplied without an IDNA conformance claim.
// Invalid configuration returns InvalidInput without retaining the supplied text.
func NewGoogleHostedDomain(domain string) (GoogleHostedDomain, error) {
	if !validGoogleHostedDomain(domain) {
		return GoogleHostedDomain{}, failure(InvalidInput, nil)
	}
	return GoogleHostedDomain{domain: domain}, nil
}

// Format redacts the configured hosted domain in every diagnostic format.
func (GoogleHostedDomain) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("oauth.GoogleHostedDomain(redacted)"))
}

// MarshalJSON refuses accidental hosted-domain configuration disclosure.
func (GoogleHostedDomain) MarshalJSON() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// MarshalText refuses accidental hosted-domain configuration disclosure.
func (GoogleHostedDomain) MarshalText() ([]byte, error) { return nil, failure(InvalidInput, nil) }

// VerifyGoogleCredentialForHostedDomain applies a mandatory exact-domain
// restriction after the same single strict Google verification as
// VerifyGoogleCredential. The only accepted hosted-domain evidence is a signed
// string hd equal to the selected domain; email and browser hints are not used.
// A zero domain returns InvalidInput before credential work. Missing, null,
// wrong-kind, duplicate, malformed or mismatching hd returns InvalidProof with
// no provider evidence. Other input, cancellation, lifecycle, borrowed-secret
// ownership and timeout semantics are VerifyGoogleCredential's.
//
// The returned opaque identity carries no hd/email observation or additional
// authority. This call neither consumes a transaction nor establishes local
// account/link/session, organization membership or email-verification policy.
// The unconstrained direct verifier and code exchange remain unchanged.
func (p *OIDCProvider) VerifyGoogleCredentialForHostedDomain(ctx context.Context, credential GoogleCredential, nonce GoogleCredentialNonce, domain GoogleHostedDomain) (ProviderIdentity, error) {
	if domain.domain == "" {
		return ProviderIdentity{}, failure(InvalidInput, ctx)
	}
	return p.verifyGoogleCredential(ctx, credential, nonce, &domain)
}

func validGoogleHostedDomain(domain string) bool {
	if len(domain) < 3 || len(domain) > 253 {
		return false
	}
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}
	finalAlpha := false
	for index, label := range labels {
		if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, b := range []byte(label) {
			if b >= 'a' && b <= 'z' {
				if index == len(labels)-1 {
					finalAlpha = true
				}
			} else if !(b >= '0' && b <= '9' || b == '-') {
				return false
			}
		}
	}
	return finalAlpha
}

// Google's server verification guidance requires the signed hd claim, not an
// email suffix or the untrusted request hint:
// https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
// This exact token already passed the pinned strict validator's duplicate-name,
// Unicode and bounded JSON checks. Reuse the existing scalar projection rather
// than introducing another claim parser or validating the signature twice.
func (domain GoogleHostedDomain) matchesValidatedToken(token []byte) bool {
	projection, ok := projectValidatedOIDCClaims(token, []string{"hd"})
	if !ok {
		return false
	}
	claim := projection.claims[0]
	return claim.kind == OIDCClaimString && claim.text == domain.domain
}
