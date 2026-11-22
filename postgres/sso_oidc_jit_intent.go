package postgres

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
)

// SSOOIDCJITIntent identifies the prospective identity within one enterprise
// callback. Account and authority versions must all be initial. The trusted
// native owner binds an original, normalized, provider-verified mailbox, a
// selected policy and the original assertion deadline. Structural validation
// does not establish any of that evidence or authorize creation.
type SSOOIDCJITIntent struct {
	Account                 ProviderAccountAdmission
	Email                   identity.Identifier
	ComparisonProfile       string
	JITPolicyVersion        uint64
	MembershipPolicyVersion uint64
	ValidUntil              time.Time
}

// Format redacts the provider subject, mailbox and linked identity details.
func (SSOOIDCJITIntent) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("postgres.SSOOIDCJITIntent(redacted)"))
}

// MarshalJSON prevents accidental publication of private creation intent.
func (SSOOIDCJITIntent) MarshalJSON() ([]byte, error) { return nil, invalidSSOOIDCJIT() }

const ssoOIDCJITIntentField = "sso.oidc.jit.identity-intent"

func invalidSSOOIDCJIT() error { return identity.InvalidInputError{Field: "sso_oidc_jit"} }

// SSOOIDCJITIntentField returns a detached digest-only field for the original
// callback's prepared command. All prospective identity values are covered
// without adding a plaintext email field to the callback's outcome.
func SSOOIDCJITIntentField(intent SSOOIDCJITIntent) (identity.FeatureField, error) {
	a := intent.Account
	c := a.Credential
	i := intent.Email
	if a.Account.Version != 1 || a.SocialLinkVersion != 1 || c.Credential.Version != 1 ||
		c.UserAuthorityVersion != 1 || c.IdentifierAuthorityVersion != 1 || c.CredentialAuthorityVersion != 1 ||
		!validSSOOIDCJITProviderNamespace(a.Account.Provider) {
		return identity.FeatureField{}, invalidSSOOIDCJIT()
	}
	if i.Validate(a.Account.UserID) != nil || i.Kind != identity.IdentifierEmail || !i.Verified || i.Primary || i.Version != 1 ||
		intent.JITPolicyVersion == 0 || intent.MembershipPolicyVersion == 0 || !postgresExactTime(intent.ValidUntil) {
		return identity.FeatureField{}, invalidSSOOIDCJIT()
	}
	if _, err := identity.ParseIdentifierID(intent.ComparisonProfile); err != nil {
		return identity.FeatureField{}, invalidSSOOIDCJIT()
	}
	account, err := SSOOIDCSigninAccountFields(a)
	if err != nil {
		return identity.FeatureField{}, invalidSSOOIDCJIT()
	}
	fields := map[string][]byte{
		"domain":                  cborText("golib.sso.oidc.jit.identity-intent.v1"),
		"email_id":                cborText(string(i.ID)),
		"email_canonical":         cborText(i.CanonicalValue),
		"email_display":           cborText(i.DisplayValue),
		"normalization_profile":   cborText(i.NormalizationProfile),
		"normalization_version":   cborUint(uint64(i.NormalizationVersion)),
		"comparison_profile":      cborText(intent.ComparisonProfile),
		"jit_policy_version":      cborUint(intent.JITPolicyVersion),
		"membership_policy":       cborUint(intent.MembershipPolicyVersion),
		"original_evidence_until": cborText(intent.ValidUntil.UTC().Format(time.RFC3339Nano)),
	}
	defer func() {
		for _, field := range fields {
			clear(field)
		}
	}()
	for _, field := range account {
		encoded, err := encodeFeatureValue(field.Value)
		if err != nil {
			return identity.FeatureField{}, invalidSSOOIDCJIT()
		}
		fields[field.Name] = encoded
	}
	wire := cborMap(fields)
	defer clear(wire)
	digest := sha256.Sum256(wire)
	return identity.FeatureField{Name: ssoOIDCJITIntentField, Value: identity.FeatureValue{Kind: identity.FeatureBytes, Bytes: digest[:]}}, nil
}

func validSSOOIDCJITProviderNamespace(provider string) bool {
	const prefix = "sso.oidc.v1."
	if len(provider) != len(prefix)+64 || !strings.HasPrefix(provider, prefix) {
		return false
	}
	for _, c := range provider[len(prefix):] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
