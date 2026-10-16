package reference

import (
	"crypto/subtle"
	"fmt"
	"time"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
)

// EmailOTPVerificationConfiguration selects native pending-email OTP separately
// from link management and HTTP. Policy is explicitly email verification.
// SessionKeys must read the graph's current password issuer and may contain only
// graph-readable retained versions. FreshnessLimit is explicit and cannot renew
// the session owner's earlier freshness/lifetime. RequestKeys uses a dedicated
// namespace with the same authoritative policy/revision as OTP. Native pools,
// risk evaluator, codec/delivery owners and migrations come from this graph.
type EmailOTPVerificationConfiguration struct {
	Policy                   otp.AttemptPolicy
	Domain                   kernel.EmailAttachmentDomainConfig
	SessionKeys              map[uint32][]byte
	FreshnessLimit           time.Duration
	CurrentAttemptKeyVersion uint32
	RequestKeys              kernel.RequestKeyConfig
	IntentKey, IdentifierKey [32]byte
	TemplateID               string
	TemplateVersion          uint32
	LocaleChain              []string
}

func composeEmailOTPVerification(c StoreConfiguration, d ReferenceDependencies, base otppg.SendConfig, crypto *envelope.Service) (*otppg.EmailVerificationService, error) {
	invalid := identity.InvalidInputError{Field: "reference_email_otp"}
	if c.Email == nil || c.Email.OTPVerification == nil || c.Session == nil || c.PasswordSignin == nil || c.OTP == nil {
		return nil, invalid
	}
	n := *c.Email.OTPVerification
	if n.RequestKeys.Namespace == c.OTP.RequestKeys.Namespace || n.RequestKeys.Policy.PolicyVersion != c.OTP.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(n.RequestKeys.Policy.Authorization, c.OTP.RequestKeys.Policy.Authorization) || !emailOTPSessionKeysMatch(c, n.SessionKeys) {
		return nil, invalid
	}
	base.Policy, base.TemplateID, base.TemplateVersion = n.Policy, n.TemplateID, n.TemplateVersion
	base.LocaleChain = append([]string(nil), n.LocaleChain...)
	base.RequestKeys, base.IntentKey, base.IdentifierKey = n.RequestKeys, n.IntentKey, n.IdentifierKey
	for _, policy := range []*kernel.CommandQueryPolicy{base.Coordinator.QueryPolicy, base.Coordinator.AdmissionPolicy} {
		if policy != nil && (policy.PolicyVersion != n.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(policy.Authorization, n.RequestKeys.Policy.Authorization)) {
			return nil, invalid
		}
	}
	policy := n.RequestKeys.Policy
	base.Coordinator.QueryPolicy, base.Coordinator.AdmissionPolicy = &policy, &policy
	base.Store.PreAuth, base.Store.PreAuthCookieKeys = sessionpg.Config{}, nil
	base.Session = &otppg.SessionAdmissionConfig{Store: c.Session.Native.Execution.Repository, Profile: c.PasswordSignin.Native.Profile, RetainedTokenKeys: n.SessionKeys, FreshnessLimit: n.FreshnessLimit}
	base.PreAuthAction = "identity.otp.email-verify"
	return otppg.NewEmailVerificationService(d.PostgreSQL, otppg.EmailVerificationConfig{Send: base, Domain: n.Domain, CurrentAttemptKeyVersion: n.CurrentAttemptKeyVersion}, crypto)
}

func emailOTPSessionKeysMatch(c StoreConfiguration, keys map[uint32][]byte) bool {
	if c.Session == nil || c.PasswordSignin == nil || len(keys) == 0 || len(keys) > 16 {
		return false
	}
	probe, err := session.ParseToken("AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE")
	if err != nil {
		return false
	}
	issuer, err := probe.Digest(c.PasswordSignin.Native.Issuance.LookupKey, "reference-email-otp-keys")
	if err != nil {
		return false
	}
	current := false
	for version, material := range keys {
		key, err := session.NewDigestKey(version, material)
		if err != nil {
			return false
		}
		actual, err := probe.Digest(key, "reference-email-otp-keys")
		if err != nil {
			return false
		}
		matched := false
		for _, retained := range c.Session.Native.Validation.LookupKeys {
			expected, err := probe.Digest(retained, "reference-email-otp-keys")
			if err == nil && actual.KeyVersion == expected.KeyVersion && subtle.ConstantTimeCompare(actual.Sum[:], expected.Sum[:]) == 1 {
				matched = true
			}
		}
		if !matched {
			return false
		}
		if actual.KeyVersion == issuer.KeyVersion && subtle.ConstantTimeCompare(actual.Sum[:], issuer.Sum[:]) == 1 {
			current = true
		}
	}
	return current
}

// Format redacts retained session and request-key configuration.
func (EmailOTPVerificationConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.EmailOTPVerificationConfiguration(redacted)"))
}

// MarshalJSON rejects configuration export.
func (EmailOTPVerificationConfiguration) MarshalJSON() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}

// MarshalText rejects configuration export.
func (EmailOTPVerificationConfiguration) MarshalText() ([]byte, error) {
	return nil, otp.ErrSensitiveSerialization
}
