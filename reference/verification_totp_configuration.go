package reference

import (
	"fmt"
	"log/slog"
	"strings"

	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// VerificationTOTPConfiguration selects original-browser TOTP completion after
// separately committed registration verification and challenge issuance. Fields
// retain the bounded counters, envelope and comparison-key contracts of native
// TOTP completion. The graph supplies the actual verification primary, risk,
// original signup cookie keys and session authority. No HTTP route, password/
// magic-link primary, recovery method or trusted-device policy is selected.
type VerificationTOTPConfiguration MagicLinkTOTPConfiguration

// Format redacts secret-bearing startup configuration.
func (VerificationTOTPConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.VerificationTOTPConfiguration(redacted)"))
}

// MarshalJSON rejects implicit startup custody export.
func (VerificationTOTPConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// MarshalText rejects implicit textual custody export.
func (VerificationTOTPConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// LogValue redacts structured diagnostics.
func (VerificationTOTPConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.VerificationTOTPConfiguration(redacted)")
}

func composeVerificationTOTP(c StoreConfiguration, d ReferenceDependencies, primary *passwordpg.VerificationSigninService, evaluator risk.Evaluator) (*magicLinkTOTPService, error) {
	if c.PasswordSignup == nil || c.PasswordSignup.VerificationTOTP == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_verification_totp"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || primary == nil || c.PasswordSignup.VerificationSignin == nil || c.PasswordSignup.VerificationSignin.TOTP == nil || c.OTP == nil {
		return nil, invalid
	}
	n, signup, selected := *c.PasswordSignup.VerificationTOTP, c.PasswordSignup.Native, *c.PasswordSignup.VerificationSignin
	if n.MaximumDuration <= 0 || n.MaximumDuration > c.OTP.Timeout || n.Counters.Schema != c.Velocity.Schema || n.Counters.CommandCounters == nil || n.Counters.CommandCounters.Policy != c.Velocity.Native.Policy {
		return nil, invalid
	}
	admitted, err := n.Counters.CommandCounters.Policy.Admit("identity.mfa.totp-verify")
	if err != nil || admitted.PolicyVersion != n.Counters.PolicyVersion {
		return nil, invalid
	}
	flowKeys := make(map[uint32]session.DigestKey, len(signup.FlowKeys))
	probe, err := session.ParseToken(strings.Repeat("A", 43))
	if err != nil {
		return nil, invalid
	}
	for _, key := range signup.FlowKeys {
		digest, err := probe.Digest(key, "mfa-configuration")
		if err != nil || digest.KeyVersion == 0 {
			return nil, invalid
		}
		if _, exists := flowKeys[digest.KeyVersion]; exists {
			return nil, invalid
		}
		flowKeys[digest.KeyVersion] = key
	}
	config := MagicLinkTOTPCompletionConfig{MaximumDuration: n.MaximumDuration, ConfigurationID: n.ConfigurationID, PolicyID: n.PolicyID, Coordinator: signup.Coordinator, Issuer: selected.TOTP.Issuer, Session: signup.Session, Profile: selected.Profile, SessionIssuer: selected.Issuance, CSRF: selected.CSRFKey, CookieKeys: flowKeys, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: n.ConfigurationID, Keys: n.RiskKeys}, Counters: n.Counters, ComparisonKey: n.ComparisonKey, ComparisonKeyVersion: n.ComparisonKeyVersion, ActiveEnvelopeKeyID: n.ActiveEnvelopeKeyID}
	return newNativeMFAService(d.PostgreSQL, nil, nil, primary, config, sessionpg.IdentifierAdmissionConfig{}, keys, nil)
}
