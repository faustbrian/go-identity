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
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// PasswordTOTPConfiguration selects password-first native TOTP completion.
// Fields retain MagicLinkTOTPConfiguration's bounded counter, encryption and
// comparison-key semantics, but do not select or depend on magic-link login.
// The graph injects the actual password primary, browser, policy and issuer.
// Neither construction nor selecting this configuration enables HTTP or IO.
type PasswordTOTPConfiguration MagicLinkTOTPConfiguration

func (PasswordTOTPConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasswordTOTPConfiguration(redacted)"))
}

// MarshalJSON denies implicit secret-bearing configuration export.
func (PasswordTOTPConfiguration) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit text/map-key export.
func (PasswordTOTPConfiguration) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue redacts configuration in structured logs.
func (PasswordTOTPConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.PasswordTOTPConfiguration(redacted)")
}

func composePasswordTOTP(c StoreConfiguration, d ReferenceDependencies, primary *passwordpg.SigninService, evaluator risk.Evaluator) (*magicLinkTOTPService, error) {
	if c.PasswordSignin == nil || c.PasswordSignin.TOTP == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_password_totp"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || primary == nil || c.PasswordSignin.MFA == nil || c.OTP == nil {
		return nil, invalid
	}
	n, p, m := *c.PasswordSignin.TOTP, c.PasswordSignin.Native, *c.PasswordSignin.MFA
	if n.MaximumDuration <= 0 || n.MaximumDuration > c.OTP.Timeout || n.Counters.Schema != c.Velocity.Schema || n.Counters.CommandCounters == nil || n.Counters.CommandCounters.Policy != c.Velocity.Native.Policy {
		return nil, invalid
	}
	admitted, err := n.Counters.CommandCounters.Policy.Admit("identity.mfa.totp-verify")
	if err != nil || admitted.PolicyVersion != n.Counters.PolicyVersion {
		return nil, invalid
	}
	flowKeys := make(map[uint32]session.DigestKey, len(p.FlowKeys))
	probe, err := session.ParseToken(strings.Repeat("A", 43))
	if err != nil {
		return nil, invalid
	}
	for _, key := range p.FlowKeys {
		digest, err := probe.Digest(key, "mfa-configuration")
		if err != nil || digest.KeyVersion == 0 {
			return nil, invalid
		}
		if _, exists := flowKeys[digest.KeyVersion]; exists {
			return nil, invalid
		}
		flowKeys[digest.KeyVersion] = key
	}
	config := MagicLinkTOTPCompletionConfig{MaximumDuration: n.MaximumDuration, ConfigurationID: n.ConfigurationID, PolicyID: n.PolicyID, Coordinator: p.Coordinator, Issuer: m.Issuer, Session: p.Session, Profile: sessionpg.MagicLinkAdmissionConfig{GlobalAuthorityID: p.Profile.GlobalAuthorityID, PolicyNamespace: p.Profile.PolicyNamespace, Audience: p.Profile.Audience}, SessionIssuer: p.Issuance, CSRF: p.CSRFKey, CookieKeys: flowKeys, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: n.ConfigurationID, Keys: n.RiskKeys}, Counters: n.Counters, ComparisonKey: n.ComparisonKey, ComparisonKeyVersion: n.ComparisonKeyVersion, ActiveEnvelopeKeyID: n.ActiveEnvelopeKeyID}
	return newPasswordTOTPService(d.PostgreSQL, primary, config, p.Profile, keys)
}
