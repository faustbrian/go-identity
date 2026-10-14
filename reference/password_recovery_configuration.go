package reference

import (
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// PasswordRecoveryConfiguration selects original password-primary recovery
// completion, not HTTP or enrollment. VerificationKeys must retain every live
// recovery-set key version; missing keys fail closed. ConfigurationID pins the
// retained completion semantics. The graph supplies actual primary/browser,
// issuer and counted risk owners. Construction copies keys and performs no IO.
type PasswordRecoveryConfiguration struct {
	MaximumDuration           time.Duration
	ConfigurationID, PolicyID string
	Counters                  riskpg.Config
	RiskKeys                  []risk.EvidenceKey
	VerificationKeys          map[uint32][32]byte
	ActiveEnvelopeKeyID       string
}

func composePasswordRecovery(c StoreConfiguration, d ReferenceDependencies, primary *passwordpg.SigninService, evaluator risk.Evaluator) (*magicLinkTOTPService, error) {
	if c.PasswordSignin == nil || c.PasswordSignin.Recovery == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_password_recovery"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || primary == nil || c.PasswordSignin.MFA == nil || c.OTP == nil {
		return nil, invalid
	}
	n, p, m := *c.PasswordSignin.Recovery, c.PasswordSignin.Native, *c.PasswordSignin.MFA
	if !slices.Contains(m.AllowedMethods, "recovery-code") {
		return nil, invalid
	}
	if n.MaximumDuration <= 0 || n.MaximumDuration > c.OTP.Timeout || n.Counters.Schema != c.Velocity.Schema || n.Counters.CommandCounters == nil || n.Counters.CommandCounters.Policy != c.Velocity.Native.Policy {
		return nil, invalid
	}
	admitted, err := n.Counters.CommandCounters.Policy.Admit("identity.mfa.recovery-use")
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
	config := MagicLinkTOTPCompletionConfig{MaximumDuration: n.MaximumDuration, ConfigurationID: n.ConfigurationID, PolicyID: n.PolicyID, Coordinator: p.Coordinator, Issuer: m.Issuer, Session: p.Session, Profile: sessionpg.MagicLinkAdmissionConfig{GlobalAuthorityID: p.Profile.GlobalAuthorityID, PolicyNamespace: p.Profile.PolicyNamespace, Audience: p.Profile.Audience}, SessionIssuer: p.Issuance, CSRF: p.CSRFKey, CookieKeys: flowKeys, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: n.ConfigurationID, Keys: n.RiskKeys}, Counters: n.Counters, ActiveEnvelopeKeyID: n.ActiveEnvelopeKeyID}
	return newNativeRecoveryService(d.PostgreSQL, nil, primary, config, p.Profile, keys, n.VerificationKeys)
}

// Format redacts all configuration and key custody.
func (PasswordRecoveryConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasswordRecoveryConfiguration(redacted)"))
}

// MarshalJSON rejects implicit key/configuration export.
func (PasswordRecoveryConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// MarshalText rejects text/map-key export.
func (PasswordRecoveryConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// LogValue emits a fixed redacted marker.
func (PasswordRecoveryConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.PasswordRecoveryConfiguration(redacted)")
}
