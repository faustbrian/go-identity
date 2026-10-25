package reference

import (
	"fmt"
	"log/slog"
	"strings"

	identity "github.com/faustbrian/go-identity"
	"github.com/faustbrian/go-identity/risk"
	"github.com/faustbrian/go-identity/session"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	native "github.com/faustbrian/go-passkey/postgres"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// PasskeyTOTPConfiguration selects native UV-passkey primary plus independent
// confirmed TOTP, not factor enrollment, recovery codes or HTTP. Challenge owns
// its original issuer/preparation keys, lifetime and attempts; its Envelope must
// be nil so the graph supplies its configured envelope owner. Completion retains
// the bounded counter/comparison/encryption semantics of native TOTP completion.
// Its envelope key must match Challenge.EnvelopeKeyID. Inputs remain borrowed,
// immutable and concurrency-safe; construction performs no IO or callbacks.
type PasskeyTOTPConfiguration struct {
	Challenge  native.SigninMFAConfig
	Completion MagicLinkTOTPConfiguration
}

func (PasskeyTOTPConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasskeyTOTPConfiguration(redacted)"))
}

// MarshalJSON rejects implicit signing, comparison and encryption-key export.
func (PasskeyTOTPConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// MarshalText rejects implicit textual startup-key export.
func (PasskeyTOTPConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// LogValue emits only a fixed redacted configuration marker.
func (PasskeyTOTPConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.PasskeyTOTPConfiguration(redacted)")
}

func composePasskeyTOTP(c StoreConfiguration, d ReferenceDependencies, primary *native.SigninService, mapping sessionpg.MFAPasskeySessionAuthority, evaluator risk.Evaluator) (*magicLinkTOTPService, error) {
	if c.Passkey == nil || c.Passkey.TOTP == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_passkey_totp"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || primary == nil || mapping == nil || c.Session == nil || !c.Session.Passkey {
		return nil, invalid
	}
	n, p, e := c.Passkey.TOTP.Completion, c.Passkey, c.Session.Native.Execution
	if n.MaximumDuration <= 0 || n.MaximumDuration > p.Protocol.MaximumDuration || n.Counters.Schema != c.Velocity.Schema || n.Counters.CommandCounters == nil || n.Counters.CommandCounters.Policy != c.Velocity.Native.Policy || n.ActiveEnvelopeKeyID != p.TOTP.Challenge.EnvelopeKeyID {
		return nil, invalid
	}
	admitted, err := n.Counters.CommandCounters.Policy.Admit("identity.mfa.totp-verify")
	if err != nil || admitted.PolicyVersion != n.Counters.PolicyVersion {
		return nil, invalid
	}
	profile := sessionpg.PasskeyAdmissionConfig{GlobalAuthorityID: e.Profile.GlobalAuthorityID, PolicyNamespace: e.Profile.PolicyNamespace, Audience: e.Profile.Audience, RPNamespace: p.RPNamespace}
	issuance := p.Issuer
	issuance.Clock = e.Clock
	config := MagicLinkTOTPCompletionConfig{MaximumDuration: n.MaximumDuration, ConfigurationID: n.ConfigurationID, PolicyID: n.PolicyID, Coordinator: e.Coordinator, Issuer: p.TOTP.Challenge.Issuer, Session: e.Repository, Profile: sessionpg.MagicLinkAdmissionConfig{GlobalAuthorityID: profile.GlobalAuthorityID, PolicyNamespace: profile.PolicyNamespace, Audience: profile.Audience}, SessionIssuer: issuance, CSRF: p.CSRF, CookieKeys: map[uint32]session.DigestKey{}, Risk: risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: n.ConfigurationID, Keys: n.RiskKeys}, Counters: n.Counters, ComparisonKey: n.ComparisonKey, ComparisonKeyVersion: n.ComparisonKeyVersion, ActiveEnvelopeKeyID: n.ActiveEnvelopeKeyID}
	probe, err := session.ParseToken(strings.Repeat("A", 43))
	if err != nil {
		return nil, invalid
	}
	digest, err := probe.Digest(p.Flow.LookupKey, "mfa-configuration")
	if err != nil || digest.KeyVersion == 0 {
		return nil, invalid
	}
	config.CookieKeys[digest.KeyVersion] = p.Flow.LookupKey
	return newPasskeyTOTPService(d.PostgreSQL, primary, config, sessionpg.MFAPasskeySessionAdmission{Profile: profile, Authority: mapping}, keys)
}
