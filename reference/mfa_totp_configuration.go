package reference

import (
	"fmt"
	"log/slog"
	"time"

	identity "github.com/faustbrian/go-identity"
	magicpg "github.com/faustbrian/go-identity/magiclink/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	sessionpg "github.com/faustbrian/go-identity/session/postgres"
	"github.com/faustbrian/go-secret-envelope/adapters/keyring"
)

// MagicLinkTOTPConfiguration selects native login completion, not HTTP,
// enrollment or trusted devices. The graph injects its original request issuer,
// coordinator, session profile, browser keys and counted provider evaluator;
// callers cannot substitute those authority owners. Counters must use the same
// durable risk namespace/policy as the graph. ComparisonKey is independent,
// versioned code-comparison custody; ActiveEnvelopeKeyID selects session-output
// encryption. MaximumDuration is bounded by the selected primary/session graph.
// ConfigurationID and PolicyID pin completion semantics. Resources and callbacks
// remain borrowed and concurrency-safe; construction has no IO or goroutines.
type MagicLinkTOTPConfiguration struct {
	MaximumDuration           time.Duration
	ConfigurationID, PolicyID string
	Counters                  riskpg.Config
	RiskKeys                  []risk.EvidenceKey
	ComparisonKey             [32]byte
	ComparisonKeyVersion      uint32
	ActiveEnvelopeKeyID       string
}

func composeMagicLinkTOTP(c StoreConfiguration, d ReferenceDependencies, request *magicpg.RequestService, evaluator risk.Evaluator) (*magicLinkTOTPService, error) {
	if c.MagicLink == nil || c.MagicLink.TOTP == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_mfa_totp"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || request == nil || c.OTP == nil || c.MagicLink.Consume == nil || c.MagicLink.Consume.MFA == nil || !c.MagicLink.Request.MFAContinuation {
		return nil, invalid
	}
	n, primary, consume := *c.MagicLink.TOTP, c.MagicLink.Request, *c.MagicLink.Consume
	if n.MaximumDuration <= 0 || n.MaximumDuration > c.OTP.Timeout || n.Counters.Schema != c.Velocity.Schema || n.Counters.CommandCounters == nil || n.Counters.CommandCounters.Policy != c.Velocity.Native.Policy {
		return nil, invalid
	}
	admitted, err := n.Counters.CommandCounters.Policy.Admit("identity.mfa.totp-verify")
	if err != nil || admitted.PolicyVersion != n.Counters.PolicyVersion {
		return nil, invalid
	}
	config := MagicLinkTOTPCompletionConfig{
		MaximumDuration: n.MaximumDuration, ConfigurationID: n.ConfigurationID, PolicyID: n.PolicyID,
		Coordinator: primary.Coordinator, Issuer: primary.Issuer, Session: primary.Session,
		Profile:       sessionpg.MagicLinkAdmissionConfig{GlobalAuthorityID: primary.GlobalAuthorityID, PolicyNamespace: consume.PolicyNamespace, Audience: primary.Issuer.Audience},
		SessionIssuer: consume.Issuer, CSRF: consume.CSRF, CookieKeys: primary.CookieKeys,
		Risk:     risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: n.ConfigurationID, Keys: n.RiskKeys},
		Counters: n.Counters, ComparisonKey: n.ComparisonKey, ComparisonKeyVersion: n.ComparisonKeyVersion, ActiveEnvelopeKeyID: n.ActiveEnvelopeKeyID,
	}
	return newMagicLinkTOTPService(d.PostgreSQL, request, config, keys)
}

// Format prevents configuration key and correlated-profile disclosure.
func (MagicLinkTOTPConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.MagicLinkTOTPConfiguration(redacted)"))
}

// MarshalJSON denies implicit comparison/envelope/risk key export.
func (MagicLinkTOTPConfiguration) MarshalJSON() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// MarshalText denies implicit text/map-key custody export.
func (MagicLinkTOTPConfiguration) MarshalText() ([]byte, error) {
	return nil, identity.ForbiddenError{}
}

// LogValue emits only a fixed redacted marker.
func (MagicLinkTOTPConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.MagicLinkTOTPConfiguration(redacted)")
}
