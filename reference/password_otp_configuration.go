package reference

import (
	"crypto/subtle"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"time"

	identity "github.com/faustbrian/go-identity"
	deliverypg "github.com/faustbrian/go-identity/delivery/postgres"
	"github.com/faustbrian/go-identity/otp"
	otppg "github.com/faustbrian/go-identity/otp/postgres"
	passwordpg "github.com/faustbrian/go-identity/password/postgres"
	kernel "github.com/faustbrian/go-identity/postgres"
	"github.com/faustbrian/go-identity/risk"
	riskpg "github.com/faustbrian/go-identity/risk/postgres"
	"github.com/faustbrian/go-identity/session"
	envelope "github.com/faustbrian/go-secret-envelope/v2"
	"github.com/faustbrian/go-secret-envelope/v2/adapters/keyring"
)

// PasswordOTPConfiguration selects native password-origin secondary OTP send
// and completion, not HTTP or enrollment. The graph supplies the actual primary,
// child issuer, session, OTP codec/store and encrypted delivery owners. Policy
// must be a consuming MFA OTP policy. TemplateID/Version select an existing
// delivery template; LocaleChain is copied by the native owner.
//
// RequestKeys, IntentKey and envelope/counter/evidence keys retain their native
// independence and rotation contracts. Both actions use the selected durable
// counter namespace/policy. Configuration IDs pin immutable send/completion
// semantics. The existing OTP store's cookie keys must match every retained
// password-flow key: shared storage cannot authenticate the same browser with
// a different key binding. Construction performs no IO or callbacks.
type PasswordOTPConfiguration struct {
	MaximumDuration                            time.Duration
	ConfigurationID, CompletionConfigurationID string
	PolicyID                                   string
	RequestKeys                                kernel.RequestKeyConfig
	IntentKey                                  [32]byte
	ActiveEnvelopeKeyID                        string
	Counters                                   riskpg.Config
	RiskKeys                                   []risk.EvidenceKey
	Policy                                     otp.AttemptPolicy
	AttemptKeyVersion                          uint32
	TemplateID                                 string
	TemplateVersion                            uint32
	LocaleChain                                []string
}

func composePasswordOTP(c StoreConfiguration, d ReferenceDependencies, primary *passwordpg.SigninService, evaluator risk.Evaluator) (*PasswordOTPLoginCompletionService, error) {
	if c.PasswordSignin == nil || c.PasswordSignin.OTP == nil {
		return nil, nil
	}
	invalid := identity.InvalidInputError{Field: "reference_password_otp"}
	keys, ok := d.EnvelopeKeys.(*keyring.Provider)
	if !ok || keys == nil || d.PostgreSQL == nil || primary == nil || c.PasswordSignin.MFA == nil || c.PasswordSignin.PreAuth == nil || c.OTP == nil || c.Delivery == nil {
		return nil, invalid
	}
	n, p, m, o := *c.PasswordSignin.OTP, c.PasswordSignin.Native, *c.PasswordSignin.MFA, c.OTP
	if !slices.Contains(m.AllowedMethods, "otp") || n.MaximumDuration < time.Millisecond || n.MaximumDuration > o.Timeout || n.Counters.Schema != c.Velocity.Schema || n.Counters.CommandCounters == nil || n.Counters.CommandCounters.Policy != c.Velocity.Native.Policy || n.RequestKeys.Policy.PolicyVersion != o.RequestKeys.Policy.PolicyVersion || !sameServerAuthorization(n.RequestKeys.Policy.Authorization, o.RequestKeys.Policy.Authorization) {
		return nil, invalid
	}
	for _, operation := range []string{"identity.mfa.otp-send", "identity.mfa.otp-verify"} {
		admitted, err := n.Counters.CommandCounters.Policy.Admit(risk.Action(operation))
		if err != nil || admitted.PolicyVersion != n.Counters.PolicyVersion {
			return nil, invalid
		}
	}
	flowKeys, err := passwordOTPFlowKeys(p.FlowKeys, o.Store.PreAuthCookieKeys)
	if err != nil {
		return nil, invalid
	}
	codec, err := otppg.NewAttemptCodec(o.Codec)
	if err != nil {
		return nil, invalid
	}
	crypto, err := envelope.NewService(keys)
	if err != nil {
		return nil, invalid
	}
	deliveryOwner, err := deliverypg.NewContributor(c.Delivery.Enqueue.Custody, crypto)
	if err != nil {
		return nil, invalid
	}
	store := o.Store
	store.Codec, store.PreAuth = codec, p.Session
	issuer, err := otppg.NewMFALoginIssuer(otppg.MFALoginIssuerConfig{Store: store, Delivery: deliveryOwner, Policy: n.Policy, TemplateID: n.TemplateID, TemplateVersion: n.TemplateVersion, ProviderVersion: o.ProviderVersion, LocaleChain: n.LocaleChain, Templates: c.Delivery.Templates})
	if err != nil {
		return nil, invalid
	}
	send, err := NewPasswordOTPLoginSendConfig(n.RequestKeys, n.IntentKey, n.ActiveEnvelopeKeyID)
	if err != nil {
		return nil, invalid
	}
	send.ConfigurationID, send.PolicyID, send.IssuerURL, send.MaximumDuration = n.ConfigurationID, n.PolicyID, m.IssuerURL, n.MaximumDuration
	send.Primary, send.Issuance, send.Issuer = primary, issuer, m.Issuer
	send.Session, send.Profile, send.CookieKeys, send.Coordinator = p.Session, p.Profile, flowKeys, p.Coordinator
	send.Risk = risk.ProtectedProviderAdmissionCustodyConfig{Evaluation: evaluator, ConfigurationID: n.ConfigurationID, Keys: n.RiskKeys}
	send.Counters, send.AllowedOrigins = n.Counters, []string{c.PasswordSignin.PreAuth.Origin}
	sender, err := NewPasswordOTPLoginSendService(d.PostgreSQL, send, keys)
	if err != nil {
		return nil, invalid
	}
	return NewPasswordOTPLoginCompletionService(PasswordOTPLoginCompletionConfig{Sender: sender, ConfigurationID: n.CompletionConfigurationID, SessionIssuer: p.Issuance, CSRF: p.CSRFKey, AttemptKeyVersion: n.AttemptKeyVersion})
}

// Compare through the owned digest API rather than exporting password key
// material. Both native browser owners must interpret retained versions exactly.
func passwordOTPFlowKeys(password []session.DigestKey, raw map[uint32][]byte) (map[uint32]session.DigestKey, error) {
	if len(password) == 0 || len(password) > 32 || len(raw) != len(password) {
		return nil, invalidPasswordOTPSend()
	}
	probe, err := session.ParseToken(strings.Repeat("A", 43))
	if err != nil {
		return nil, invalidPasswordOTPSend()
	}
	keys := make(map[uint32]session.DigestKey, len(password))
	for _, key := range password {
		original, err := probe.Digest(key, "otp-configuration")
		if err != nil || original.KeyVersion == 0 {
			return nil, invalidPasswordOTPSend()
		}
		if _, exists := keys[original.KeyVersion]; exists {
			return nil, invalidPasswordOTPSend()
		}
		native, err := session.NewDigestKey(original.KeyVersion, raw[original.KeyVersion])
		if err != nil {
			return nil, invalidPasswordOTPSend()
		}
		observed, err := probe.Digest(native, "otp-configuration")
		if err != nil || subtle.ConstantTimeCompare(original.Sum[:], observed.Sum[:]) != 1 {
			return nil, invalidPasswordOTPSend()
		}
		keys[original.KeyVersion] = key
	}
	return keys, nil
}

// Format redacts deployment secrets and correlated configuration.
func (PasswordOTPConfiguration) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("reference.PasswordOTPConfiguration(redacted)"))
}

// MarshalJSON denies implicit secret-bearing configuration export.
func (PasswordOTPConfiguration) MarshalJSON() ([]byte, error) { return nil, identity.ForbiddenError{} }

// MarshalText denies implicit text or map-key export.
func (PasswordOTPConfiguration) MarshalText() ([]byte, error) { return nil, identity.ForbiddenError{} }

// LogValue emits only a fixed redacted marker.
func (PasswordOTPConfiguration) LogValue() slog.Value {
	return slog.StringValue("reference.PasswordOTPConfiguration(redacted)")
}
